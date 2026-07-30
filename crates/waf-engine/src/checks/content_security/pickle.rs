//! Bounded Python-`pickle` **opcode walker** — reads a byte stream, never runs it.
//!
//! ## Why this exists
//!
//! `docs/semantic-engine-ast-survey.md` measured the shipped
//! `deser.py_pickle_global_exec` rule against every pickle protocol and found a
//! structural blind spot, not a tuning gap. That rule matches the *text* `GLOBAL`
//! opcode (`c<module>\n<callable>`), which `save_global` stops emitting at
//! protocol 4 — and protocol 4 has been `pickle.DEFAULT_PROTOCOL` since Python
//! 3.8. From protocol 4 on, a global is pushed as two length-prefixed strings
//! joined by the one-byte `STACK_GLOBAL` (`\x93`) opcode: no `c`, no newline, and
//! the framing bytes are not UTF-8, so the module and the callable are not
//! adjacent tokens in any *text* view a regex can see (they arrive as `U+FFFD`).
//! No additional regex closes that; only reading the opcode stream does.
//!
//! ## The safety boundary, stated once
//!
//! A pickle is not a data format, it is a **stack virtual machine**, and
//! `GLOBAL` / `STACK_GLOBAL` / `REDUCE` / `INST` / `OBJ` / `NEWOBJ` are its
//! arbitrary-code-execution primitives. The distance between *walking* these
//! opcodes and *running* them is one function call, so the property this module
//! must hold is enforced by construction and asserted by test:
//!
//! * **nothing is constructed.** No object, no tuple, no dict. The stack holds
//!   only `Item`, a 12-byte tag that is either a byte range into the input, a
//!   resolved-global marker, or `Opaque`.
//! * **nothing is imported or resolved.** A module / callable name is compared
//!   byte-wise against [`DANGEROUS_GLOBALS`], a closed compile-time table, and
//!   the *table's* `&'static str` is what a hit reports — never the payload's
//!   bytes. A pickle can therefore not make this module echo attacker data, nor
//!   reach a symbol the table does not already name.
//! * **nothing recurses.** The walk is one `while` loop. A pickle opcode stream
//!   is flat: nesting is expressed with `MARK`, not with re-entry, so the
//!   stack-overflow class that bit `brush-parser` does not exist here. A pickle
//!   nested *inside* another pickle's `BINBYTES` payload is skipped as opaque
//!   bytes — we decline to re-enter rather than recurse (the same call the JSON
//!   walk makes with `MAX_VALUE_NODES` in `struct_extract`).
//! * **nothing is unbounded.** Every opcode argument is either fixed-width or
//!   read from an explicit length field that is validated against the remaining
//!   buffer *before* the read, so a declared length can never allocate or index
//!   out of range. Every opcode consumes at least one input byte, so the loop is
//!   strictly monotonic and terminates in at most [`MAX_PICKLE_BYTES`] steps.
//!
//! ## What it decides
//!
//! One thing, and it is structural rather than suggestive: *this byte stream, if
//! unpickled, calls `<module>.<callable>`*. [`PickleHit::reduced`] separates the
//! two grades — a dangerous global that a reduction opcode actually consumed
//! (`REDUCE` / `INST` / `OBJ` / `NEWOBJ` / `NEWOBJ_EX`) from one that is named on
//! the stack but never applied.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

use super::budget::ContentInspectionState;

// ── bounds ───────────────────────────────────────────────────────────────────

/// Maximum stream length handed to the walker, in bytes.
///
/// A pickle RCE payload is tens of bytes (the corpus row is 40); this cap is
/// three orders of magnitude of headroom and exists so the walk's worst case is
/// a compile-time constant. A longer stream is walked over its first
/// `MAX_PICKLE_BYTES` bytes — a truncated stream simply fails somewhere and
/// yields no verdict, which is fail-open, not fail-loud.
const MAX_PICKLE_BYTES: usize = 4096;

/// Hard ceiling on simulated stack depth.
///
/// Deliberately equal to [`MAX_PICKLE_BYTES`]: **every** opcode that pushes
/// consumes at least one input byte, so an input capped at `MAX_PICKLE_BYTES`
/// cannot drive more than `MAX_PICKLE_BYTES` pushes and this bound is
/// unreachable by construction. It is checked anyway — defence in depth against
/// a future opcode arm that pushes twice — and hitting it aborts the walk rather
/// than growing. The bound is *not* set lower on purpose: a smaller stack would
/// hand an attacker a trivial evasion (pad with `N` opcodes until the walker
/// gives up, then reduce).
const MAX_PICKLE_STACK: usize = MAX_PICKLE_BYTES;

/// Highest memo slot tracked. A `PUT` / `BINPUT` naming a larger index is
/// ignored (the value is simply not recallable later, costing at most a missed
/// detection) so a 4-byte index field cannot size an allocation.
const MAX_PICKLE_MEMO: usize = 1024;

/// Shortest byte string worth walking. The smallest stream that can name a
/// global and reduce it is longer than this; below it there is nothing to find.
const MIN_PICKLE_BYTES: usize = 6;

/// Shortest base64 token worth decoding — below this a token cannot carry a
/// pickle that names a module *and* a callable.
const MIN_B64_TOKEN: usize = 16;

/// Longest base64 token decoded, chosen so the decode output cannot exceed
/// [`MAX_PICKLE_BYTES`].
const MAX_B64_TOKEN: usize = MAX_PICKLE_BYTES / 3 * 4;

/// Maximum base64 tokens decoded per view. Mirrors the preprocessor's own
/// `MAX_BLIND_CANDIDATES`, so this path adds at most the same order of decode
/// work the blind decoder already performs on every field.
const MAX_B64_CANDIDATES: usize = 8;

// ── opcode bytes (protocols 0–5, complete) ───────────────────────────────────

// Protocol 0.
const OP_MARK: u8 = b'(';
const OP_STOP: u8 = b'.';
const OP_POP: u8 = b'0';
const OP_POP_MARK: u8 = b'1';
const OP_DUP: u8 = b'2';
const OP_FLOAT: u8 = b'F';
const OP_INT: u8 = b'I';
const OP_LONG: u8 = b'L';
const OP_NONE: u8 = b'N';
const OP_PERSID: u8 = b'P';
const OP_REDUCE: u8 = b'R';
const OP_STRING: u8 = b'S';
const OP_UNICODE: u8 = b'V';
const OP_APPEND: u8 = b'a';
const OP_BUILD: u8 = b'b';
const OP_GLOBAL: u8 = b'c';
const OP_DICT: u8 = b'd';
const OP_EMPTY_DICT: u8 = b'}';
const OP_APPENDS: u8 = b'e';
const OP_GET: u8 = b'g';
const OP_INST: u8 = b'i';
const OP_LIST: u8 = b'l';
const OP_EMPTY_LIST: u8 = b']';
const OP_OBJ: u8 = b'o';
const OP_PUT: u8 = b'p';
const OP_SETITEM: u8 = b's';
const OP_TUPLE: u8 = b't';
const OP_EMPTY_TUPLE: u8 = b')';
const OP_SETITEMS: u8 = b'u';

// Protocol 1.
const OP_BININT: u8 = b'J';
const OP_BININT1: u8 = b'K';
const OP_BININT2: u8 = b'M';
const OP_BINPERSID: u8 = b'Q';
const OP_BINSTRING: u8 = b'T';
const OP_SHORT_BINSTRING: u8 = b'U';
const OP_BINUNICODE: u8 = b'X';
const OP_BINGET: u8 = b'h';
const OP_LONG_BINGET: u8 = b'j';
const OP_BINPUT: u8 = b'q';
const OP_LONG_BINPUT: u8 = b'r';
const OP_BINFLOAT: u8 = b'G';

// Protocol 2.
const OP_PROTO: u8 = 0x80;
const OP_NEWOBJ: u8 = 0x81;
const OP_EXT1: u8 = 0x82;
const OP_EXT2: u8 = 0x83;
const OP_EXT4: u8 = 0x84;
const OP_TUPLE1: u8 = 0x85;
const OP_TUPLE2: u8 = 0x86;
const OP_TUPLE3: u8 = 0x87;
const OP_NEWTRUE: u8 = 0x88;
const OP_NEWFALSE: u8 = 0x89;
const OP_LONG1: u8 = 0x8a;
const OP_LONG4: u8 = 0x8b;

// Protocol 3.
const OP_BINBYTES: u8 = b'B';
const OP_SHORT_BINBYTES: u8 = b'C';

// Protocol 4.
const OP_SHORT_BINUNICODE: u8 = 0x8c;
const OP_BINUNICODE8: u8 = 0x8d;
const OP_BINBYTES8: u8 = 0x8e;
const OP_EMPTY_SET: u8 = 0x8f;
const OP_ADDITEMS: u8 = 0x90;
const OP_FROZENSET: u8 = 0x91;
const OP_NEWOBJ_EX: u8 = 0x92;
const OP_STACK_GLOBAL: u8 = 0x93;
const OP_MEMOIZE: u8 = 0x94;
const OP_FRAME: u8 = 0x95;

// Protocol 5.
const OP_BYTEARRAY8: u8 = 0x96;
const OP_NEXT_BUFFER: u8 = 0x97;
const OP_READONLY_BUFFER: u8 = 0x98;

/// Whether `b` is an opcode this walker knows. Used only as the cheap admission
/// gate on the first byte — the walk itself is the real filter.
const fn is_opcode(b: u8) -> bool {
    matches!(
        b,
        OP_MARK
            | OP_STOP
            | OP_POP
            | OP_POP_MARK
            | OP_DUP
            | OP_FLOAT
            | OP_INT
            | OP_LONG
            | OP_NONE
            | OP_PERSID
            | OP_REDUCE
            | OP_STRING
            | OP_UNICODE
            | OP_APPEND
            | OP_BUILD
            | OP_GLOBAL
            | OP_DICT
            | OP_EMPTY_DICT
            | OP_APPENDS
            | OP_GET
            | OP_INST
            | OP_LIST
            | OP_EMPTY_LIST
            | OP_OBJ
            | OP_PUT
            | OP_SETITEM
            | OP_TUPLE
            | OP_EMPTY_TUPLE
            | OP_SETITEMS
            | OP_BININT
            | OP_BININT1
            | OP_BININT2
            | OP_BINPERSID
            | OP_BINSTRING
            | OP_SHORT_BINSTRING
            | OP_BINUNICODE
            | OP_BINGET
            | OP_LONG_BINGET
            | OP_BINPUT
            | OP_LONG_BINPUT
            | OP_BINFLOAT
            | OP_BINBYTES
            | OP_SHORT_BINBYTES
            | 0x80..=0x98
    )
}

// ── the dangerous-callable table ─────────────────────────────────────────────

/// Process-execution and filesystem-mutation entry points on the OS module and
/// its two platform aliases (`posix` on Unix, `nt` on Windows — `save_global`
/// records the module a callable *actually* lives in, which is why the shipped
/// regex had to enumerate all three too).
const OS_CALLABLES: &[&str] = &[
    "system",
    "popen",
    "popen2",
    "popen3",
    "popen4",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "fork",
    "forkpty",
    "kill",
    "killpg",
    "abort",
    "remove",
    "unlink",
    "rmdir",
    "removedirs",
    "rename",
    "renames",
    "replace",
    "chmod",
    "chown",
    "symlink",
    "link",
    "truncate",
    "putenv",
    "setuid",
    "setgid",
];

/// `subprocess` entry points that start a process.
const SUBPROCESS_CALLABLES: &[&str] = &[
    "Popen",
    "call",
    "check_call",
    "check_output",
    "run",
    "getoutput",
    "getstatusoutput",
];

/// Builtins that evaluate source, import, open files or reach attributes
/// dynamically — the primitives a pickle gadget chains through. `builtins` is
/// the Python 3 spelling, `__builtin__` the Python 2 one.
const BUILTIN_CALLABLES: &[&str] = &[
    "eval",
    "exec",
    "execfile",
    "compile",
    "open",
    "input",
    "__import__",
    "getattr",
    "apply",
    "breakpoint",
];

/// The closed set of `(module, callables)` a pickle may not name.
///
/// **This is a deny list of execution primitives, not a heuristic**, and that is
/// the whole false-positive argument: every global outside this table — the
/// `collections.OrderedDict`, `copy_reg._reconstructor`, `_codecs.encode`,
/// `numpy.core.multiarray._reconstruct`, `datetime.datetime`,
/// `decimal.Decimal`, `pandas.*` globals that ordinary serialized data is made
/// of — resolves to nothing here and produces no signal at all. Growing this
/// table is the only way to grow the false-positive surface, so it stays
/// restricted to callables whose presence in request data has no benign reading.
const DANGEROUS_GLOBALS: &[(&str, &[&str])] = &[
    ("os", OS_CALLABLES),
    ("posix", OS_CALLABLES),
    ("nt", OS_CALLABLES),
    ("subprocess", SUBPROCESS_CALLABLES),
    ("_posixsubprocess", &["fork_exec"]),
    ("builtins", BUILTIN_CALLABLES),
    ("__builtin__", BUILTIN_CALLABLES),
    // Python 2's `commands`. Not only a legacy spelling: CPython's
    // `_compat_pickle` rewrites `subprocess.*` to `commands.*` when dumping at
    // protocols 0–2, so a plain `pickle.dumps(…, protocol=2)` of a
    // `subprocess.check_output` reduction arrives naming this module.
    ("commands", SUBPROCESS_CALLABLES),
    ("pty", &["spawn"]),
    ("platform", &["popen"]),
    ("importlib", &["import_module"]),
    ("runpy", &["run_path", "run_module", "_run_code"]),
    ("timeit", &["timeit"]),
    ("webbrowser", &["open", "open_new", "open_new_tab", "get"]),
    ("shutil", &["rmtree", "move"]),
    ("socket", &["socket", "create_connection"]),
    ("ctypes", &["CDLL", "cdll", "WinDLL", "windll"]),
    ("io", &["open"]),
];

/// Pack a table coordinate into one stack slot. Both indices are far below 256
/// (18 modules, at most 41 callables), and [`unpack_global`] is the only reader.
fn pack_global(module_idx: usize, callable_idx: usize) -> u16 {
    let packed = ((module_idx & 0xff) << 8) | (callable_idx & 0xff);
    // Both halves are masked to a byte, so the value always fits; the fallback
    // is a value [`unpack_global`] resolves to `None` rather than a panic.
    u16::try_from(packed).unwrap_or(u16::MAX)
}

/// Reverse of [`pack_global`], resolving back to the table's own strings.
fn unpack_global(packed: u16) -> Option<(&'static str, &'static str)> {
    let (module, callables) = DANGEROUS_GLOBALS.get(usize::from(packed >> 8))?;
    let callable = callables.get(usize::from(packed & 0xff))?;
    Some((module, callable))
}

/// Resolve a `(module, callable)` name pair against [`DANGEROUS_GLOBALS`],
/// returning its packed coordinate.
///
/// Both arguments are **payload bytes**; nothing they contain survives into the
/// return value, which is a table coordinate — that is the mechanism by which a
/// hit can never echo attacker-controlled data. Comparison is byte-exact and
/// case-sensitive, because Python symbol resolution is.
fn locate_global(module: &[u8], callable: &[u8]) -> Option<u16> {
    let module_idx = DANGEROUS_GLOBALS
        .iter()
        .position(|(name, _)| name.as_bytes() == module)?;
    let (_, callables) = DANGEROUS_GLOBALS.get(module_idx)?;
    let callable_idx = callables.iter().position(|c| c.as_bytes() == callable)?;
    Some(pack_global(module_idx, callable_idx))
}

// ── the walk ─────────────────────────────────────────────────────────────────

/// One slot of the simulated stack. Deliberately **not** a value: it carries a
/// byte range or a table coordinate, never a constructed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    /// A string / bytes literal, as `(start, len)` into the walked stream.
    Text(u32, u32),
    /// A global naming an entry of [`DANGEROUS_GLOBALS`], packed by
    /// [`pack_global`].
    Dangerous(u16),
    /// Anything else — an int, a container, an unresolvable global, a value we
    /// deliberately decline to model.
    Opaque,
}

/// What one opcode did to the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Keep walking.
    Go,
    /// `STOP` was reached, or the stream is malformed. Either way the walk ends
    /// and whatever was already observed stands (a stream that reduces
    /// `os.system` and *then* runs off the rails has already executed the call
    /// by the time the unpickler fails, so a trailing-garbage suffix must not
    /// launder it).
    Halt,
}

/// A dangerous callable a pickle stream names.
///
/// `module` and `callable` are always [`DANGEROUS_GLOBALS`] entries — compile-time
/// constants — never bytes copied out of the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PickleHit {
    pub module: &'static str,
    pub callable: &'static str,
    /// `true` when a reduction opcode (`REDUCE` / `INST` / `OBJ` / `NEWOBJ` /
    /// `NEWOBJ_EX`) consumed the global — i.e. the stream does not merely
    /// *mention* the callable, it applies it.
    pub reduced: bool,
}

/// The walker state for one stream.
struct Walk<'a> {
    stream: &'a [u8],
    pos: usize,
    stack: Vec<Item>,
    /// Stack indices of open `MARK`s. Kept beside the stack rather than as a
    /// stack item so `pop_to_mark` is O(1) instead of a reverse scan.
    marks: Vec<usize>,
    memo: Vec<Item>,
    hit: Option<PickleHit>,
}

impl<'a> Walk<'a> {
    const fn new(stream: &'a [u8]) -> Self {
        Self {
            stream,
            pos: 0,
            stack: Vec::new(),
            marks: Vec::new(),
            memo: Vec::new(),
            hit: None,
        }
    }

    // ── primitive reads (every one bounds-checked before it advances) ────────

    /// Consume `n` bytes, returning their range. `None` — and no advance — when
    /// the stream is shorter than the declared length.
    fn take(&mut self, n: usize) -> Option<(u32, u32)> {
        let end = self.pos.checked_add(n)?;
        if end > self.stream.len() {
            return None;
        }
        let start = u32::try_from(self.pos).ok()?;
        let len = u32::try_from(n).ok()?;
        self.pos = end;
        Some((start, len))
    }

    /// Consume a newline-terminated argument, returning the range *excluding*
    /// the newline. `None` when the stream ends without one.
    fn take_line(&mut self) -> Option<(u32, u32)> {
        let rest = self.stream.get(self.pos..)?;
        let nl = rest.iter().position(|b| *b == b'\n')?;
        let range = self.take(nl)?;
        self.pos = self.pos.checked_add(1)?;
        Some(range)
    }

    /// Read a little-endian unsigned integer of `width` bytes as a `usize`.
    fn take_uint(&mut self, width: usize) -> Option<usize> {
        let (start, len) = self.take(width)?;
        let bytes = self.slice(start, len)?;
        let mut acc: u64 = 0;
        for (i, b) in bytes.iter().enumerate() {
            if i >= 8 {
                // A 9th byte can only come from an 8-byte field, so this is
                // unreachable; declining rather than shifting out is still the
                // safe answer.
                return None;
            }
            acc |= u64::from(*b) << (i * 8);
        }
        usize::try_from(acc).ok()
    }

    /// Consume a length-prefixed payload (`width`-byte little-endian length,
    /// then that many bytes) and return the payload range.
    fn take_sized(&mut self, width: usize) -> Option<(u32, u32)> {
        let n = self.take_uint(width)?;
        self.take(n)
    }

    /// Resolve a stored range back to bytes.
    fn slice(&self, start: u32, len: u32) -> Option<&'a [u8]> {
        let start = usize::try_from(start).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.stream.get(start..end)
    }

    // ── stack primitives ────────────────────────────────────────────────────

    fn push(&mut self, item: Item) -> Step {
        if self.stack.len() >= MAX_PICKLE_STACK {
            return Step::Halt;
        }
        self.stack.push(item);
        Step::Go
    }

    /// Pop `n` items, returning the deepest one popped (for `REDUCE`-family
    /// opcodes the callable sits below its arguments). `None` on underflow.
    fn pop_n(&mut self, n: usize) -> Option<Item> {
        let mut deepest = None;
        for _ in 0..n {
            deepest = Some(self.stack.pop()?);
        }
        deepest
    }

    /// Truncate the stack back to the most recent open `MARK`, returning that
    /// index. `None` when there is no open mark (a malformed stream).
    fn pop_to_mark(&mut self) -> Option<usize> {
        let at = self.marks.pop()?;
        if at <= self.stack.len() {
            self.stack.truncate(at);
        }
        Some(at)
    }

    /// Record a global that the table names, and whether a reduction consumed
    /// it. A `reduced` hit always wins over a merely-named one.
    fn record(&mut self, packed: u16, reduced: bool) {
        let Some((module, callable)) = unpack_global(packed) else {
            return;
        };
        if self.hit.is_none_or(|h| reduced && !h.reduced) {
            self.hit = Some(PickleHit {
                module,
                callable,
                reduced,
            });
        }
    }

    /// If `item` is a dangerous global, record it as reduced.
    fn record_reduction(&mut self, item: Option<Item>) {
        if let Some(Item::Dangerous(packed)) = item {
            self.record(packed, true);
        }
    }

    // ── the loop ────────────────────────────────────────────────────────────

    fn run(mut self) -> Option<PickleHit> {
        while let Some(op) = self.stream.get(self.pos).copied() {
            self.pos = self.pos.saturating_add(1);
            let step = self
                .step_literal(op)
                .or_else(|| self.step_stack(op))
                .or_else(|| self.step_global(op))
                // An opcode this table does not know means the stream is not a
                // pickle (or is a newer protocol we decline to guess at).
                .unwrap_or(Step::Halt);
            if step == Step::Halt {
                break;
            }
        }
        self.hit
    }

    /// Opcodes that push a literal read from the stream, plus the two framing
    /// opcodes that push nothing. `None` when `op` is not in this group.
    fn step_literal(&mut self, op: u8) -> Option<Step> {
        // Length-prefixed text / bytes: the operands `STACK_GLOBAL` consumes.
        let sized = match op {
            OP_SHORT_BINUNICODE | OP_SHORT_BINSTRING | OP_SHORT_BINBYTES => Some(1),
            OP_BINUNICODE | OP_BINSTRING | OP_BINBYTES => Some(4),
            OP_BINUNICODE8 | OP_BINBYTES8 | OP_BYTEARRAY8 => Some(8),
            _ => None,
        };
        if let Some(width) = sized {
            return Some(
                self.take_sized(width)
                    .map_or(Step::Halt, |(start, len)| self.push(Item::Text(start, len))),
            );
        }
        // Newline-terminated text (protocol 0). `STRING` is a quoted repr, so
        // the quotes are stripped; `UNICODE` is raw-unicode-escape and taken
        // verbatim.
        if matches!(op, OP_STRING | OP_UNICODE) {
            return Some(self.take_line().map_or(Step::Halt, |(start, len)| {
                let (start, len) = if op == OP_STRING {
                    strip_quotes(self.stream, start, len)
                } else {
                    (start, len)
                };
                self.push(Item::Text(start, len))
            }));
        }
        // Scalars whose value we deliberately do not model.
        let opaque = match op {
            OP_NONE | OP_NEWTRUE | OP_NEWFALSE | OP_EMPTY_TUPLE | OP_EMPTY_LIST | OP_EMPTY_DICT | OP_EMPTY_SET
            | OP_NEXT_BUFFER => Some(Ok(0)),
            OP_BININT1 | OP_EXT1 => Some(Err(1)),
            OP_BININT2 | OP_EXT2 => Some(Err(2)),
            OP_BININT | OP_EXT4 => Some(Err(4)),
            OP_BINFLOAT => Some(Err(8)),
            _ => None,
        };
        if let Some(width) = opaque {
            return Some(match width {
                Ok(_) => self.push(Item::Opaque),
                Err(n) if self.take(n).is_some() => self.push(Item::Opaque),
                Err(_) => Step::Halt,
            });
        }
        match op {
            // Newline-terminated numbers, and the persistent-id form.
            OP_INT | OP_LONG | OP_FLOAT | OP_PERSID => {
                Some(self.take_line().map_or(Step::Halt, |_| self.push(Item::Opaque)))
            }
            // Length-prefixed arbitrary-precision integers.
            OP_LONG1 => Some(self.take_sized(1).map_or(Step::Halt, |_| self.push(Item::Opaque))),
            OP_LONG4 => Some(self.take_sized(4).map_or(Step::Halt, |_| self.push(Item::Opaque))),
            // Framing only — no stack effect. `FRAME`'s declared length is not
            // trusted: we keep decoding opcodes rather than jumping, so a lying
            // frame header cannot steer the walk.
            OP_PROTO => Some(self.take(1).map_or(Step::Halt, |_| Step::Go)),
            OP_FRAME => Some(self.take(8).map_or(Step::Halt, |_| Step::Go)),
            _ => None,
        }
    }

    /// Pure stack / memo shuffling. `None` when `op` is not in this group.
    #[allow(clippy::cognitive_complexity)]
    fn step_stack(&mut self, op: u8) -> Option<Step> {
        // Memo writes (`PUT` family) and reads (`GET` family).
        let put = match op {
            OP_BINPUT => Some(1),
            OP_LONG_BINPUT => Some(4),
            _ => None,
        };
        if let Some(width) = put {
            return Some(self.take_uint(width).map_or(Step::Halt, |i| self.memo_put(i)));
        }
        let get = match op {
            OP_BINGET => Some(1),
            OP_LONG_BINGET => Some(4),
            _ => None,
        };
        if let Some(width) = get {
            return Some(self.take_uint(width).map_or(Step::Halt, |i| self.memo_get(i)));
        }
        match op {
            OP_STOP => Some(Step::Halt),
            OP_MARK => Some(if self.marks.len() >= MAX_PICKLE_STACK {
                Step::Halt
            } else {
                self.marks.push(self.stack.len());
                Step::Go
            }),
            OP_MEMOIZE => Some(self.memo_push()),
            OP_PUT => Some(self.take_line().map_or(Step::Halt, |(start, len)| {
                self.slice(start, len)
                    .and_then(parse_decimal)
                    .map_or(Step::Go, |i| self.memo_put(i))
            })),
            OP_GET => Some(self.take_line().map_or(Step::Halt, |(start, len)| {
                match self.slice(start, len).and_then(parse_decimal) {
                    Some(i) => self.memo_get(i),
                    None => self.push(Item::Opaque),
                }
            })),
            OP_POP | OP_APPEND | OP_BUILD | OP_BINPERSID => Some(self.pop_n(1).map_or(Step::Halt, |_| {
                if op == OP_BINPERSID {
                    self.push(Item::Opaque)
                } else {
                    Step::Go
                }
            })),
            OP_SETITEM => Some(self.pop_n(2).map_or(Step::Halt, |_| Step::Go)),
            OP_DUP => Some(self.stack.last().copied().map_or(Step::Halt, |top| self.push(top))),
            OP_TUPLE1 => Some(self.pop_n(1).map_or(Step::Halt, |_| self.push(Item::Opaque))),
            OP_TUPLE2 => Some(self.pop_n(2).map_or(Step::Halt, |_| self.push(Item::Opaque))),
            OP_TUPLE3 => Some(self.pop_n(3).map_or(Step::Halt, |_| self.push(Item::Opaque))),
            // Mark-delimited constructions. The first three leave a fresh
            // container on the stack; the last four mutate the object already
            // below the mark and push nothing.
            OP_TUPLE | OP_LIST | OP_DICT | OP_FROZENSET => {
                Some(self.pop_to_mark().map_or(Step::Halt, |_| self.push(Item::Opaque)))
            }
            OP_APPENDS | OP_SETITEMS | OP_ADDITEMS | OP_POP_MARK => {
                Some(self.pop_to_mark().map_or(Step::Halt, |_| Step::Go))
            }
            // Transforms the top of the stack in place.
            OP_READONLY_BUFFER => Some(if self.stack.is_empty() { Step::Halt } else { Step::Go }),
            _ => None,
        }
    }

    /// The resolver and reduction opcodes — the arbitrary-code-execution
    /// primitives, and the only place this module looks anything up.
    fn step_global(&mut self, op: u8) -> Option<Step> {
        match op {
            // `c<module>\n<callable>\n` — protocols 0–3.
            OP_GLOBAL => Some(self.text_global(false)),
            // `i<module>\n<callable>\n` then pop-to-mark — instantiates directly,
            // so the resolved name counts as reduced.
            OP_INST => Some(self.text_global(true)),
            // Two strings joined by one opcode byte — protocol 4+. This is the
            // spelling `pickle.dumps()` has emitted by default since Python 3.8,
            // and the one no regex over a lossy text view can reach.
            OP_STACK_GLOBAL => Some(self.stack_global()),
            // `R` pops the argument tuple, then the callable.
            OP_REDUCE | OP_NEWOBJ => Some(self.reduce(2)),
            // `\x92` pops kwargs, args, then the class.
            OP_NEWOBJ_EX => Some(self.reduce(3)),
            // `o` instantiates the item sitting directly above the mark.
            OP_OBJ => Some(self.obj()),
            _ => None,
        }
    }

    /// `GLOBAL` / `INST`: two newline-terminated names read straight from the
    /// stream.
    fn text_global(&mut self, instantiates: bool) -> Step {
        let Some((m_start, m_len)) = self.take_line() else {
            return Step::Halt;
        };
        let Some((c_start, c_len)) = self.take_line() else {
            return Step::Halt;
        };
        let resolved = match (self.slice(m_start, m_len), self.slice(c_start, c_len)) {
            (Some(module), Some(callable)) => locate_global(module, callable),
            _ => None,
        };
        if instantiates {
            // `INST` consumes the mark-delimited argument list and produces the
            // instance; the resolution is an application, not a mention.
            if let Some(packed) = resolved {
                self.record(packed, true);
            }
            if self.pop_to_mark().is_none() {
                return Step::Halt;
            }
            return self.push(Item::Opaque);
        }
        self.push_resolved(resolved)
    }

    /// Push the outcome of a resolver opcode: a table hit becomes a tracked
    /// `Dangerous` slot (and is recorded as *named*), anything else is `Opaque`.
    fn push_resolved(&mut self, resolved: Option<u16>) -> Step {
        match resolved {
            Some(packed) => {
                self.record(packed, false);
                self.push(Item::Dangerous(packed))
            }
            None => self.push(Item::Opaque),
        }
    }

    /// `STACK_GLOBAL`: pop the callable name, then the module name.
    fn stack_global(&mut self) -> Step {
        let (Some(callable), Some(module)) = (self.stack.pop(), self.stack.pop()) else {
            return Step::Halt;
        };
        let resolved = match (module, callable) {
            (Item::Text(m_start, m_len), Item::Text(c_start, c_len)) => {
                match (self.slice(m_start, m_len), self.slice(c_start, c_len)) {
                    (Some(m), Some(c)) => locate_global(m, c),
                    _ => None,
                }
            }
            _ => None,
        };
        self.push_resolved(resolved)
    }

    /// `REDUCE` / `NEWOBJ` / `NEWOBJ_EX`: pop `n` items; the deepest is the
    /// callable being applied.
    fn reduce(&mut self, n: usize) -> Step {
        let Some(callable) = self.pop_n(n) else {
            return Step::Halt;
        };
        self.record_reduction(Some(callable));
        self.push(Item::Opaque)
    }

    /// `OBJ`: the class is the item immediately above the open mark.
    fn obj(&mut self) -> Step {
        let Some(at) = self.marks.last().copied() else {
            return Step::Halt;
        };
        let class = self.stack.get(at).copied();
        self.record_reduction(class);
        if self.pop_to_mark().is_none() {
            return Step::Halt;
        }
        self.push(Item::Opaque)
    }

    // ── memo ────────────────────────────────────────────────────────────────

    /// `MEMOIZE`: append the top of the stack to the memo.
    fn memo_push(&mut self) -> Step {
        let Some(top) = self.stack.last().copied() else {
            return Step::Halt;
        };
        if self.memo.len() < MAX_PICKLE_MEMO {
            self.memo.push(top);
        }
        Step::Go
    }

    /// `PUT` family: store the top of the stack at `index`. An index past
    /// [`MAX_PICKLE_MEMO`] is dropped rather than sizing an allocation.
    fn memo_put(&mut self, index: usize) -> Step {
        let Some(top) = self.stack.last().copied() else {
            return Step::Halt;
        };
        if index >= MAX_PICKLE_MEMO {
            return Step::Go;
        }
        if self.memo.len() <= index {
            self.memo.resize(index.saturating_add(1), Item::Opaque);
        }
        if let Some(slot) = self.memo.get_mut(index) {
            *slot = top;
        }
        Step::Go
    }

    /// `GET` family: recall a memo slot. An unknown slot pushes `Opaque` — the
    /// stream stays walkable, we simply learn nothing from that value.
    fn memo_get(&mut self, index: usize) -> Step {
        let item = self.memo.get(index).copied().unwrap_or(Item::Opaque);
        self.push(item)
    }
}

/// Strip one layer of matching ASCII quotes from a `STRING` operand's repr.
fn strip_quotes(stream: &[u8], start: u32, len: u32) -> (u32, u32) {
    if len < 2 {
        return (start, len);
    }
    let Ok(begin) = usize::try_from(start) else {
        return (start, len);
    };
    let Ok(count) = usize::try_from(len) else {
        return (start, len);
    };
    let Some(bytes) = stream.get(begin..begin.saturating_add(count)) else {
        return (start, len);
    };
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return (start, len);
    };
    if (*first == b'\'' || *first == b'"') && first == last {
        return (start.saturating_add(1), len.saturating_sub(2));
    }
    (start, len)
}

/// Parse an ASCII decimal memo index. Returns `None` for anything else,
/// including the `L`-suffixed Python 2 long form and negative indices.
fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || bytes.len() > 10 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut acc: usize = 0;
    for b in bytes {
        acc = acc.checked_mul(10)?.checked_add(usize::from(b - b'0'))?;
    }
    Some(acc)
}

// ── entry points ─────────────────────────────────────────────────────────────

/// Cheap admission gate: is this byte string worth walking at all?
///
/// Two O(1)/O(n) checks that cost nothing next to the walk they guard — the
/// first byte must be an opcode this table knows, and a `STOP` must appear
/// somewhere. The walk is the real filter; this only keeps ordinary prose from
/// entering it.
fn looks_like_pickle(stream: &[u8]) -> bool {
    stream.len() >= MIN_PICKLE_BYTES && stream.first().copied().is_some_and(is_opcode) && stream.contains(&OP_STOP)
}

/// Walk one candidate byte stream, metering it against the shared Lane 2 parse
/// budget.
///
/// The budget taken is `max_ast_input_bytes_total` — the same parse-input meter
/// the SQL and shell AST layers use — rather than `max_ast_attempts_per_request`.
/// The attempt counter is only six per request and is consumed by detectors that
/// run before this one, so charging attempts would let an ordinary SQL-ish
/// request starve the pickle walk entirely; the byte meter bounds the same work
/// (a walk costs at most [`MAX_PICKLE_BYTES`], so the 256 KiB default admits ~64
/// walks per request) and sets `degraded` on exhaustion exactly the same way.
fn walk_stream(stream: &[u8], state: &mut ContentInspectionState) -> Option<PickleHit> {
    let stream = stream.get(..stream.len().min(MAX_PICKLE_BYTES)).unwrap_or(stream);
    if !looks_like_pickle(stream) {
        return None;
    }
    if !state.try_take_ast_input_bytes(stream.len()) {
        return None;
    }
    Walk::new(stream).run()
}

/// Whether `b` may appear inside a base64 token. Mirrors the preprocessor's own
/// candidate alphabet: standard and URL-safe alphabets, padding excluded (the
/// unpadded engines are tried first, so a split-off `==` costs nothing).
const fn is_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_'
}

/// Whether `b` may appear inside a hex token.
const fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Inspect one preprocessor view's text for a pickle.
///
/// Three input paths, in order:
///
/// 1. **the text itself**, anchored at byte 0 — a raw pickle body (`content-type:
///    application/octet-stream`) arrives this way;
/// 2. **base64 tokens inside it** — the shape that actually ships, and the one
///    the existing decode chain structurally cannot deliver: the preprocessor's
///    blind base64 gate requires the decoded bytes to be ≥ 85 % printable ASCII
///    and hands detectors a `String`, and a protocol-4 pickle is neither
///    printable nor UTF-8. So this decodes for itself, from `view.text` rather
///    than `view.lower_trunc` — base64 is case-significant and the lowercased
///    normalisation destroys it;
/// 3. **hex tokens inside it**, for the same reason and by the same argument —
///    the preprocessor blind-decodes hex too, and the deserialization table
///    already carries a hex rule (`deser.java_hex_magic`), so hex delivery is a
///    shape this family has seen.
///
/// Bounded by [`MAX_B64_CANDIDATES`] decodes per encoding per view, each into one
/// reused buffer, and by the parse-byte budget inside [`walk_stream`].
///
/// The whole-request cost is bounded without needing a budget of its own. The
/// candidates in one view are disjoint substrings of it, so the decode input per
/// view is at most the view's own length; and the sum of every view's length is
/// already capped by `max_preprocess_output_bytes_total` (512 KiB by default),
/// which the preprocessor charges as it produces them. A request therefore
/// cannot drive more than that many bytes of decode here, whatever shape it
/// takes.
pub(super) fn scan_view_text(text: &str, state: &mut ContentInspectionState) -> Option<PickleHit> {
    if let Some(hit) = walk_stream(text.as_bytes(), state) {
        return Some(hit);
    }
    let mut buf: Vec<u8> = Vec::new();
    if let Some(hit) = scan_encoded(
        text,
        is_b64_byte,
        MIN_B64_TOKEN,
        MAX_B64_TOKEN,
        decode_b64,
        &mut buf,
        state,
    ) {
        return Some(hit);
    }
    scan_encoded(
        text,
        is_hex_byte,
        MIN_PICKLE_BYTES * 2,
        MAX_PICKLE_BYTES * 2,
        decode_hex,
        &mut buf,
        state,
    )
}

/// Walk the decoded form of every candidate token of one encoding.
fn scan_encoded(
    text: &str,
    is_token_byte: fn(u8) -> bool,
    min_len: usize,
    max_len: usize,
    decode: for<'b> fn(&str, &'b mut Vec<u8>) -> Option<&'b [u8]>,
    buf: &mut Vec<u8>,
    state: &mut ContentInspectionState,
) -> Option<PickleHit> {
    let mut decoded_tokens = 0usize;
    for token in text.split(|c: char| !c.is_ascii() || !is_token_byte(u8::try_from(c).unwrap_or(0xff))) {
        if decoded_tokens >= MAX_B64_CANDIDATES {
            break;
        }
        if token.len() < min_len || token.len() > max_len {
            continue;
        }
        decoded_tokens = decoded_tokens.saturating_add(1);
        let Some(bytes) = decode(token, buf) else {
            continue;
        };
        if let Some(hit) = walk_stream(bytes, state) {
            return Some(hit);
        }
    }
    None
}

/// Decode one base64 token into `buf` across the standard and URL-safe
/// alphabets, padded and unpadded. Returns the decoded slice, or `None` when the
/// token is not base64 in any of them.
fn decode_b64<'b>(token: &str, buf: &'b mut Vec<u8>) -> Option<&'b [u8]> {
    // `token.len()` is already capped at `MAX_B64_TOKEN`, so the output bound
    // cannot exceed `MAX_PICKLE_BYTES` rounded up to the next group.
    let capacity = token.len() / 4 * 3 + 3;
    if buf.len() < capacity {
        buf.resize(capacity, 0);
    }
    for engine in [&STANDARD_NO_PAD, &STANDARD, &URL_SAFE_NO_PAD, &URL_SAFE] {
        if let Ok(n) = engine.decode_slice(token, buf) {
            return buf.get(..n);
        }
    }
    None
}

/// Decode one hex token into `buf`. Odd-length tokens are declined rather than
/// padded — an odd run is not a hex-encoded byte string.
fn decode_hex<'b>(token: &str, buf: &'b mut Vec<u8>) -> Option<&'b [u8]> {
    if !token.len().is_multiple_of(2) {
        return None;
    }
    let capacity = token.len() / 2;
    if buf.len() < capacity {
        buf.resize(capacity, 0);
    }
    let out = buf.get_mut(..capacity)?;
    hex::decode_to_slice(token, out).ok()?;
    buf.get(..capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk a stream with a fresh, generous budget.
    fn walk(stream: &[u8]) -> Option<PickleHit> {
        let mut state = ContentInspectionState::new(super::super::budget::Budget::default());
        walk_stream(stream, &mut state)
    }

    fn scan(text: &str) -> Option<PickleHit> {
        let mut state = ContentInspectionState::new(super::super::budget::Budget::default());
        scan_view_text(text, &mut state)
    }

    // ── protocol coverage: the same `os.system("id")` reduction, 0 through 5 ──
    //
    // Byte strings produced by CPython 3.13.5 `pickle.dumps(E(), protocol=p)`
    // where `E.__reduce__` returns `(os.system, ("id",))`, and cross-checked
    // against `pickletools.dis`. Protocol 2 is the old default, protocol 4 the
    // current one; the shipped regex sees 0–3 and is blind to 4–5.

    const PROTO0: &[u8] = b"cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.";
    const PROTO1: &[u8] = b"cposix\nsystem\nq\0(X\x02\0\0\0idq\x01tq\x02Rq\x03.";
    const PROTO2: &[u8] = b"\x80\x02cposix\nsystem\nq\0X\x02\0\0\0idq\x01\x85q\x02Rq\x03.";
    const PROTO3: &[u8] = b"\x80\x03cposix\nsystem\nq\0X\x02\0\0\0idq\x01\x85q\x02Rq\x03.";
    const PROTO4: &[u8] =
        b"\x80\x04\x95\x1d\0\0\0\0\0\0\0\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.";
    const PROTO5: &[u8] =
        b"\x80\x05\x95\x1d\0\0\0\0\0\0\0\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.";

    #[test]
    fn every_protocol_zero_through_five_is_recognised() {
        for (proto, stream) in [
            (0, PROTO0),
            (1, PROTO1),
            (2, PROTO2),
            (3, PROTO3),
            (4, PROTO4),
            (5, PROTO5),
        ] {
            let hit = walk(stream).unwrap_or_else(|| panic!("protocol {proto} not recognised"));
            assert_eq!(hit.module, "posix", "protocol {proto}");
            assert_eq!(hit.callable, "system", "protocol {proto}");
            assert!(hit.reduced, "protocol {proto} must be seen as a reduction");
        }
    }

    // ── differential vectors: byte-for-byte CPython 3.13.5 output ───────────
    //
    // Generated by `pickle.dumps(obj, protocol=p)` for every protocol, not
    // hand-written, so the walker is measured against what the interpreter
    // actually emits rather than against our reading of the format. The benign
    // half is the load-bearing half: it is made of the globals real serialized
    // data is built from (`collections.OrderedDict`, `copy_reg._reconstructor`,
    // `_codecs.encode`, `datetime.datetime`, `decimal.Decimal`,
    // `fractions.Fraction`, `builtins.set` / `frozenset`, `collections.deque`,
    // a plain `__main__` instance), every one of which must resolve to nothing.

    const DANGEROUS_VECTORS: &[(&str, u8, &str)] = &[
        ("os.system", 0, "Y3Bvc2l4CnN5c3RlbQpwMAooVmlkCnAxCnRwMgpScDMKLg=="),
        ("os.system", 1, "Y3Bvc2l4CnN5c3RlbQpxAChYAgAAAGlkcQF0cQJScQMu"),
        ("os.system", 2, "gAJjcG9zaXgKc3lzdGVtCnEAWAIAAABpZHEBhXECUnEDLg=="),
        ("os.system", 3, "gANjcG9zaXgKc3lzdGVtCnEAWAIAAABpZHEBhXECUnEDLg=="),
        (
            "os.system",
            4,
            "gASVHQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
        ),
        (
            "os.system",
            5,
            "gAWVHQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==",
        ),
        (
            "subprocess.check_output",
            0,
            "Y2NvbW1hbmRzCmNoZWNrX291dHB1dApwMAooKGxwMQpWaWQKcDIKYXRwMwpScDQKLg==",
        ),
        (
            "subprocess.check_output",
            1,
            "Y2NvbW1hbmRzCmNoZWNrX291dHB1dApxAChdcQFYAgAAAGlkcQJhdHEDUnEELg==",
        ),
        (
            "subprocess.check_output",
            2,
            "gAJjY29tbWFuZHMKY2hlY2tfb3V0cHV0CnEAXXEBWAIAAABpZHECYYVxA1JxBC4=",
        ),
        (
            "subprocess.check_output",
            3,
            "gANjc3VicHJvY2VzcwpjaGVja19vdXRwdXQKcQBdcQFYAgAAAGlkcQJhhXEDUnEELg==",
        ),
        (
            "subprocess.check_output",
            4,
            "gASVKwAAAAAAAACMCnN1YnByb2Nlc3OUjAxjaGVja19vdXRwdXSUk5RdlIwCaWSUYYWUUpQu",
        ),
        (
            "subprocess.check_output",
            5,
            "gAWVKwAAAAAAAACMCnN1YnByb2Nlc3OUjAxjaGVja19vdXRwdXSUk5RdlIwCaWSUYYWUUpQu",
        ),
        (
            "builtins.eval",
            0,
            "Y19fYnVpbHRpbl9fCmV2YWwKcDAKKFYxKzEKcDEKdHAyClJwMwou",
        ),
        (
            "builtins.eval",
            1,
            "Y19fYnVpbHRpbl9fCmV2YWwKcQAoWAMAAAAxKzFxAXRxAlJxAy4=",
        ),
        (
            "builtins.eval",
            2,
            "gAJjX19idWlsdGluX18KZXZhbApxAFgDAAAAMSsxcQGFcQJScQMu",
        ),
        ("builtins.eval", 3, "gANjYnVpbHRpbnMKZXZhbApxAFgDAAAAMSsxcQGFcQJScQMu"),
        (
            "builtins.eval",
            4,
            "gASVHwAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwDMSsxlIWUUpQu",
        ),
        (
            "builtins.eval",
            5,
            "gAWVHwAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwDMSsxlIWUUpQu",
        ),
        ("os.popen", 0, "Y29zCnBvcGVuCnAwCihWaWQKcDEKdHAyClJwMwou"),
        ("os.popen", 1, "Y29zCnBvcGVuCnEAKFgCAAAAaWRxAXRxAlJxAy4="),
        ("os.popen", 2, "gAJjb3MKcG9wZW4KcQBYAgAAAGlkcQGFcQJScQMu"),
        ("os.popen", 3, "gANjb3MKcG9wZW4KcQBYAgAAAGlkcQGFcQJScQMu"),
        ("os.popen", 4, "gASVGQAAAAAAAACMAm9zlIwFcG9wZW6Uk5SMAmlklIWUUpQu"),
        ("os.popen", 5, "gAWVGQAAAAAAAACMAm9zlIwFcG9wZW6Uk5SMAmlklIWUUpQu"),
    ];

    const BENIGN_VECTORS: &[(&str, u8, &str)] = &[
        (
            "ordereddict",
            0,
            "Y2NvbGxlY3Rpb25zCk9yZGVyZWREaWN0CnAwCih0UnAxClZhCnAyCkkxCnNWYgpwMwoobHA0CkkxCmFJMgphSTMKYXMu",
        ),
        (
            "ordereddict",
            1,
            "Y2NvbGxlY3Rpb25zCk9yZGVyZWREaWN0CnEAKVJxAShYAQAAAGFxAksBWAEAAABicQNdcQQoSwFLAksDZXUu",
        ),
        (
            "ordereddict",
            2,
            "gAJjY29sbGVjdGlvbnMKT3JkZXJlZERpY3QKcQApUnEBKFgBAAAAYXECSwFYAQAAAGJxA11xBChLAUsCSwNldS4=",
        ),
        (
            "ordereddict",
            3,
            "gANjY29sbGVjdGlvbnMKT3JkZXJlZERpY3QKcQApUnEBKFgBAAAAYXECSwFYAQAAAGJxA11xBChLAUsCSwNldS4=",
        ),
        (
            "ordereddict",
            4,
            "gASVOAAAAAAAAACMC2NvbGxlY3Rpb25zlIwLT3JkZXJlZERpY3SUk5QpUpQojAFhlEsBjAFilF2UKEsBSwJLA2V1Lg==",
        ),
        (
            "ordereddict",
            5,
            "gAWVOAAAAAAAAACMC2NvbGxlY3Rpb25zlIwLT3JkZXJlZERpY3SUk5QpUpQojAFhlEsBjAFilF2UKEsBSwJLA2V1Lg==",
        ),
        (
            "datetime",
            0,
            "Y2RhdGV0aW1lCmRhdGV0aW1lCnAwCihjX2NvZGVjcwplbmNvZGUKcDEKKFYH6gceDFx1MDAwMFx1MDAwMFx1MDAwMFx1MDAwMFx1MDAwMApwMgpWbGF0aW4xCnAzCnRwNApScDUKdHA2ClJwNwou",
        ),
        (
            "datetime",
            1,
            "Y2RhdGV0aW1lCmRhdGV0aW1lCnEAKGNfY29kZWNzCmVuY29kZQpxAShYCwAAAAfDqgceDAAAAAAAcQJYBgAAAGxhdGluMXEDdHEEUnEFdHEGUnEHLg==",
        ),
        (
            "datetime",
            2,
            "gAJjZGF0ZXRpbWUKZGF0ZXRpbWUKcQBjX2NvZGVjcwplbmNvZGUKcQFYCwAAAAfDqgceDAAAAAAAcQJYBgAAAGxhdGluMXEDhnEEUnEFhXEGUnEHLg==",
        ),
        (
            "datetime",
            3,
            "gANjZGF0ZXRpbWUKZGF0ZXRpbWUKcQBDCgfqBx4MAAAAAABxAYVxAlJxAy4=",
        ),
        (
            "datetime",
            4,
            "gASVKgAAAAAAAACMCGRhdGV0aW1llIwIZGF0ZXRpbWWUk5RDCgfqBx4MAAAAAACUhZRSlC4=",
        ),
        (
            "datetime",
            5,
            "gAWVKgAAAAAAAACMCGRhdGV0aW1llIwIZGF0ZXRpbWWUk5RDCgfqBx4MAAAAAACUhZRSlC4=",
        ),
        ("decimal", 0, "Y2RlY2ltYWwKRGVjaW1hbApwMAooVjMuMTQxNTkKcDEKdHAyClJwMwou"),
        ("decimal", 1, "Y2RlY2ltYWwKRGVjaW1hbApxAChYBwAAADMuMTQxNTlxAXRxAlJxAy4="),
        ("decimal", 2, "gAJjZGVjaW1hbApEZWNpbWFsCnEAWAcAAAAzLjE0MTU5cQGFcQJScQMu"),
        ("decimal", 3, "gANjZGVjaW1hbApEZWNpbWFsCnEAWAcAAAAzLjE0MTU5cQGFcQJScQMu"),
        (
            "decimal",
            4,
            "gASVJQAAAAAAAACMB2RlY2ltYWyUjAdEZWNpbWFslJOUjAczLjE0MTU5lIWUUpQu",
        ),
        (
            "decimal",
            5,
            "gAWVJQAAAAAAAACMB2RlY2ltYWyUjAdEZWNpbWFslJOUjAczLjE0MTU5lIWUUpQu",
        ),
        (
            "fraction",
            0,
            "Y2ZyYWN0aW9ucwpGcmFjdGlvbgpwMAooSTIyCkk3CnRwMQpScDIKLg==",
        ),
        ("fraction", 1, "Y2ZyYWN0aW9ucwpGcmFjdGlvbgpxAChLFksHdHEBUnECLg=="),
        ("fraction", 2, "gAJjZnJhY3Rpb25zCkZyYWN0aW9uCnEASxZLB4ZxAVJxAi4="),
        ("fraction", 3, "gANjZnJhY3Rpb25zCkZyYWN0aW9uCnEASxZLB4ZxAVJxAi4="),
        (
            "fraction",
            4,
            "gASVIgAAAAAAAACMCWZyYWN0aW9uc5SMCEZyYWN0aW9ulJOUSxZLB4aUUpQu",
        ),
        (
            "fraction",
            5,
            "gAWVIgAAAAAAAACMCWZyYWN0aW9uc5SMCEZyYWN0aW9ulJOUSxZLB4aUUpQu",
        ),
        (
            "nested",
            0,
            "KGRwMApWdXNlcnMKcDEKKGxwMgooZHAzClZpZApwNApJMQpzVnRhZ3MKcDUKY19fYnVpbHRpbl9fCnNldApwNgooKGxwNwpWYgpwOAphVmEKcDkKYXRwMTAKUnAxMQpzYXNWbgpwMTIKTDEyMzc5NDAwMzkyODUzODAyNzQ4OTkxMjQyMjRMCnNWZgpwMTMKRjEuNQpzLg==",
        ),
        (
            "nested",
            1,
            "fXEAKFgFAAAAdXNlcnNxAV1xAn1xAyhYAgAAAGlkcQRLAVgEAAAAdGFnc3EFY19fYnVpbHRpbl9fCnNldApxBihdcQcoWAEAAABicQhYAQAAAGFxCWV0cQpScQt1YVgBAAAAbnEMTDEyMzc5NDAwMzkyODUzODAyNzQ4OTkxMjQyMjRMClgBAAAAZnENRz/4AAAAAAAAdS4=",
        ),
        (
            "nested",
            2,
            "gAJ9cQAoWAUAAAB1c2Vyc3EBXXECfXEDKFgCAAAAaWRxBEsBWAQAAAB0YWdzcQVjX19idWlsdGluX18Kc2V0CnEGXXEHKFgBAAAAYnEIWAEAAABhcQllhXEKUnELdWFYAQAAAG5xDIoMAAAAAAAAAAAAAAAEWAEAAABmcQ1HP/gAAAAAAAB1Lg==",
        ),
        (
            "nested",
            3,
            "gAN9cQAoWAUAAAB1c2Vyc3EBXXECfXEDKFgCAAAAaWRxBEsBWAQAAAB0YWdzcQVjYnVpbHRpbnMKc2V0CnEGXXEHKFgBAAAAYnEIWAEAAABhcQllhXEKUnELdWFYAQAAAG5xDIoMAAAAAAAAAAAAAAAEWAEAAABmcQ1HP/gAAAAAAAB1Lg==",
        ),
        (
            "nested",
            4,
            "gASVTQAAAAAAAAB9lCiMBXVzZXJzlF2UfZQojAJpZJRLAYwEdGFnc5SPlCiMAWKUjAFhlJB1YYwBbpSKDAAAAAAAAAAAAAAABIwBZpRHP/gAAAAAAAB1Lg==",
        ),
        (
            "nested",
            5,
            "gAWVTQAAAAAAAAB9lCiMBXVzZXJzlF2UfZQojAJpZJRLAYwEdGFnc5SPlCiMAWKUjAFhlJB1YYwBbpSKDAAAAAAAAAAAAAAABIwBZpRHP/gAAAAAAAB1Lg==",
        ),
        (
            "plain-object",
            0,
            "Y2NvcHlfcmVnCl9yZWNvbnN0cnVjdG9yCnAwCihjX19tYWluX18KUGxhaW4KcDEKY19fYnVpbHRpbl9fCm9iamVjdApwMgpOdHAzClJwNAooZHA1ClZhCnA2CkkxCnNWYgpwNwpWdHdvCnA4CnNiLg==",
        ),
        (
            "plain-object",
            1,
            "Y2NvcHlfcmVnCl9yZWNvbnN0cnVjdG9yCnEAKGNfX21haW5fXwpQbGFpbgpxAWNfX2J1aWx0aW5fXwpvYmplY3QKcQJOdHEDUnEEfXEFKFgBAAAAYXEGSwFYAQAAAGJxB1gDAAAAdHdvcQh1Yi4=",
        ),
        (
            "plain-object",
            2,
            "gAJjX19tYWluX18KUGxhaW4KcQApgXEBfXECKFgBAAAAYXEDSwFYAQAAAGJxBFgDAAAAdHdvcQV1Yi4=",
        ),
        (
            "plain-object",
            3,
            "gANjX19tYWluX18KUGxhaW4KcQApgXEBfXECKFgBAAAAYXEDSwFYAQAAAGJxBFgDAAAAdHdvcQV1Yi4=",
        ),
        (
            "plain-object",
            4,
            "gASVLgAAAAAAAACMCF9fbWFpbl9flIwFUGxhaW6Uk5QpgZR9lCiMAWGUSwGMAWKUjAN0d2+UdWIu",
        ),
        (
            "plain-object",
            5,
            "gAWVLgAAAAAAAACMCF9fbWFpbl9flIwFUGxhaW6Uk5QpgZR9lCiMAWGUSwGMAWKUjAN0d2+UdWIu",
        ),
        (
            "bytes",
            0,
            "Y19jb2RlY3MKZW5jb2RlCnAwCihWXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQJcdTAwMDABAlx1MDAwMAECXHUwMDAwAQIKcDEKVmxhdGluMQpwMgp0cDMKUnA0Ci4=",
        ),
        (
            "bytes",
            1,
            "Y19jb2RlY3MKZW5jb2RlCnEAKFh4AAAAAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECAAECcQFYBgAAAGxhdGluMXECdHEDUnEELg==",
        ),
        (
            "bytes",
            2,
            "gAJjX2NvZGVjcwplbmNvZGUKcQBYeAAAAAABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAnEBWAYAAABsYXRpbjFxAoZxA1JxBC4=",
        ),
        (
            "bytes",
            3,
            "gANDeAABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAnEALg==",
        ),
        (
            "bytes",
            4,
            "gASVfAAAAAAAAABDeAABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABApQu",
        ),
        (
            "bytes",
            5,
            "gAWVfAAAAAAAAABDeAABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABAgABApQu",
        ),
        ("deque", 0, "Y2NvbGxlY3Rpb25zCmRlcXVlCnAwCih0UnAxCkkxCmFJMgphSTMKYS4="),
        ("deque", 1, "Y2NvbGxlY3Rpb25zCmRlcXVlCnEAKVJxAShLAUsCSwNlLg=="),
        ("deque", 2, "gAJjY29sbGVjdGlvbnMKZGVxdWUKcQApUnEBKEsBSwJLA2Uu"),
        ("deque", 3, "gANjY29sbGVjdGlvbnMKZGVxdWUKcQApUnEBKEsBSwJLA2Uu"),
        (
            "deque",
            4,
            "gASVJAAAAAAAAACMC2NvbGxlY3Rpb25zlIwFZGVxdWWUk5QpUpQoSwFLAksDZS4=",
        ),
        (
            "deque",
            5,
            "gAWVJAAAAAAAAACMC2NvbGxlY3Rpb25zlIwFZGVxdWWUk5QpUpQoSwFLAksDZS4=",
        ),
        (
            "frozenset",
            0,
            "Y19fYnVpbHRpbl9fCmZyb3plbnNldApwMAooKGxwMQpJMQphSTIKYUkzCmF0cDIKUnAzCi4=",
        ),
        (
            "frozenset",
            1,
            "Y19fYnVpbHRpbl9fCmZyb3plbnNldApxAChdcQEoSwFLAksDZXRxAlJxAy4=",
        ),
        (
            "frozenset",
            2,
            "gAJjX19idWlsdGluX18KZnJvemVuc2V0CnEAXXEBKEsBSwJLA2WFcQJScQMu",
        ),
        (
            "frozenset",
            3,
            "gANjYnVpbHRpbnMKZnJvemVuc2V0CnEAXXEBKEsBSwJLA2WFcQJScQMu",
        ),
        ("frozenset", 4, "gASVCgAAAAAAAAAoSwFLAksDkZQu"),
        ("frozenset", 5, "gAWVCgAAAAAAAAAoSwFLAksDkZQu"),
    ];

    fn decode_vector(b64: &str) -> Vec<u8> {
        STANDARD.decode(b64).expect("vector is valid base64")
    }

    #[test]
    fn cpython_dangerous_vectors_are_recognised_at_every_protocol() {
        for (label, proto, b64) in DANGEROUS_VECTORS {
            let stream = decode_vector(b64);
            let hit = walk(&stream).unwrap_or_else(|| panic!("{label} at protocol {proto} missed"));
            assert!(hit.reduced, "{label} at protocol {proto} must be seen as a reduction");
        }
    }

    #[test]
    fn cpython_benign_vectors_produce_nothing_at_every_protocol() {
        for (label, proto, b64) in BENIGN_VECTORS {
            let stream = decode_vector(b64);
            assert_eq!(walk(&stream), None, "{label} at protocol {proto} false-positived");
        }
    }

    #[test]
    fn corpus_row_deser_009_is_recognised_through_base64() {
        // tests/lane2/corpus/attack-t2.jsonl, verbatim.
        let body = r#"{"blob":"gASVIAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg=="}"#;
        let hit = scan(body).expect("base64-wrapped protocol-4 pickle");
        assert_eq!((hit.module, hit.callable, hit.reduced), ("posix", "system", true));
    }

    #[test]
    fn a_hex_wrapped_pickle_is_recognised() {
        let hex_form = hex::encode(PROTO4);
        let hit = scan(&format!("payload={hex_form}")).expect("hex-wrapped protocol-4 pickle");
        assert_eq!((hit.module, hit.callable, hit.reduced), ("posix", "system", true));
    }

    #[test]
    fn corpus_row_deser_007_is_recognised_raw() {
        let hit = scan("cos\nsystem\n(S'id'\ntR.").expect("raw protocol-0 pickle");
        assert_eq!((hit.module, hit.callable, hit.reduced), ("os", "system", true));
    }

    #[test]
    fn a_named_global_without_a_reduction_is_graded_lower() {
        // `GLOBAL posix system` then STOP: the callable is on the stack but was
        // never applied.
        let hit = walk(b"cposix\nsystem\n.").expect("named global");
        assert!(!hit.reduced);
    }

    // ── the safety property, as a test rather than an assumption ─────────────

    #[test]
    fn a_hit_never_carries_payload_bytes() {
        // The reported strings must come from the compile-time table, never
        // from the walked bytes. Walk a heap-owned copy of the stream and assert
        // the reported `&'static str`s point outside that allocation — the
        // structural form of "this detector cannot echo attacker data".
        let owned = PROTO4.to_vec();
        let mut state = ContentInspectionState::new(super::super::budget::Budget::default());
        let hit = walk_stream(&owned, &mut state).expect("protocol 4");
        let lo = owned.as_ptr() as usize;
        let hi = lo.saturating_add(owned.len());
        for reported in [hit.module, hit.callable] {
            let at = reported.as_ptr() as usize;
            assert!(at < lo || at >= hi, "a hit must not borrow the walked stream");
        }
        assert_eq!((hit.module, hit.callable), ("posix", "system"));
    }

    #[test]
    fn benign_globals_produce_nothing() {
        for stream in [
            // collections.OrderedDict — the single most common global in real
            // serialized data.
            b"\x80\x04\x95\x20\0\0\0\0\0\0\0\x8c\x0bcollections\x94\x8c\x0bOrderedDict\x94\x93\x94)R\x94.".as_slice(),
            // copy_reg._reconstructor, the protocol-0/1 workhorse.
            b"ccopy_reg\n_reconstructor\np0\n(c__main__\nC\np1\nc__builtin__\nobject\np2\nNtp3\nRp4\n.".as_slice(),
            // numpy array reconstruction.
            b"\x80\x04\x95\x30\0\0\0\0\0\0\0\x8c\x15numpy.core.multiarray\x94\x8c\x0c_reconstruct\x94\x93\x94."
                .as_slice(),
            // _codecs.encode, which serde-pickle whitelists for the same reason.
            b"\x80\x04\x95\x20\0\0\0\0\0\0\0\x8c\x07_codecs\x94\x8c\x06encode\x94\x93\x94.".as_slice(),
        ] {
            assert_eq!(walk(stream), None, "benign global must not fire");
        }
    }

    #[test]
    fn ordinary_text_produces_nothing() {
        for text in [
            "Some sentence that happens to start with S and end with a full stop.",
            "The quick brown fox. Nothing here is a pickle.",
            r#"{"user":"alice","role":"admin","note":"see the docs."}"#,
            // A base64 JWT-shaped token.
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
            // Base64 of ordinary prose.
            "aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBwZXJmZWN0bHkgb3JkaW5hcnkgc2VudGVuY2Uu",
            // The word `system` next to the word `os`, in prose.
            "The os system call is documented in section 3. See os.system for details.",
        ] {
            assert_eq!(scan(text), None, "benign text must not fire: {text}");
        }
    }

    // ── malformed / hostile input: the walker must never panic, hang or grow ──

    #[test]
    fn every_truncation_of_every_protocol_is_survivable() {
        for stream in [PROTO0, PROTO1, PROTO2, PROTO3, PROTO4, PROTO5] {
            for n in 0..=stream.len() {
                let prefix = stream.get(..n).unwrap_or(stream);
                let _ = walk(prefix);
            }
        }
    }

    #[test]
    fn lying_length_prefixes_are_declined_not_trusted() {
        // SHORT_BINUNICODE claiming 255 bytes with 2 available.
        assert_eq!(walk(b"\x80\x04\x8c\xffab\x93R.".as_slice()), None);
        // BINUNICODE claiming 4 GiB.
        assert_eq!(walk(b"\x80\x04X\xff\xff\xff\xffab\x93R.".as_slice()), None);
        // BINUNICODE8 claiming u64::MAX.
        assert_eq!(
            walk(b"\x80\x04\x8d\xff\xff\xff\xff\xff\xff\xff\xffa\x93R.".as_slice()),
            None
        );
        // FRAME declaring a length far beyond the buffer — must not be trusted
        // as a jump target.
        assert_eq!(walk(b"\x80\x04\x95\xff\xff\xff\xff\xff\xff\xff\xff.".as_slice()), None);
    }

    #[test]
    fn stack_underflow_never_panics() {
        for stream in [
            b"R......".as_slice(),
            b"\x93\x93\x93\x93\x93\x93.".as_slice(),
            b"\x85\x86\x87.....".as_slice(),
            b"tttttt.".as_slice(),
            b"\x942222.".as_slice(),
            b"o......".as_slice(),
            b"b0sae1u.".as_slice(),
        ] {
            let _ = walk(stream);
        }
    }

    #[test]
    fn a_deeply_padded_stream_terminates_and_still_reduces() {
        // 2000 `NONE` pushes before the exploit: the stack bound must not be a
        // usable evasion, because it is set to the input-byte bound.
        let mut stream = vec![OP_PROTO, 4];
        stream.extend(std::iter::repeat_n(OP_NONE, 2000));
        stream.extend_from_slice(b"\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R.");
        let hit = walk(&stream).expect("deep stack must still reduce");
        assert!(hit.reduced);
    }

    #[test]
    fn a_stream_of_marks_terminates() {
        let stream: Vec<u8> = std::iter::repeat_n(OP_MARK, 5000)
            .chain(std::iter::once(OP_STOP))
            .collect();
        assert_eq!(walk(&stream), None);
    }

    #[test]
    fn a_stream_of_dups_cannot_grow_without_bound() {
        let mut stream = vec![OP_NONE];
        stream.extend(std::iter::repeat_n(OP_DUP, 8000));
        stream.push(OP_STOP);
        assert_eq!(walk(&stream), None);
    }

    #[test]
    fn a_huge_memo_index_does_not_size_an_allocation() {
        // LONG_BINPUT with index 0xFFFF_FFFF, then recall it.
        assert_eq!(walk(b"\x80\x04N r\xff\xff\xff\xffj\xff\xff\xff\xff.".as_slice()), None);
    }

    /// Deterministic xorshift — a repeatable pseudo-random source with no
    /// dependency, so a failure here reproduces exactly.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn mutated_real_pickles_never_panic_hang_or_grow() {
        // The shape that bit `brush-parser`: a valid stream with one byte
        // changed. Every single-byte substitution of every byte of every
        // protocol vector, plus random splices and random noise, all walked.
        let mut seed = 0x5eed_1234_abcd_0f0fu64;
        for (_, _, b64) in DANGEROUS_VECTORS.iter().chain(BENIGN_VECTORS.iter()) {
            let base = decode_vector(b64);
            for i in 0..base.len() {
                for delta in [1u8, 0x7f, 0x80, 0xff] {
                    let mut mutated = base.clone();
                    if let Some(slot) = mutated.get_mut(i) {
                        *slot = slot.wrapping_add(delta);
                    }
                    let _ = walk(&mutated);
                }
            }
            // Random splices: keep a prefix, append random bytes.
            for _ in 0..16 {
                let cut = usize::try_from(xorshift(&mut seed) % 64).unwrap_or(0).min(base.len());
                let mut spliced = base.get(..cut).unwrap_or(&base).to_vec();
                for _ in 0..(xorshift(&mut seed) % 48) {
                    spliced.push(u8::try_from(xorshift(&mut seed) & 0xff).unwrap_or(0));
                }
                let _ = walk(&spliced);
            }
        }
        // Pure noise, including streams that start with a real PROTO header so
        // the admission gate lets them into the walk.
        for _ in 0..4096 {
            let len = usize::try_from(xorshift(&mut seed) % 512).unwrap_or(0);
            let mut noise = vec![OP_PROTO, 4];
            for _ in 0..len {
                noise.push(u8::try_from(xorshift(&mut seed) & 0xff).unwrap_or(0));
            }
            noise.push(OP_STOP);
            let _ = walk(&noise);
        }
    }

    #[test]
    fn every_single_byte_and_pair_is_survivable() {
        for a in 0u8..=255 {
            let _ = walk(&[a]);
            let _ = walk(&[a, OP_STOP, OP_STOP, OP_STOP, OP_STOP, OP_STOP]);
            for b in 0u8..=255 {
                let _ = walk(&[a, b, OP_STOP, OP_STOP, OP_STOP, OP_STOP]);
            }
        }
    }

    #[test]
    fn oversized_input_is_truncated_not_walked_whole() {
        let mut stream = vec![OP_PROTO, 4];
        stream.extend(std::iter::repeat_n(OP_NONE, MAX_PICKLE_BYTES * 4));
        stream.push(OP_STOP);
        // Nothing dangerous in it; the point is that it returns.
        assert_eq!(walk(&stream), None);
    }

    #[test]
    fn the_parse_byte_budget_is_charged_and_can_be_exhausted() {
        let budget = super::super::budget::Budget {
            max_ast_input_bytes_total: 8,
            ..Default::default()
        };
        let mut state = ContentInspectionState::new(budget);
        assert_eq!(walk_stream(PROTO4, &mut state), None, "budget must decline the walk");
        assert!(state.is_degraded(), "an exhausted parse budget must mark degraded");
    }

    // ── resolver coverage ───────────────────────────────────────────────────

    #[test]
    fn classify_matches_only_the_table() {
        let resolve = |m: &[u8], c: &[u8]| locate_global(m, c).and_then(unpack_global);
        assert_eq!(resolve(b"os", b"system"), Some(("os", "system")));
        assert_eq!(resolve(b"nt", b"system"), Some(("nt", "system")));
        assert_eq!(
            resolve(b"subprocess", b"check_output"),
            Some(("subprocess", "check_output"))
        );
        assert_eq!(resolve(b"builtins", b"eval"), Some(("builtins", "eval")));
        assert_eq!(resolve(b"__builtin__", b"eval"), Some(("__builtin__", "eval")));
        // `_compat_pickle` rewrites `subprocess` to `commands` below protocol 3.
        assert_eq!(
            resolve(b"commands", b"check_output"),
            Some(("commands", "check_output"))
        );
        // Case-sensitive, like Python.
        assert_eq!(resolve(b"OS", b"system"), None);
        assert_eq!(resolve(b"os", b"System"), None);
        // Not in the table — the globals ordinary serialized data is made of.
        assert_eq!(resolve(b"collections", b"OrderedDict"), None);
        assert_eq!(resolve(b"copy_reg", b"_reconstructor"), None);
        assert_eq!(resolve(b"_codecs", b"encode"), None);
        assert_eq!(resolve(b"os", b"getcwd"), None);
    }

    #[test]
    fn pack_and_unpack_round_trip_every_table_entry() {
        for (m, (module, callables)) in DANGEROUS_GLOBALS.iter().enumerate() {
            for (c, callable) in callables.iter().enumerate() {
                let packed =
                    locate_global(module.as_bytes(), callable.as_bytes()).expect("every table entry must locate");
                assert_eq!(unpack_global(packed), Some((*module, *callable)));
                assert_eq!(packed, pack_global(m, c));
            }
        }
    }

    #[test]
    fn inst_and_obj_count_as_reductions() {
        // INST: `i<module>\n<callable>\n` after a MARK.
        let hit = walk(b"(iposix\nsystem\n.").expect("INST");
        assert!(hit.reduced);
        // OBJ: MARK, GLOBAL, args, `o`.
        let hit = walk(b"(cposix\nsystem\nS'id'\no.").expect("OBJ");
        assert!(hit.reduced);
    }

    #[test]
    fn a_memo_recalled_global_still_reduces() {
        // GLOBAL, PUT 0, POP, GET 0, EMPTY_TUPLE, REDUCE.
        let hit = walk(b"cposix\nsystem\np0\n0g0\n)R.").expect("memoised global");
        assert!(hit.reduced);
    }
}
