# HTTP/2 attack surface

The TLS listener began advertising ALPN `h2` in v0.2.148 (`enable_h2()`,
`crates/prx-waf/src/main.rs:2511`). Before that this proxy only ever spoke
HTTP/1.1, so the frame-level attack surface that HTTP/2 opens — resets, header
continuations, control-frame floods — had never been examined. This document
records what defends each of those surfaces, cites the source that does it, and
carries the empirical evidence that it holds under attack.

The short version: the three named HTTP/2 denial-of-service classes
(Rapid Reset / CVE-2023-44487, CONTINUATION flood / CVE-2024-27316, and the
control-frame floods) are all answered inside the `h2` crate (0.4.15) that
Pingora hands the connection to, before a single request reaches WAF detection.
Pingora starts from `default_h2_options()`, which is `h2::server::Builder`'s
own defaults plus a 64 KiB header-list cap and a 100 concurrent-stream cap, and
never disables any of the reset guards. So the defense exists at the layer that
can actually see the frames — the WAF request path never runs on a stream that
`h2` has already refused.

## Where HTTP/2 lives in this proxy

There is no HTTP/2 code in this repository. ALPN negotiation, the frame codec,
HPACK, flow control, and every abuse guard below belong to `h2` 0.4.15, which
Pingora 0.8.1 drives:

- `enable_h2()` sets ALPN to `h2` then `http/1.1`
  (`crates/prx-waf/src/main.rs:2511`, doc block at 2490-2503).
- Pingora's accept loop peeks ALPN and, on `h2`, calls
  `server::handshake(stream, h2_options)`
  (`pingora-core-0.8.1/src/apps/mod.rs:213-225`). The connection's
  `conn.accept().await` at `.../protocols/http/v2/server.rs:148-149` is what
  drives every frame; each accepted stream is then spawned as its own task
  (`apps/mod.rs:256-261`) into `process_new_http`, which is where WAF
  `request_filter` eventually runs (`crates/gateway/src/proxy.rs:500`).
- `h2_options` is `None` in this build, so `apps/mod.rs:224` +
  `pingora-core-0.8.1/src/protocols/http/v2/server.rs:66` fall back to
  `default_h2_options()` (`.../v2/server.rs:53-58`): 64 KiB
  `max_header_list_size`, 100 `max_concurrent_streams`. Everything else keeps
  `h2::server::Builder::new()`'s defaults (`h2-0.4.15/src/server.rs:650-661`).

The consequence that matters for all three sections below: a frame-level guard
in `h2` fires **inside `conn.accept()`**, i.e. before Pingora pops a stream and
before the WAF ever builds a `RequestCtx`. A refused connection gets a `GOAWAY`
and is torn down; the detection lanes (Lane 1 / CRS / Lane 2, all synchronous in
`request_filter` — `crates/gateway/src/proxy.rs:721`,
`crates/waf-engine/src/engine.rs:1171`) never spend a cycle on it.

## 1. Rapid Reset (CVE-2023-44487)

Attack: open a stream (HEADERS) and immediately `RST_STREAM` it, over and over.
A naive server does the per-request work but never counts the stream against
`SETTINGS_MAX_CONCURRENT_STREAMS`, because the reset frees the slot instantly —
so the concurrency cap provides no backpressure and the attacker buys unbounded
request work at near-zero cost.

`h2` 0.4.15 carries the fix that was written in direct response to this CVE. A
stream that the remote resets *while it is still waiting to be accepted by the
application* is counted separately, and once too many such streams accumulate
the whole connection is failed with `GOAWAY(ENHANCE_YOUR_CALM)`:

- `recv_reset` (`h2-0.4.15/src/proto/streams/recv.rs:874-901`): when
  `stream.is_pending_accept`, it calls `counts.can_inc_num_remote_reset_streams()`;
  if the limit is already reached it returns
  `Error::library_go_away_data(Reason::ENHANCE_YOUR_CALM, "too_many_resets")`.
- The cap is `max_remote_reset_streams`
  (`h2-0.4.15/src/proto/streams/counts.rs:153-171`), seeded from
  `pending_accept_reset_stream_max`, whose default is
  `DEFAULT_REMOTE_RESET_STREAM_MAX = 20` (`h2-0.4.15/src/proto/mod.rs:34`,
  `src/server.rs:654`).
- The counter is only decremented once the application actually accepts the
  stream (`h2-0.4.15/src/proto/streams/streams.rs:144-146`, in `next_incoming`),
  so a flood that resets faster than Pingora accepts drives the count straight
  to the ceiling.
- A second, coarser ceiling covers streams this server itself resets on
  protocol errors: `local_max_error_reset_streams`, default
  `DEFAULT_LOCAL_RESET_COUNT_MAX = 1024` (`src/proto/mod.rs:35`,
  `src/server.rs:659`, `counts.rs:79-96`).

Pingora's `default_h2_options()` does not touch any of these, so the guard runs
with `pending_accept_reset_stream_max = 20`. The GOAWAY is emitted by the single
task that drives `conn.accept()`, which means the connection dies at the frame
layer; Pingora never pops a reset stream that arrived past the ceiling, so the
per-stream `process_new_http` task that carries WAF detection is never spawned
for it.

The residual, and it is inherent to any HTTP/2 server: a stream that Pingora
*accepts* before the RST arrives is decremented out of the reset counter, its
task is spawned, and the WAF does its work; the RST just cancels the response
write. That race is bounded by `max_concurrent_streams = 100` (only 100 tasks
in flight per connection) and by the 20-deep pending-accept-reset ceiling that
caps how fast an attacker can churn the pre-accept queue. It is not an
amplification vector: the attacker pays one full round trip per unit of work,
exactly as with HTTP/1.1 keep-alive.

_Empirical evidence: see "Measured behaviour" below._

## 2. CONTINUATION flood (CVE-2024-27316 class)

Attack: send HEADERS with `END_HEADERS` clear, then an unbounded stream of
CONTINUATION frames, forcing the server to accumulate header state forever
without ever completing the request — and, in the vulnerable servers, without
`max_header_list_size` being consulted until the header block finished.

`h2` 0.4.15 enforces two independent bounds *during* accumulation:

- A frame-count ceiling. `calc_max_continuation_frames`
  (`h2-0.4.15/src/codec/framed_read.rs:110-117`) derives a per-header-block cap
  from `max_header_list_size / max_frame_size` (min 5); the decoder counts
  CONTINUATION frames and returns
  `GOAWAY(ENHANCE_YOUR_CALM, "too_many_continuations")` once the count is
  exceeded (`framed_read.rs:304-316`). With the 64 KiB header-list cap and the
  16 KiB default frame size this ceiling is 5.
- A byte ceiling that is checked *while* the block is still being assembled:
  `partial.buf.len() + bytes.len() > max_header_list_size` →
  `GOAWAY(COMPRESSION_ERROR)` (`framed_read.rs:337-340`), and the decoded-size
  abuse limit → `GOAWAY(ENHANCE_YOUR_CALM, "header_list_way_too_large")`
  (`framed_read.rs:356-360`). This is the crux of the CVE: the size limit is
  applied per-frame during accumulation, not deferred to `END_HEADERS`.

So `max_header_list_size` (64 KiB via `default_h2_options()`) does bound the
mid-flight accumulation, and the frame-count guard trips first in practice. Both
fire inside `conn.accept()`, before the request is handed up.

_Empirical evidence: see "Measured behaviour" below._

## 3. Control-frame floods (SETTINGS / PING / WINDOW_UPDATE / HPACK table)

These are handled by construction rather than by a discrete counter, and reading
the source is enough to see why none of them buffer without bound. They still
cost CPU per frame, but that cost is paid one frame at a time by the single task
that reads the socket — there is no queue an attacker can grow.

- **SETTINGS flood.** The connection ACKs a received SETTINGS frame before it
  reads the next frame, and asserts there is never more than one outstanding:
  `assert!(self.remote.is_none())` on receipt
  (`h2-0.4.15/src/proto/settings.rs:80-85`), with the ACK written in
  `poll_send` (`src/proto/settings.rs:122-136`). No unbounded pending set; an
  unexpected ACK is a `PROTOCOL_ERROR` GOAWAY (`settings.rs:73-78`).
- **PING flood.** A received PING stores exactly one pending pong
  (`self.pending_pong = Some(...)`,
  `h2-0.4.15/src/proto/ping_pong.rs:132-134`), drained before the next read.
  One `Option`, not a queue.
- **WINDOW_UPDATE.** Flow-control accounting only; increments are validated
  against `MAX_WINDOW_SIZE` and overflow is a protocol error. No allocation is
  driven by receiving them.
- **HPACK dynamic table.** Bounded by `SETTINGS_HEADER_TABLE_SIZE`; the decoder
  tracks it as its own limit (`h2-0.4.15/src/codec/framed_read.rs:97-107`,
  `set_header_table_size`).

Because a control-frame flood is naturally serialized behind the socket read
loop, its ceiling is the client's own bandwidth, identical to any other traffic
the connection carries. There is no per-connection amplification to close, so
nothing here is exposed as a knob.

## Disposition

The `h2` crate already answers every surface HTTP/2 adds here, with defaults
that are the crate authors' own CVE responses, and Pingora keeps those defaults.
The honest conclusion for all three is **covered upstream** — so no counter or
guard is added in this repository that would merely duplicate one that already
fires earlier and closer to the frames.

<!-- Measured behaviour is appended after the empirical run. -->
