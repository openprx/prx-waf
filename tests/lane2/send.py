#!/usr/bin/env python3
"""Replay the Lane 2 corpus at a running prx-waf and record what came back.

One corpus row = one HTTP request = one **unique loopback source address**.

The source address is the join key, and it is the only part of this script that
needs explaining. `semantic_observations` stores `client_ip` but not the path
(the table is deliberately de-identified — plan v2.2 §13.1 — so it carries the
signal breakdown and nothing that could reconstruct the payload). Correlating a
row back to the corpus case that produced it therefore needs a per-case value
that survives into that table, and `client_ip` is the only one.

`127.0.0.0/8` is entirely local on Linux, so every address in it is bindable
without configuring anything, and `trust_proxy_headers = false` in the generated
config means the WAF takes the peer address verbatim — a corpus row carrying its
own `X-Forwarded-For` (there are several, deliberately) cannot move the key.
Case *i* binds `127.(16 + n>>16).(n>>8 & 255).(n & 255)` with `n = i + 1`.

The alternative — sending serially and matching observations by insertion order —
does not work: a request that produces no signal writes no observation, so the
two sequences drift apart at the first clean request and every subsequent
attribution is wrong.

Requests are sent **serially**, one connection each. The corpus is ~400 rows, so
the whole replay is a few seconds, and serial keeps the WAF's per-request work
(and the observation sink's queue) uncontended.
"""

from __future__ import annotations

import argparse
import http.client
import json
import pathlib
import socket
import sys
import time


def load_corpus(paths: list[pathlib.Path]) -> list[dict]:
    """Read every corpus file into one list, validating as we go.

    A malformed corpus is a silent measurement error — a row that fails to parse
    would simply not be sent, and the denominator would shrink without anyone
    noticing. So every failure here is fatal.
    """
    rows: list[dict] = []
    seen: dict[str, str] = {}
    required = {
        "id",
        "label",
        "family",
        "method",
        "path",
        "query",
        "headers",
        "content_type",
        "body",
        "note",
    }
    for path in paths:
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError as exc:
                    raise SystemExit(f"{path}:{lineno}: not valid JSON: {exc}") from exc
                missing = required - set(row)
                if missing:
                    raise SystemExit(f"{path}:{lineno}: missing keys {sorted(missing)}")
                if row["label"] not in ("attack", "benign"):
                    raise SystemExit(f"{path}:{lineno}: label must be attack|benign")
                if row["label"] == "attack" and not row["family"]:
                    raise SystemExit(f"{path}:{lineno}: an attack row needs a family")
                if row["label"] == "benign" and row["family"] is not None:
                    raise SystemExit(f"{path}:{lineno}: a benign row must have family null")
                # A raw space or control character in the request line makes
                # http.client refuse to send the row. That refusal lands in the
                # `harness` bucket, which reads like "the WAF answered oddly"
                # rather than "this row was never sent" — two corpus rows sat
                # there before this check existed. The corpus declares what goes
                # on the wire, so a row that cannot go on the wire is a corpus
                # bug and is fatal here.
                for field in ("path", "query"):
                    bad = [c for c in row[field] if c <= " " or c == "\x7f"]
                    if bad:
                        raise SystemExit(
                            f"{path}:{lineno}: {field} contains a raw space or control "
                            f"character ({bad[0]!r}) — percent-encode it"
                        )
                cid = row["id"]
                if cid in seen:
                    raise SystemExit(f"{path}:{lineno}: duplicate id '{cid}' (also in {seen[cid]})")
                seen[cid] = f"{path}:{lineno}"
                row["_source_file"] = path.name
                rows.append(row)
    if not rows:
        raise SystemExit("corpus is empty")
    return rows


def source_ip(index: int) -> str:
    """The per-case loopback source address. See the module docstring."""
    n = index + 1
    return f"127.{16 + (n >> 16)}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def send_one(row: dict, src: str, dest: str, port: int, host_header: str, timeout: float) -> dict:
    """Send one corpus row and return its outcome record."""
    url = row["path"]
    if row["query"]:
        url = f"{url}?{row['query']}"

    headers = {str(k): str(v) for k, v in (row["headers"] or {}).items()}
    headers["Host"] = host_header
    body = None
    if row["body"] is not None:
        body = row["body"].encode("utf-8")
        if row["content_type"]:
            headers["Content-Type"] = row["content_type"]
        headers["Content-Length"] = str(len(body))

    started = time.monotonic()
    try:
        conn = http.client.HTTPConnection(dest, port, timeout=timeout, source_address=(src, 0))
        conn.request(row["method"], url, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        status = resp.status
        error = None
        conn.close()
    except (OSError, http.client.HTTPException) as exc:
        status = None
        error = f"{type(exc).__name__}: {exc}"

    return {
        "id": row["id"],
        "label": row["label"],
        "family": row["family"],
        "difficulty": row.get("difficulty"),
        "trap": row.get("trap"),
        "method": row["method"],
        "path": row["path"],
        "source_file": row["_source_file"],
        "note": row["note"],
        "client_ip": src,
        "status": status,
        "error": error,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        # Which surfaces this row puts content on. classify.py needs it to tell a
        # detector that missed a payload from a payload the engine never saw:
        # Lane 2's header scope is a curated list, so an attack delivered in a
        # header outside it is out of scope, not undetected.
        "has_query": bool(row["query"]),
        "has_body": row["body"] is not None,
        "header_names": sorted((row["headers"] or {}).keys()),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", nargs="+", required=True, help="corpus .jsonl files")
    ap.add_argument("--dest", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host-header", required=True)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--out", required=True, help="where to write the outcome records")
    args = ap.parse_args()

    rows = load_corpus([pathlib.Path(p) for p in args.corpus])

    # Fail before sending anything if the WAF is not actually there — a run
    # against a closed port would otherwise report "every case errored", which
    # reads like a catastrophic detection result rather than a wiring mistake.
    try:
        with socket.create_connection((args.dest, args.port), timeout=5):
            pass
    except OSError as exc:
        raise SystemExit(f"nothing listening on {args.dest}:{args.port} — {exc}") from exc

    results = []
    for index, row in enumerate(rows):
        results.append(
            send_one(row, source_ip(index), args.dest, args.port, args.host_header, args.timeout)
        )

    errored = [r for r in results if r["error"]]
    with pathlib.Path(args.out).open("w", encoding="utf-8") as fh:
        json.dump({"results": results}, fh, indent=1)

    print(f"sent {len(results)} requests ({len(errored)} transport errors)", file=sys.stderr)
    for r in errored[:10]:
        print(f"  {r['id']}: {r['error']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
