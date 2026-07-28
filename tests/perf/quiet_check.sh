#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# "Were the subject's cores the subject's alone?"
#
#   tests/perf/quiet_check.sh <pid> [cpus] [window_seconds]
#   tests/perf/quiet_check.sh 12345 0-3 8
#
# Compares the busy jiffies accumulated by a set of CPUs against the subject
# process's own utime+stime over the same window, and prints the residual.
#
# ── Why a load average is not enough ─────────────────────────────────────────
# `tests/perf/RESULTS.md` retires the old "load average below 3" quiet criterion
# and explains why: a multi-threaded subject contributes several runnable
# threads by itself, so a load average can no longer separate "the host was
# busy" from "the benchmark was working". The criterion that survives is the one
# this script implements — **no measurable CPU on the subject's cores other than
# the subject** — and it has to be checked DURING a run, because a background
# process that wakes up halfway through leaves no trace in a before/after
# reading.
#
# A residual of order ±0.02 cores is the cost of reading two counters a few
# hundred microseconds apart and means the cores were clean. A residual of a
# tenth of a core or more means something else ran there and the numbers from
# that window are contaminated.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PID="${1:?usage: quiet_check.sh <pid> [cpus] [window_seconds]}"
CPUS="${2:-0-3}"
WINDOW="${3:-8}"

[ -d "/proc/$PID" ] || { echo "no such pid: $PID" >&2; exit 1; }

clk_tck="$(getconf CLK_TCK)"

# Expand "0-3,7" into a list the /proc/stat filter can test against.
cpu_list() {
  local spec="$1" part lo hi
  IFS=',' read -ra parts <<<"$spec"
  for part in "${parts[@]}"; do
    if [[ "$part" == *-* ]]; then
      lo="${part%%-*}"; hi="${part##*-}"
      seq "$lo" "$hi"
    else
      echo "$part"
    fi
  done
}

CPU_SET="$(cpu_list "$CPUS" | tr '\n' ' ')"

# Busy jiffies on the selected CPUs. "Busy" is every field except idle (4th) and
# iowait (5th): a core waiting on IO is not a core somebody else is computing on.
cpus_busy() {
  awk -v want="$CPU_SET" '
    BEGIN { n = split(want, a, " "); for (i = 1; i <= n; i++) sel["cpu" a[i]] = 1 }
    $1 ~ /^cpu[0-9]+$/ && ($1 in sel) {
      total = 0
      for (i = 2; i <= NF; i++) total += $i
      busy += total - $5 - $6
    }
    END { print busy + 0 }' /proc/stat
}

proc_ticks() {
  awk '{ n = split($0, f, ") "); split(f[n], g, " "); print g[12] + g[13] }' \
    "/proc/$1/stat"
}

b0="$(cpus_busy)"; p0="$(proc_ticks "$PID")"; t0="$(date +%s.%N)"
sleep "$WINDOW"
b1="$(cpus_busy)"; p1="$(proc_ticks "$PID")"; t1="$(date +%s.%N)"

awk -v b="$((b1 - b0))" -v p="$((p1 - p0))" -v k="$clk_tck" \
    -v a="$t0" -v z="$t1" -v cpus="$CPUS" -v pid="$PID" '
  BEGIN {
    e = z - a
    if (e <= 0 || k <= 0) { print "quiet_check: bad window"; exit 1 }
    core_busy = (b / k) / e
    subj      = (p / k) / e
    resid     = core_busy - subj
    printf "cpus %-6s window %.1fs   cores busy %.3f   pid %s %.3f   unaccounted %+.3f\n",
           cpus, e, core_busy, pid, subj, resid
    if (resid > 0.05)
      printf "  CONTAMINATED: %+.3f cores of work on %s came from something other than pid %s\n",
             resid, cpus, pid
    else
      print  "  clean: nothing but the subject ran on those cores"
  }'
