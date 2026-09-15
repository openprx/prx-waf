- **The performance harness records the load average of every round, and stops
  reporting its own affinity mask as the machine's CPU count.** `tests/perf/run.sh`
  read `/proc/loadavg` once before the matrix and once after, which brackets a
  spike without showing it and cannot say which round was the noisy one; each
  round now carries its own reading into `raw.jsonl` and into `summary.json`,
  reduced to min/median/max across the run. The environment block reported
  `len(sched_getaffinity(0))` as `cpus`, so a harness pinned away from the
  subject's cores printed "12 cpus" beside a CPU model that has 16; `cpus` is now
  the machine and the mask is recorded separately as `harness_cpu_affinity`,
  which matters when the subject is pinned to alternating physical cores and the
  harness must be kept off them.
