- **`tests/perf/scaling.sh` drives the two multi-invocation performance
  experiments that only mean anything as a set.** `scaling.sh curve` sweeps
  `[proxy] worker_threads` over 1/2/4 against one fixed core set, and
  `scaling.sh smt` runs the same four workers on two physical cores and then on
  four. Both hold two things a reader retyping the commands would lose: the
  harness process is itself pinned off the subject's cores, because run.sh's
  shell, its awk/jq children and the RSS sampler otherwise inherit an affinity
  that can overlap them, and the arms are named so that "4 workers on 4 CPUs"
  is never mistaken for "4 workers on 4 cores" on a host whose CPUs 0-3 are two
  SMT pairs. It writes summaries to a scratch directory and never into
  `results/`, so a published figure stays something a human chose to publish.
