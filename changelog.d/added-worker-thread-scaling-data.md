- **The controlled `worker_threads` scaling curve and the SMT control that
  `tests/perf/RESULTS.md` owed are now measured, on one tree and one quiet
  host.** `results/worker-threads-{1,2,4}.json` replace the cross-tree ×2.32
  ratio §1 warned not to read as a scaling factor: four workers are worth
  **×2.0–2.4** over one, never ×4, on every posture and every benign workload,
  with round-to-round spread at or below 2.4%. `results/smt-control-*.json`
  separate why: moving the same four workers from two physical cores
  (CPUs 0–3, SMT siblings) to four physical cores (0,2,4,6) buys **+23% on
  `passthrough` and +33–42% on `full`** and *lowers* CPU µs/req by ~20% at
  unchanged core occupancy, so roughly a fifth of the shortfall is SMT and the
  rest is not. RESULTS.md is not yet rewritten around these files.
