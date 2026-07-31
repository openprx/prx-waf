- **A fuzz crash reproducer now survives a job timeout.** The workflow step that
  uploads `fuzz/artifacts/` ran `if: failure()`, which is false while a job is
  being cancelled — so a soak that exceeded `timeout-minutes: 60`, or one killed
  by `cancel-in-progress`, threw away the crashing input. Those are the runs most
  likely to be holding one: a target that crashes late in a 1800-second soak, or
  one that wrote a `crash-*` file and then hung on the next input. The step now
  runs `always()`, and the retention rises from 30 days to 90 — a scheduled run
  reports to no pull request, and the 2026-07-27 soak crash sat unread for over a
  day before anyone looked.
