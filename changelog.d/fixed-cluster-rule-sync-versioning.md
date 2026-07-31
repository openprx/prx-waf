- **A restarted Main can correct its workers again, and a synced config no
  longer disarms enforcement.** Three defects in rule synchronisation, each of
  which reported itself healthy while doing the wrong thing.

  The registry version is a counter that restarts at 1, so a Main that came
  back up reissued a version its workers already held. `delta_since` then
  answered "nothing has changed since 1" — truthfully, for the wrong
  incarnation — and both sides logged a successful sync while the worker went
  on serving the previous Main's state. Since restarting the Main was the only
  way to change Lane 2 configuration, that made the new channel unusable. A
  worker joining a Main now forgets the version it holds; the rules stay live
  and the next pull is a full snapshot. A worker that had somehow advanced past
  the Main is likewise sent a snapshot instead of an empty delta.

  Applying a synced semantic config rebuilt the detection subsystem, and the
  pull loop runs every five seconds. That subsystem anchors the restart shadow
  latch and the detector circuit breaker, both measured in minutes, so
  rebuilding on every tick meant the latch never lifted: a cluster configured
  to enforce would enforce nothing while logging that it did. The config is now
  compared by payload identity, and a genuine change carries `created_at` and
  the breaker's trip state across — resetting the breaker would have turned any
  config write into a way around the one control that stops a misfiring
  detector.
