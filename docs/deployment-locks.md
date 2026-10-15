# Deployment concurrency and fencing contract

All Chronicles staging and production operations must be serialized by a shared lock owner and monotonic fencing token. A time-based lease alone is not safe: a paused old worker may resume after its lease expires. The executor and any persistent state writer must reject stale fencing tokens atomically.

This PR only validates lease and fencing metadata. It does not acquire locks, enforce atomic fencing in storage, or coordinate real GitHub Actions jobs. Until a reliable atomic store is connected, deployment remains disabled. Chess Studio is out of scope.
