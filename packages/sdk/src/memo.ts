/**
 * A promise that is created once and reused — but a *failed* attempt is not cached.
 *
 * The pattern shows up wherever a client has to build an expensive resource (a
 * network connection, a key fetch) and then reuse it. Memoising the promise
 * blindly is the bug: a rejection that is cached is a permanent failure, so a
 * momentary outage — the relayer restarting, the RPC hiccupping — leaves the
 * client broken until the process is restarted. The failure is dropped instead,
 * and the next call tries again.
 */
export function onceAsync<T>(factory: () => Promise<T>): () => Promise<T> {
  let pending: Promise<T> | undefined;
  return () => {
    if (!pending) {
      pending = factory().catch((err: unknown) => {
        // Clear before rethrowing: the next call must build a fresh attempt.
        pending = undefined;
        throw err;
      });
    }
    return pending;
  };
}
