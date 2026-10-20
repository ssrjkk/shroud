/**
 * Atomic, serialised file writes.
 *
 * The bot persists two pieces of state (the alert cursor and the per-chat watchlist)
 * from more than one place: the poll loop writes the cursor, and the dispatcher runs
 * chat handlers concurrently. Two writers that race on the same destination are worse
 * than either of them alone:
 *
 *   - a *shared* temp path makes both writes land in one file, and the rename then
 *     publishes a mixture of the two snapshots - not valid JSON. The reader treats that
 *     as corruption, moves the file aside and starts empty, so every chat loses its
 *     state over one interleaved save;
 *   - distinct temp paths still race on the rename, and on Windows the loser gets
 *     EPERM: its update is silently dropped.
 *
 * So: a unique temp file per write, and one write per destination at a time. The
 * chain keeps the newest snapshot - a caller that saves twice in a row wants the
 * second state on disk, not the first.
 */
import { writeFile, rename, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

/** destination -> the tail of the write chain */
const chains = new Map();

/** A per-process counter, so two writes in the same tick never share a temp name. */
let seq = 0;

/**
 * Write `data` to `file` atomically: temp file + rename, and never concurrently with
 * another write to the same file.
 */
export function writeAtomic(file, data) {
  const previous = chains.get(file) ?? Promise.resolve();
  const run = previous.then(
    () => writeNow(file, data),
    () => writeNow(file, data)
  );
  // The chain must not break on a failed write: the next one still has to run.
  chains.set(file, run.catch(() => {}));
  return run;
}

async function writeNow(file, data) {
  await mkdir(dirname(file), { recursive: true });
  seq = (seq + 1) % Number.MAX_SAFE_INTEGER;
  const tmp = `${file}.tmp-${process.pid}-${seq}`;
  await writeFile(tmp, data);
  await rename(tmp, file);
}
