# Trust assumptions

Every party this protocol must trust, what breaks if they turn, and where it is
documented. If any row is unacceptable for your use case, do not escrow value.

| # | Assumption | If broken | Status / pointer |
|---|---|---|---|
| T-01 | The decryption committee does not collude at or above threshold | Rows and early weights decrypt; privacy ends | Residual by design (F-10); ceremony/rotation are future work |
| T-02 | Fewer than 3 mutually distrusting re-executors per epoch are malicious | Honest winner loses reward + bond; epoch rejected | Priced, not prevented (flat quorum); `docs/04` §2a |
| T-03 | The contract owner key is honest and live | Pause/treasury/abort/slash abused; no multisig or timelock on these paths | Single-key today; `CipherTask` owner powers listed in `docs/01` |
| T-04 | The TFHE network key pinned by `NetworkParams` is correct | Ciphertexts under a substituted key decrypt elsewhere or nowhere | SDK pin fail-closed when configured; relayer binding required; node pin checked at startup by default |
| T-05 | The DA serves the bytes its CIDs name, eventually | Liveness stalls (withholds fail loudly via digest/size/timeout checks, never silently) | Hostile-DA handling tested (`da.ts`, ShardStore guard suite) |
| T-06 | `chainId` and contract addresses in client config are right | Cross-chain replay / wrong-task encryption | SDK hard-errors on configured mismatch; unconfigured values are skipped, not verified |
| T-07 | Contributors' plaintext never touches the reference path in production | Dev/noop shards are open bytes by design | Enforced by backend selection (`prover` feature + `server_key_path`); lab is demo math |
| T-08 | Reviewers/auditors beyond the author exist | Bugs survive (bus factor 1) | No external audit; this file + `docs/04` + `docs/05` are the whole record |
| T-09 | The toolchain (solc, rustc, npm, Docker, GitHub Actions) is intact | Supply-chain compromise | Lockfiles committed; CI pinned (`ubuntu-24.04`, `--locked`); no provenance/SBOM yet |
| T-10 | One BLS identity per node (no key reuse across nodes) | A single operator poses as a quorum | Enforced on-chain (key uniqueness + proof-of-possession) |
| T-11 | The relayer serves the correct key and does not censor inputs | Wrong-key ciphertexts; censored contributions miss the window | Key bytes hashed into `publicKeyHash` and pinned on-chain; `contractAddress` binding required (`assertInputBinding`); ordering/censorship by the relayer itself is not mitigated |

| T-12 | The registered node set of a task is what the dispute committee is drawn from | A Sybil ring that registers enough identities buys its way into the committee, and a dispute is decided by the ring | Every registration posts a bond and the draw is weighted by it, so the ring's weight is priced (F-04); the sequencer cannot pick the committee at all (F-59) |

Removing a row requires code + tests + docs in the same change, never docs alone.
