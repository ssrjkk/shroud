# Incident response

Something is wrong. Work top-down; each step names the on-chain lever and its cost.

## 1. Triage (minutes)

- **Funds moving wrong:** pause the protocol (`setPaused(true)`, owner). Pause
  freezes progress, never exits: bonds release and claims still work, so pausing
  cannot strand user money by itself.
- **Bad task in flight:** the buyer/update manager calls `abort(taskId, reason)`.
  Refunds net of verified work; reverts once every epoch ran (then `settle` is
  the only path — by design, not by accident).
- **Stuck task past deadline:** owner `emergencyUnwind(taskId)` after
  `epochDeadline + disputeWindow`. Same refund path as `abort`.
- **Wrong epoch winning:** file a dispute from a registered node holding its own
  verified commit (`commitDispute` + `reportDisputeWithSalt`; bare `reportDispute`
  only if the mempool is safe). Quorum of 3 rejects the epoch.

## 2. Key compromise

- **Operator key:** rotate the key, re-register the node (bond per task), revoke
  the old key's approvals (`approve(vault, 0)` on the escrow token).
- **FHE network key suspected:** rotate via `NetworkParams` proposal → timelock →
  anyone executes. Nodes and SDKs compare `fhePublicKeyHash` pins and refuse on
  mismatch — a rotation without updating pins halts uploads loudly, which is the
  safe failure.
- **Committee shares:** threshold assumption broken — see T-01. There is no
  in-protocol recovery; rotate the set out of band and disclose per `SECURITY.md`.

## 3. Data and availability

- **DA withholding/corruption:** detected, never silent — digest mismatch, size cap,
  timeout. Re-upload from the contributor's local copy and re-pin; the chain pin
  (`ctDigest`) does not change, so recovery is a re-PUT, not a new task.
- **ShardStore disk loss:** objects exist only where persisted (`DATA_DIR`) plus
  any replica the operator runs. No replication in-repo: run two instances behind
  distinct disks/hosts for anything beyond devnet.

## 4. Disclosure

- Do not exploit or demo the issue publicly before a fix is released.
- Report privately via GitHub Security Advisories (`SECURITY.md`); acknowledge
  within 3 business days; coordinate the fix, then disclose with the release notes.
- Fraud/disputes on live tasks are on-chain and public by nature — describe them
  with task/epoch/digest references, never with key material.
