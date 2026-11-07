# Control API and custody

The Linux package exposes these operations in [store_linux.go](../../../../store_linux.go):

```go
func Open(policyFD *os.File) (*Control, error)
func (c *Control) Consume(ctx context.Context, eventID string, tokenFD *os.File) (Receipt, error)
func (c *Control) Close() error
```

`Open` seeks the supplied policy descriptor to the start, reads it and anchors an
already provisioned store; it creates no files or directories. Keep the returned
`Control` until done, do not copy it, and call `Close` to release its directory
descriptors and idle HTTP connections. The caller retains ownership of the policy
and token descriptors. `Consume` reads only the explicit token descriptor, never
discovers credentials, and requires complete EOF within 4096 bytes, nonempty
printable ASCII without whitespace. Do not log token bytes or reconstruct the
underlying HTTP error; exported `*Refusal` exposes only its `Code`.

## Inputs the custodian must already have admitted

Use [Policy, Binding and Custody](../../../../types.go) as the exact closed shapes;
do not fill missing bindings with defaults. Policy and custody bytes must be the
exact `encoding/json.Marshal` output for their structs under the pinned Go
implementation, including declaration order and all fields. This is not RFC 8785.

- Policy is an owned, regular, single-link 0600 file, at most 16 KiB, with schema
  `g07-policy/1`. It pins one HTTPS origin, explicit TLS roots (at most 8192 bytes),
  original room, issuer/custodian/executor (all equal), task, stable slot, every
  `Binding` digest, 1–128 distinct historic spent operation IDs, three disjoint
  absolute R/E/K paths and their locator digests, custody SHA256 and store
  device/inode. R/E/K paths are checked lexically and never opened.
- The store already exists outside R/E/K, keeper-owned 0700, with nonsymlink
  ancestry. Ancestors must be root- or keeper-owned without group/other write or
  special bits. Directory locking and fsync must work. Provisioning and its prior
  durability are external responsibilities; `Open` does not supply them.
- Existing `custody.json` is an owned, regular, single-link 0600 file, at most
  8 KiB; its complete canonical bytes match the policy pin. Schema is
  `g07-custody/1`, state `ADMITTED_SOURCE_REVIEW_QUALIFICATION_BOUNDARY`, route
  `ADMITTED_META_TO_KEEPER_SOURCE_CUSTODY_ATTESTATION`. Custodian, executor, task,
  slot and bindings match policy. Source attestation, source review, control
  review, exclusive execution acceptance and path inspection digests require
  actual external verification and admission. The route preserves the
  meta-keeper's firsthand source attestation; it is not the preparer's own read.

Ownership and matching JSON cannot prove those prerequisites. Preserve the
[README's live-use blockers](../../../../README.md#control-boundary-and-live-adoption-blockers):
exact-source review/admission, qualified build and installation authority,
exclusive custody, accepted frozen boundary, fresh absence inspection, separately
authorized live store and issuer integration. This skill supplies none of them.

## Event and clock boundary

[auth.go](../../../../auth.go) fetches only the exact event at the pinned origin
and original room. Trust rests on HTTPS-authenticated selected-homeserver sender
attribution, not Matrix end-to-end signatures. There is no proxy, ambient TLS-root,
redirect, alternate-origin or search fallback. The request has a 10-second context,
8 KiB header limit and 32 KiB fully read, successfully closed response limit.

The event type is `works.relux.keeper.g07.v1`; `content` contains only the string
`body`, holding canonical `Grant` bytes. Unknown members, duplicates, redaction
and relations refuse. Optional `unsigned` permits only nonnegative integral `age`
and conveys no authority. The grant binds one entry, inspect-then-invoke, the full
policy digest bundle, recipient equal to executor, and `outer_seconds = 1260`.
Times are integral Unix seconds, with `0 < latest-issued <= 600` and
`issued <= now < latest`; the positive millisecond event timestamp must fall in
that window and not be in the future. Production uses `time.Now`.

## Results and refusals

Interpret the public [Receipt and Refusal](../../../../types.go) without granting
additional authority:

| Result | Meaning and handling |
| --- | --- |
| `NEWLY_CONSUMED` | This call created the exclusive slot claim, completed file write/fsync/close and directory fsync, then rechecked anchors, custody, bytes and clock. The clock is checked again after unlocking. Retain the receipt for the actual custodian's separately authorized boundary checks. |
| `INSPECTION_ONLY` | Matching claim is present; this proves neither a prior durable commit nor delivery of a new receipt. No execution or reissue follows from inspection. |
| `SLOT_CONFLICT` | Existing valid claim differs from this request. Keep the slot held. |
| `HELD_UNCERTAIN` | Existing claim cannot be trusted, unlock failed, or a post-create durability/check failure occurred. Keep the claim; no repair or recovery execution. |

`Receipt` contains outcome, event ID, request/slot/record SHA256, operation and
issue/latest times; it has no separate event-digest member. Receipt JSON can be
fabricated and is not independent authentication evidence.

`Open` can return `POLICY_REFUSED`, `OWN_ANCHOR_INCOMPATIBILITY`, `STORE_REFUSED`
or `PREREQUISITE_REFUSED`. `Consume` also exposes `AUTH_REFUSED`, `LOCK_REFUSED`,
`CLOCK_REFUSED`, `SLOT_CONFLICT` and `HELD_UNCERTAIN`. Event/grant verification
errors inside authentication become public `AUTH_REFUSED`; do not promise callers
internal classifications such as `EVENT_TIME` or `GRANT_BINDING`.

The anchored `SHA256(slot).claim` uses no-replace creation. Every post-create
failure retains it, including expiry after durable consumption. A crash before
receipt delivery may permanently lose availability. No reset, pruning, rollback,
exactly-once execution guarantee or direct-adapter bypass prevention exists.

## Offline synthetic checks

The [existing tests](../../../../control_test.go) exercise the API with synthetic
policy, custody, token and loopback TLS fixtures. Before executing Go or helpers,
use `bwrap --clearenv --unshare-all` with read-only source/toolchain, private
absolute 0700 HOME/TMP/cache/fixtures (including the tests' hardcoded
`/private/tmp`), no host home, credentials, keys, sockets,
foreign caches or live network. Set `GOMAXPROCS=2`, `CGO_ENABLED=1`, actual libc,
`GOTOOLCHAIN=local`, `GOPROXY=off`, `GOSUMDB=off` and private Go caches. Inside that
already isolated harness at the module root, run serially:

```sh
go test -p=2 -parallel=1 -count=1 -timeout=120s ./...
```

The syscall-witness test requires `/usr/bin/strace` in the read-only tools.
[go.mod](../../../../go.mod) declares Go 1.26.0 and no external dependencies;
do not fetch or upgrade dependencies. Record the actual compiler and exit status,
including any mismatch with the README's reference compiler. Process exit tests
prove interruption behavior, not power-loss durability or actual Matrix trust.
Do not turn fixtures into store initialization, grant issuance, real-event fetch
or activation instructions.
