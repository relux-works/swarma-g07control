# G07 keeper control source candidate

This isolated Linux Go module implements control admission only. It has no
command that starts Host, no adapter integration, no store initializer and no
runtime invocation or installation path. It is new source against the empty Git
tree, not a patch to Host. Completing its tests grants no live authority.

The frozen Host context is `a77a2714c3262a84d0b82a3a856311759846ad71`
(tree `7ea7614cbc66094134c908601bffef0239a6c617`). The distinct frozen
adapter manifest SHA256 is
`bd3131ef10418eb7656734fec84f357dc14370c0742a125c6e0bfea5a094e0a3`.
Neither was built, changed or invoked here.

## Small API and trust inputs

`Open(policyFD)` takes an explicitly supplied, regular, single-link, owner-only
0600 custodian policy descriptor. `Control.Consume(ctx, eventID, tokenFD)` takes
only the exact event ID and an explicit token descriptor. `Close()` releases
descriptors. No method discovers credentials, initializes a store, resets a slot,
changes expected bindings or runs a command. The policy is a **trusted custodian
input**, outside the grant caller's authority. Ownership checks alone do not
establish that a policy or prerequisite is actually admitted.

The custodian must separately admit and provision the policy. It pins a single
HTTPS homeserver origin, explicit public TLS root certificates, original room,
issuer/custodian/executor, task, stable execution slot, every `Binding` digest,
historic spent operation IDs, R/E/K locator digests and an existing store's
device/inode. There are no authority defaults. The private R/E/K locators are
used only for lexical separation; the tool never opens or creates those paths.
The token is read only from the supplied descriptor, is bounded, is never
reported, and must be complete (including EOF). The caller owns that descriptor.

The selected homeserver's sender attribution, authenticated by HTTPS using the
custodian's explicit roots, is the signature-equivalent trust basis. There is no
Matrix end-to-end signature verification and no protection against a malicious
selected homeserver. Proxy environment variables, root-file environment
variables, redirects, alternate origins and event search are not used.

## Exact event protocol

The tool fetches only
`GET /_matrix/client/v3/rooms/{escaped-room}/event/{escaped-event}` at the pinned
origin with the explicit bearer token. HTTP is bounded by a 10-second request
context, 8 KiB response headers and a 32 KiB fully read and successfully closed
response. A successful response has status 200, one JSON content type and no
content encoding. JSON duplicate keys at any object depth, unknown members,
redaction and relations are refused.

The event has exactly `event_id`, `room_id`, `sender`, `type`,
`origin_server_ts`, `content` and optionally `unsigned`. Its type is
`works.relux.keeper.g07.v1`. `content` has exactly one member, `body`, a string
containing the canonical `Grant` encoding. The only allowed unsigned metadata
is a nonnegative integral `age`; it confers no authority. The event timestamp
must lie in the grant window and cannot be in the future.

Canonical means precisely the UTF-8 bytes emitted by `encoding/json.Marshal`
on the published structs in `types.go`, using the pinned Go implementation.
All fields are present in declaration order, with no extra whitespace. This is
a deliberately closed protocol, not a claim to implement RFC 8785. The string
body preserves those bytes when a homeserver reserializes or reorders the outer
JSON. The outer object may use ordinary JSON whitespace and member ordering.
The stable event digest normalizes its authenticated core and excludes changing
unsigned age; the request digest hashes the exact canonical body bytes.

The body binds one operation, issuer/custodian/executor/recipient, Host task,
stable slot, one entry, inspect-then-invoke, the full digest bundle, integral
Unix-second issue/latest times and the unchanged 1260-second runtime budget.
The allowed window is `0 < latest-issued <= 600` and `issued <= now < latest`.
The actual production clock is `time.Now`. The clock is checked after durable
consumption, before receipt and again after releasing serialization. Equality at
expiry refuses and retains the claim. The actual custodian must still check
`issued <= T0 < latest` immediately before the frozen first runtime effect.

## Separate source custody

An already existing `custody.json` inside the anchored store must be an owned
0600 single-link regular file whose entire canonical bytes match the policy's
SHA256. It must carry the exact admitted disposition, all expected bindings,
and pins for source attestation, independent source/control reviews, exclusive
execution acceptance and path inspection. Unknown, missing, changed, unadmitted
or incomplete records refuse before any claim.

This validates a **custodian-pinned disposition**, not the truth of arbitrary
JSON. Installing that pin requires actual authenticated evidence and independent
admission outside this component. The route is explicitly
`ADMITTED_META_TO_KEEPER_SOURCE_CUSTODY_ATTESTATION`; the supplied reference
attests the meta-keeper's firsthand verification of the addressed source event. It is not
rewritten as the preparer's own read. The supplied
references still show G07 unissued and exclusive execution custody unaccepted.
The fixtures' positive dispositions are synthetic, never live qualification.

## Durable slot claim

The store must already exist outside R/E/K, with a pinned device/inode and
nonsymlink ancestry. Every ancestor is root- or keeper-owned without group or
other write permissions or special bits; the store itself is keeper-owned 0700.
Root and all ancestor descriptors stay open. Their identities, modes and parent
links are checked repeatedly; the consume path never silently initializes them.
Its provisioner must have durably established the preexisting store and custody
record before policy admission. Unsupported directory locking/fsync refuses.

A Linux `flock` on the anchored directory serializes processes. The file
`SHA256(slot).claim` is opened relative to that directory with
`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600. It records the exact verified event digest,
event ID, request digest, operation, slot, custody pin and window. The complete
write, file fsync, successful file close and directory fsync precede a new
receipt. Anchors, custody, the stored bytes and clock are checked before return.
No rename or additional lock-file publication is required: the no-replace
creation itself holds the slot, including when interrupted before persistence.

Only one caller can receive `NEWLY_CONSUMED`. Matching present records yield
`INSPECTION_ONLY`, which asserts presence, not that a prior caller reached fsync
or received its result. Different inputs yield `SLOT_CONFLICT`. Partial, corrupt,
inaccessible or otherwise uncertain existing claims yield `HELD_UNCERTAIN`.
Inspection never repairs, replays, resends, deletes or issues authority. Every
post-create failure leaves the claim. A crash after commit but before delivery
intentionally loses availability. There is no reset, recovery execution,
pruning, rollback or exactly-once execution guarantee.

The receipt includes outcome, event, request, slot and record digests, operation
and window. A JSON receipt can be fabricated and is not independently
authenticating evidence. Acceptance depends on the actual custodian invoking
the reviewed qualified code against its actual owned store and retaining the
receipt. Shared UID users and privileged storage administrators remain trusted;
this is not malicious-same-UID isolation or a tamper-proof ledger.

## Control boundary and live adoption blockers

The operation performs only separately admitted keeper control effects. It must
complete before runtime entry, outside R/E/K. It neither starts T0 nor changes
the original 1260-second whole-runtime deadline. If a proposed installation
requires any runtime effect before the frozen E anchor, it is an OWN-ANCHOR
incompatibility and must stop. No exception or automatic Host call exists.
An overlapping configured control store refuses with
`OWN_ANCHOR_INCOMPATIBILITY` before opening the store or authenticating a grant.

Before any live use, all of the following remain required:

1. Independent review of exact final source and meta-keeper/source/check/signature
   acceptance through the existing route; this preparation is not self-review
   ACCEPT, source admission or signed landing.
2. Explicit later source-approved build qualification and installation authority
   for this exact new tool, with sealed source/compiler/build/artifact pins.
3. Actual keeper source-agreement authentication and exclusive execution custody,
   independent reviews, qualified frozen artifact, accepted boundary, fresh
   R/E/K absence inspection and retained prerequisite evidence. The reference
   custody route remains attributed to the meta-keeper.
4. Explicit keeper authority to provision a dedicated, durably protected,
   device/inode-pinned live store outside R/E/K and a reviewed policy/custody
   record. No live store was created during preparation.
5. Actual approved Matrix issuer integration using this exact closed wire
   protocol, original room, selected HTTPS origin, verified public TLS roots,
   keeper-controlled policy and explicit private token descriptor. Synthetic
   TLS does not prove actual Matrix trust, server behavior or private-token
   custody. There is no permissive compatibility fallback.
6. A fresh exact finite grant for the frozen one-entry stable slot, followed by
   actual keeper consumption, retained new receipt, final read-only inspection,
   clock check at T0 and at most one invocation under the existing custody.

The frozen adapter does not enforce this store. Arbitrary direct adapter calls
remain technically possible; actual keeper custody must prevent bypass. This
module does not introduce another executor, controller, daemon or runtime
wrapper. Later independent execution needs a separately authorized different
slot and new source/custody disposition, never a retry identifier invented here.

## Tests and limits

Use the exported isolated harness. All Go/compiler/helper execution requires
`bwrap --clearenv --unshare-all`, a read-only source and toolchain, private 0700
HOME/TMP/cache/fixtures, no host home/credentials/sockets or live networking,
`GOMAXPROCS=2`, `-p=2`, CGO with actual libc and serial suites. Loopback TLS exists
only in that private network namespace. The minimum module directive is Go
1.26.0; the supplied compiler is Go 1.26.10 with binary SHA256
`9c2a37ae5b21ba1d5a004bb9ab4d0c64de6fc5778e9d30487adccea62678b8b5`.
The product depends only on the standard library and Linux filesystem syscalls.

Tests cover authenticated synthetic issuance, closed bindings and bad evidence,
TLS failures, unavailable/partial/oversize HTTP, full-read/close errors, time
edges and post-durability expiry, admitted/refused pinned prerequisites, protected
ancestry, damaged records, short writes/fsync failures, real concurrent processes
and deliberate exits at every durable boundary. A syscall witness uses existing
OS `strace` to observe file fsync before directory fsync before receipt output.
Fixtures alone do not prove real Matrix trust or storage power-loss behavior.
Process exits are interruption evidence, not power-cut, media or filesystem
durability qualification. Fsync assumes a correct OS/filesystem/storage stack.
Causal plants and byte restoration are recorded in the preparation export.
