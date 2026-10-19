# Important

The drive 'redirect.bpf.sys' must be signed manually currently, so if we have to make any code changes within this folder, we need manual sign the 'redirect.bpf.sys' from the build output folder.

## Get the new 'redirect.bpf.sys'

1. To get the release version of new redirect.bpf.sys from your local dev box, run ```build release clean```. 
2. copy the './out/release/redirect.bpf.sys' to sign it manually.

## Manual Sign the new 'redirect.bpf.sys'

<< To be defined later >>

## Connection-bound audit correlation

The Windows and Linux audit maps use `(protocol, source port, source address
family, source IP address)` keys, with 16 bytes reserved for the address.
IPv4 uses the first address word and zeros the remaining words; IPv4-mapped
IPv6 peers normalize to the same IPv4 key. Native IPv6 uses all four words
and a distinct family. Both
lookup and removal require the complete key, so a direct connection from
another local address cannot read or consume a redirected caller's identity.
Missing entries follow the existing unauthenticated-connection rejection path
(HTTP 421).

Linux captures the selected source address at `tcp_connect`, after automatic
source selection, correlating it with the cgroup connect hook by socket cookie.
The Windows cookie-correlation prototype publishes the
selected source tuple at `CONNECT_AUTHORIZATION` and retains socket-bound
redirect context for every redirected connection.

Deploy the updated agent and eBPF program together (and sign the Windows
driver as described above). The audit key ABI is now 28 bytes.
For compatibility with released Windows eBPF programs, the agent also supports
their original 8-byte `(protocol, source port)` keys for lookup and removal.
This legacy layout cannot distinguish same-port peers on different source
addresses and retains the cross-address identity-stealing vulnerability.
The source-bound mitigation requires deploying the updated eBPF program;
updating the agent alone does not fix connections correlated by legacy keys.
Unknown key sizes are also rejected.
Windows socket-bound redirect contexts remain supported.
The expanded source key does not enable native IPv6 destination redirection;
that still requires IPv6 policy and destination handling.

## Linux socket-cookie correlation

The cgroup connect hooks capture the caller's PID, UID, executable identity,
and original destination, and stage them in `local_map` keyed by
`bpf_get_socket_cookie(ctx)`. This helper initializes the socket's cookie.
The `tcp_connect` kprobe reads that same cookie from
`sock.__sk_common.skc_cookie.counter` using CO-RE; it does not call the
context-taking cookie helper on a kernel `struct sock *`.

The probe publishes the selected source tuple in `audit_map` and removes the
pending cookie entry. PID/TGID is used only when capturing identity, not for
the handoff or a second skip-process decision. Different sockets from the
same thread therefore cannot consume each other's pending identity, and a
changed execution context does not change the captured caller identity.
The Rust audit map interface and full-source-tuple key remain unchanged.

An untracked socket (including one with no initialized cookie) publishes
nothing. Cookie-generation, CO-RE read, and map-operation failures are logged;
there is no PID/TGID fallback. A failed capture still redirects, so the
listener rejects the connection without an audit identity rather than
bypassing the proxy. Connections failing before `tcp_connect` can leave
pending entries; these remain bounded by the existing 200-entry LRU map.

### Linux native regression tests

On an x86-64 Linux development host with Clang and libbpf headers installed,
run from the repository root:

```sh
clang -Werror -Wno-unknown-attributes -D__TARGET_ARCH_x86 -O2 linux-ebpf/tests/audit_cookie_tests.c -o /tmp/gpa-linux-audit-cookie-tests &&
/tmp/gpa-linux-audit-cookie-tests &&
rm -f /tmp/gpa-linux-audit-cookie-tests
```

These tests include the production C source with mocked helpers. They cover
64-bit cookie isolation, two pending sockets on one thread, changed execution
context, original identity preservation, one-time consumption, missing
cookies, helper failures, mapped IPv6, and skip/monitor-only behavior.
They do not replace CO-RE relocation, verifier, or live connection tests on
the supported Linux kernels.

## Windows two-stage cookie prototype

The prototype is built against the eBPF-for-Windows 1.6.0 SDK.
CONNECT_AUTHORIZATION also exists in 1.5.0; successful loading and attachment
alone do not establish runtime compatibility or callback execution.
Record both the EbpfApi.dll and installed NetEbpfExt driver versions when
comparing behavior with upstream source. It uses two hook pairs:

1. `authorize_connect4` / `authorize_connect6` capture the caller identity and
   original destination, and stage the audit entry and expected redirect
   target in `local_map` keyed by `bpf_get_socket_cookie(ctx)`.
   Only connections selected for redirection are staged. Nonzero-cookie
   connections use the map path without socket-bound redirect context.
   The existing redirect-context branch is retained only for zero cookies.
2. `audit_authorization4` / `audit_authorization6`, in
   `cgroup/connect_authorization4` / `cgroup/connect_authorization6`, atomically
   inspect that pending entry after route selection. They require the WFP
   process/logon IDs, protocol, and redirected destination to match, and
   a concrete source address and port. Only then do they atomically take
   the entry and publish the full source-tuple audit key. These hooks do
   not modify the socket context or make authorization policy decisions.

WFP can authorize an original destination as well as a redirected destination.
An earlier callback with an original or unresolved tuple must not consume
the pending identity needed by the redirected callback. Invalid tuples and
identity mismatches leave the pending entry intact. This does not guarantee
another callback will arrive: live testing must establish that authorization
exposes the final peer tuple for the supported OS and eBPF runtime.
`bpf_sock_addr_set_redirect_context` is supported only in the redirect hook;
calling it from authorization cannot repair an unresolved tuple.

The local map is an LRU map bounded to 1,000 entries. Entries for connections
that never reach matching authorization remain bounded by LRU eviction.
Atomic consumption prevents later
authorization callbacks from recreating a listener-consumed audit entry.
Neither staging nor publication overwrites an existing matching map key.
Nonzero-cookie publication failures are logged and leave no new audit entry;
they are not hidden by redirect-context fallback.

The agent attaches both authorization hooks before the redirect hooks when
the object contains `local_map`. Missing or failing authorization
hooks then fail attachment rather than silently disabling the new path.
Older objects without this map retain their existing attachment behavior.
Deploy the updated agent and rebuilt, signed driver together. The internal
Windows `local_map` value is now 40 bytes; the listener audit key/value ABI
is unchanged.

### Comparing the hook tuples with the accepted peer

At startup, the agent queries each loaded program with
`bpf_program__get_expected_attach_type` before attaching it. The authorization
programs must report `BPF_CGROUP_INET4_CONNECT_AUTHORIZATION (12)` and
`BPF_CGROUP_INET6_CONNECT_AUTHORIZATION (13)`. Redirect programs must report
`BPF_CGROUP_INET4_CONNECT (3)` and `BPF_CGROUP_INET6_CONNECT (4)`.
A mismatch fails attachment and reports the actual and expected types; rebuild
and sign the native driver after refreshing the SDK program information.
The `Verified ... attach type` log checks the loaded metadata, not just the
program name. A successful attach still does not prove callback execution.

If staging appears but neither `Entered audit_authorization4.` nor
`Entered audit_authorization6.` appears:

1. Confirm the startup type-verification and attachment logs above.
2. Capture the NetEbpfExt provider as well as eBPF printk and WFP events for
   the same transport endpoint handle (the socket cookie). WFP's
   `RedirectedAuthConnect` alone is not evidence of eBPF program invocation.
3. Check for NetEbpfExt `auth_connect_classify` and invocation errors.
   In the matching runtime source, trace the AUTH_CONNECT filter context,
   compartment, action-write rights, cached redirect verdict, and selected
   authorization clients. No classification event points to filter dispatch
   or tracing configuration; classification without program entry points to
   provider gating/client selection or invocation failure.

Use an elevated `netsh wfp show state` on the test VM to inspect the installed
ALE_AUTH_CONNECT_V4/V6 filters and their callouts, sublayers, weights, and
compartment conditions. Redirect hooks also install AUTH_CONNECT filters.
Filter arbitration is a possibility to verify, not an established root cause.
In the inspected 1.5.0 and 1.6.0 providers, both hook types install AUTH_CONNECT filters
in the default sublayer, invocation selects clients from the current filter
context, and even a soft proceed verdict becomes `FWP_ACTION_PERMIT`.
Check whether the redirect hook's AUTH_CONNECT filter runs first with only
redirect clients, selects no authorization client, and permits before the
separate authorization filter runs. Confirm this with filter IDs and client
attach types on the VM; do not rely on attach order as a fix. If confirmed,
the correction belongs in the provider's filter/client dispatch so the
authorization programs run before the final permit decision.
Do not change cookie matching or add a fallback to mask missing hook execution.

Enable eBPF-for-Windows tracing as described in the upstream
[tracing guide](https://github.com/microsoft/ebpf-for-windows/blob/v1.6.0/docs/GettingStarted.md#using-tracing)
and enable agent Trace logging.

Capture the program's `bpf_printk` events, not just runtime errors. From an
elevated PowerShell with WDK tracing tools available (adjust the installation
path if needed):

```powershell
tracelog -start GpaCookieTrace -guid "$env:ProgramFiles\ebpf-for-windows\ebpf-printk.guid" -rt
tracefmt -rt GpaCookieTrace -displayonly -jsonMeta 0
# Reproduce the request, then stop tracefmt with Ctrl+C.
tracelog -stop GpaCookieTrace
```

The upstream printk filter selects provider
`394f321c-5cf4-404c-aa34-4df1428a7f9c`, keyword `0x200`, level `4`.
These events contain a `Message` field. A runtime `ErrorMessage` chain ending
in `_map_lookup_element` only reports the failed lookup; it does not show
the hook cookie or explain the failed handoff.

- `Staged audit cookie=... pid=... logon=...` confirms successful staging.
- `Audit authorization cookie=...` shows the cookie observed by each
  authorization invocation, including those without a pending entry.
- `Entered audit_authorization4` / `Entered audit_authorization6` is emitted
  before the cookie helper, distinguishing program entry from helper failure.
- `Audit stage=0` is capture before redirection; `Audit stage=1` is a
  matching-cookie authorization candidate, not necessarily publication.
  Follow the cookie across source and destination lines.
  Source addresses are four hexadecimal network-address words;
  `7f000001` in `ip0`, followed by zero words, means `127.0.0.1`.
  Ports are printed in host byte order.
- `Published audit cookie=... protocol=... port=...` confirms map publication.
- Agent `Found audit entry for TCP peer '...'` messages show the accepted peer,
  captured PID, and original destination. Compare that peer with the
  authorization source tuple.
- `Found audit entry from socket stream successfully for TCP peer '...'`
  means the socket-bound fallback succeeded; a preceding map miss is not
  itself a failed connection.
- `Deferred audit` means the callback did not have the required tuple and
  left the pending identity intact. Check whether a later callback for the
  same cookie publishes the actual accepted peer.
- `No staged audit` can be normal for unrelated connections or consumed
  entries. If it follows successful staging for a failing request, inspect
  earlier callbacks, LRU pressure, and the cookie values.
- A map miss followed by a zero-byte socket context is expected when this
  nonzero-cookie prototype fails to publish: only primary map success counts
  as successful cookie-path validation.

Before rollout, verify IPv4 and IPv4-mapped IPv6, wildcard and explicit binds,
automatic ports, periodic fabric callers, and same-port direct connections
from another loopback address on a Windows test VM. Confirm that repeated
authorization does not republish consumed entries and that ordinary fabric
requests do not receive HTTP 421.

### Native state-machine regression tests

From an x64 Visual Studio Developer PowerShell at the repository root:

```powershell
clang -Werror -O2 -I .\packages\eBPF-for-Windows.x64.1.6.0\build\native\include .\ebpf\tests\redirect_context_tests.c -o "$env:TEMP\gpa-audit-cookie-tests.exe"
if ($LASTEXITCODE -ne 0) { throw "Cookie audit tests failed to compile" }
& "$env:TEMP\gpa-audit-cookie-tests.exe"
if ($LASTEXITCODE -ne 0) { throw "Cookie audit tests failed" }
Remove-Item -LiteralPath "$env:TEMP\gpa-audit-cookie-tests.exe"
```

These tests include the actual eBPF source with mocked kernel helpers. They
cover primary publication without socket context, original-destination
callbacks followed by redirected callbacks, unresolved sources, identity,
protocol and destination mismatches, cookie isolation, staging/publication
failures, IPv4 and mapped IPv6, one-time publication, the zero-cookie branch,
and skip/alert-only behavior. They do not
replace driver verification, signing, or live WFP timing tests.
