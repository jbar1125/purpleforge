"""
red_agent/benign.py — normal "blue-collar" activity generator.

WHY THIS EXISTS
---------------
A detection's recall (does it catch the attack?) is only half the story. The
other half is PRECISION (does it fire ONLY on the attack?). A rule that alerts on
every scheduled task or every new user technically "catches" the attack but
drowns a SOC in false positives. You cannot measure precision without a stream of
realistic legitimate activity to measure it against.

This generator injects benign events that share the SAME EventCodes the attacks
use, but with legitimate field values, all tagged arena_technique="benign". The
scorer then counts how many of each rule's hits are benign (false positives).

PREDICTED OUTCOME against the v1 baseline rules (this is the teaching point):
  * scheduled_task  fires on schtasks.exe /Create -> FALSE POSITIVE on IT automation
                    (the rule is precise, yet admins legitimately run `schtasks /Create`)
  * new_account     fires on net.exe ... /add     -> FALSE POSITIVE on IT provisioning
                    (LOLBin dual-use: admins legitimately run `net user /add` too)
  * lsass_dump / process_injection  filter svchost/MsMpEng  -> correctly SILENT
  * rdp_lateral (Type 10 only), powershell_encoded (encoded only),
    registry_persist (Run key only), brute_force (threshold)  -> correctly SILENT
  * cloud_account_anomaly (legacy/risky/anon only)  -> correctly SILENT on a
    normal MFA sign-in; email_forwarding_rule (forwarding params only)  -> SILENT
    on a benign move-to-folder rule
So overall precision < 100%, driven by two identifiable broad rules — exactly the
rules Blue should tighten. That gap is the point.
"""
from __future__ import annotations

import random
import time

from splunk_client.hec import HECClient

_USERS = ["jsmith", "a.davis", "m.wilson", "r.thomas", "helpdesk01", "itadmin", "k.patel"]
_INTERNAL_IPS = ["10.0.5.12", "10.0.5.40", "10.0.6.7", "192.168.1.55", "192.168.1.88"]
_WORKSTATIONS = ["CORP-WS-010", "CORP-WS-021", "CORP-WS-033", "CORP-WS-058", "CORP-WS-077"]
_LEGIT_TASKS = [
    "GoogleUpdateTaskMachineUA",
    "MicrosoftEdgeUpdateTaskMachineCore",
    "OneDrive Standalone Update Task",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
]
_LEGIT_PROCS = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Notepad++\\notepad++.exe",
]

_SEC = "WinEventLog:Security"
_SYS = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
_PS = "WinEventLog:Microsoft-Windows-PowerShell/Operational"
# Cloud events use _json so Splunk auto-extracts JSON fields — same as the
# attack events for T1078.004 and T1114.003 (required since the Microsoft TA
# for azure:aad:signin / o365:management:activity isn't installed by default).
_AAD = "_json"
_O365 = "_json"

# Corporate egress IPs for legitimate cloud sign-ins (not anonymizers)
_CORP_EGRESS = ["203.0.113.10", "203.0.113.25", "198.18.7.4"]


def _u() -> str:
    return f"CORP\\{random.choice(_USERS)}"


class BenignGenerator:
    """Injects a batch of legitimate events so rule precision can be measured."""

    def __init__(self, hec: HECClient, index: str):
        self.hec = hec
        self.index = index

    def _specs(self) -> list[tuple[str, dict, int]]:
        """(sourcetype, event_template, count). Builders sample fresh values per event."""
        return [
            # Normal interactive + network logons — Type 2/3, never Type 10 (RDP rule is silent)
            (_SEC, {"EventCode": 4624, "Logon_Type": 2, "Account_Name": "{user}",
                    "Workstation_Name": "{ws}", "Source_Network_Address": "{ip}"}, 8),
            (_SEC, {"EventCode": 4624, "Logon_Type": 3, "Account_Name": "{user}",
                    "Workstation_Name": "{ws}", "Source_Network_Address": "{ip}"}, 5),
            # A couple of isolated failed logons — below brute-force threshold (count & dc both low)
            (_SEC, {"EventCode": 4625, "Account_Name": "{user}", "Sub_Status": "0xC000006A",
                    "Source_Network_Address": "{ip}"}, 2),
            # Legit IT scheduled task created with schtasks.exe /Create — the SAME LOLBin+flag
            # the attack uses, so scheduled_task FALSE-POSITIVES (LOLBin dual-use: the rule keys
            # on the binary, which can't tell admin automation from an attacker's persistence)
            (_SYS, {"EventCode": 1, "Image": "C:\\Windows\\System32\\schtasks.exe",
                    "CommandLine": "schtasks /Create /TN \"CorpNightlyBackup\" "
                                   "/TR C:\\IT\\backup.cmd /SC DAILY /ST 02:00 /RU SYSTEM",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "User": "CORP\\itadmin", "IntegrityLevel": "High"}, 2),
            # Legit IT account provisioning with net.exe /add — the SAME LOLBin+flag the attack
            # uses, so new_account FALSE-POSITIVES (LOLBin dual-use: admins really do run this)
            (_SYS, {"EventCode": 1, "Image": "C:\\Windows\\System32\\net.exe",
                    "CommandLine": "net user n.intern Welcome2Corp! /add",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "User": "CORP\\itadmin", "IntegrityLevel": "High"}, 1),
            # Benign LSASS access by Defender/host services — filtered out, NO false positive
            (_SYS, {"EventCode": 10, "SourceImage": "C:\\Windows\\System32\\svchost.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1000",
                    "SourceUser": "NT AUTHORITY\\SYSTEM"}, 3),
            # Benign admin PowerShell — no encoded/IEX/WebClient indicators, NO false positive
            (_PS, {"EventCode": 4104,
                   "ScriptBlockText": "Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table",
                   "User": "{user}"}, 2),
            # Normal process launches — non-suspicious images, NO false positive
            (_SYS, {"EventCode": 1, "Image": "{proc}", "CommandLine": "{proc}",
                    "ParentImage": "C:\\Windows\\explorer.exe", "User": "{user}",
                    "IntegrityLevel": "Medium"}, 4),
            # Benign registry write to a non-Run key — registry_persist stays SILENT
            (_SYS, {"EventCode": 13, "TargetObject":
                    "HKLM\\SOFTWARE\\Vendor\\App\\Settings\\LastRun", "Image": "{proc}"}, 3),
            # Normal cloud sign-in: MFA-satisfied, modern client, corporate IP, no risk
            # — cloud_account_anomaly stays SILENT (no legacy client / no risk / no anon IP)
            (_AAD, {"operationName": "Sign-in activity", "category": "SigninLogs",
                    "UserPrincipalName": "{cloud_user}", "UserId": "{cloud_user}",
                    "ResultType": 0, "ResultDescription": "Success", "IpAddress": "{corp_ip}",
                    "Location": "US", "AppDisplayName": "Microsoft Teams",
                    "ClientAppUsed": "Browser", "ConditionalAccessStatus": "success",
                    "AuthenticationRequirement": "multiFactorAuthentication",
                    "RiskLevelDuringSignIn": "none", "RiskState": "none"}, 6),
            # Benign inbox rule: file newsletters to a folder, NO forwarding/redirect
            # — email_forwarding_rule stays SILENT (no ForwardTo/RedirectTo/ForwardingSmtpAddress)
            (_O365, {"Workload": "Exchange", "Operation": "New-InboxRule",
                     "UserId": "{cloud_user}", "UserKey": "{cloud_user}", "ClientIP": "{corp_ip}",
                     "ResultStatus": "True",
                     "Parameters": "[{\"Name\":\"Name\",\"Value\":\"Newsletters\"},"
                                   "{\"Name\":\"MoveToFolder\",\"Value\":\"Newsletters\"},"
                                   "{\"Name\":\"From\",\"Value\":\"news@vendor.com\"}]"}, 2),
        ]

    @staticmethod
    def _fill(ev: dict) -> dict:
        ctx = {
            "user": _u(),
            "ip": random.choice(_INTERNAL_IPS),
            "ws": random.choice(_WORKSTATIONS),
            "task": random.choice(_LEGIT_TASKS),
            "proc": random.choice(_LEGIT_PROCS),
            "cloud_user": f"{random.choice(_USERS).replace('.', '')}@contoso.com",
            "corp_ip": random.choice(_CORP_EGRESS),
        }
        out = {}
        for k, v in ev.items():
            if isinstance(v, str):
                for ph, val in ctx.items():
                    v = v.replace(f"{{{ph}}}", val)
            out[k] = v
        return out

    def inject(self, round_num: int = 0, spread_seconds: float = 60.0) -> list[dict]:
        """
        Inject one batch of benign activity, spread over the last `spread_seconds`
        so it lands inside the detector's search window. Returns the sent events.
        """
        now = time.time()
        sent: list[dict] = []
        for sourcetype, template, count in self._specs():
            batch = []
            for _ in range(count):
                ev = self._fill(template)
                ev["arena_round"] = round_num
                ev["arena_technique"] = "benign"   # the FP marker the scorer keys on
                ev["arena_generation"] = 0
                ev["benign"] = "true"
                ev["_time"] = now - random.uniform(0, spread_seconds)
                batch.append(ev)
            self.hec.send_events(batch, index=self.index, sourcetype=sourcetype)
            sent.extend(batch)
        return sent
