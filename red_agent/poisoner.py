"""
red_agent/poisoner.py — Red's alert-fatigue weapon.

HOW IT WORKS
------------
When Blue catches Red with rule R, Red does two things:
  1. Mutate: change attack fields to evade R (existing)
  2. POISON: inject high-volume legitimate-looking events that trip R as FPs

Repeated poisoning degrades R's precision until RuleRegistry marks it BURNED.
A burned rule covers nothing — Red has neutralized that defense vector.

TWO-PHASE APPROACH
------------------
Phase 1 — Flood (template-based, no LLM, always reliable):
  Extract the primary EventCode (or Operation/action field) from the catching SPL.
  Inject N events with that field set to legitimate-looking values that still
  match the rule's anchor. Example: scheduled_task fires on EventCode=4698 with
  no filters — inject 20 legit-looking 4698 events from IT accounts, updating
  task names. The rule fires, logs TP→FP mix → precision drops.

Phase 2 — Smart (LLM, when available):
  Ask the LLM to craft event fields that look completely benign but satisfy the
  rule's search clauses. More sophisticated, harder for Blue to filter out.
"""
from __future__ import annotations

import random
import re
import time

from splunk_client.hec import HECClient
from llm_client.base import LLMClient

# Benign-looking identity fields for FP events
_BENIGN_USERS = [
    "CORP\\jsmith", "CORP\\a.davis", "CORP\\m.wilson",
    "CORP\\helpdesk01", "CORP\\itadmin", "CORP\\svc_backup",
]
_BENIGN_IPS   = ["10.0.5.12", "10.0.5.40", "10.0.6.7", "192.168.1.55"]
_BENIGN_HOSTS = ["CORP-WS-010", "CORP-WS-021", "SRV-FILE-01"]
_BENIGN_TASKS = [
    "GoogleUpdateTaskMachineUA",
    "MicrosoftEdgeUpdateTaskMachineCore",
    "OneDrive Standalone Update Task",
    "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
    "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
    "AdobeARM",
]
_BENIGN_ACCOUNTS = [
    "n.intern", "t.contractor", "b.testuser", "s.auditor",
]

# Regex to extract EventCode / Operation values from SPL
_EVENTCODE_RE  = re.compile(r"EventCode\s*=\s*(\d+)", re.IGNORECASE)
_OPERATION_RE  = re.compile(r'Operation\s*=\s*"([^"]+)"', re.IGNORECASE)
_RESULTTYPE_RE = re.compile(r"ResultType\s*=\s*(\d+)", re.IGNORECASE)


def _extract_anchor(spl: str) -> dict | None:
    """
    Parse the most specific anchor from a catching rule's SPL.
    Returns a minimal event dict that will trigger the rule.
    """
    anchors = {}
    m = _EVENTCODE_RE.search(spl)
    if m:
        anchors["EventCode"] = int(m.group(1))
    m = _OPERATION_RE.search(spl)
    if m:
        anchors["Operation"] = m.group(1)
    m = _RESULTTYPE_RE.search(spl)
    if m:
        anchors["ResultType"] = int(m.group(1))
    return anchors if anchors else None


def _build_fp_event(anchor: dict) -> dict:
    """
    Build a single FP event that looks as benign as possible while satisfying
    the rule's anchor field(s).
    """
    ev = dict(anchor)
    code = anchor.get("EventCode", 0)

    if code == 4698:        # Scheduled Task — legit updater registering a task
        ev.update({
            "TaskName": random.choice(_BENIGN_TASKS),
            "Account_Name": random.choice(_BENIGN_USERS),
            "Computer": random.choice(_BENIGN_HOSTS),
            "Source_Network_Address": random.choice(_BENIGN_IPS),
        })
    elif code == 4720:      # New Account — IT provisioning
        ev.update({
            "TargetUserName": random.choice(_BENIGN_ACCOUNTS),
            "Account_Name": "CORP\\itadmin",
            "Subject_Account_Name": "CORP\\itadmin",
            "Computer": random.choice(_BENIGN_HOSTS),
        })
    elif code == 4624:      # Logon — normal Type 3 network logon (not Type 10 RDP)
        ev.update({
            "Logon_Type": 3,
            "Account_Name": random.choice(_BENIGN_USERS),
            "Source_Network_Address": random.choice(_BENIGN_IPS),
            "Workstation_Name": random.choice(_BENIGN_HOSTS),
        })
    elif code == 4625:      # Failed logon — isolated, below spray threshold
        ev.update({
            "Account_Name": random.choice(_BENIGN_USERS),
            "Sub_Status": "0xC000006A",
            "Source_Network_Address": random.choice(_BENIGN_IPS),
        })
    elif code == 1:         # Process create — legit parent/image
        ev.update({
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "User": random.choice(_BENIGN_USERS),
            "IntegrityLevel": "System",
        })
    elif code == 3:         # Network connection — looks like admin RDP session (needs DestinationPort=3389)
        ev.update({
            "DestinationPort": 3389,
            "DestinationIp": random.choice(["10.0.1.5", "10.0.1.10", "10.0.2.20"]),
            "SourceIp": random.choice(_BENIGN_IPS),
            "Image": "C:\\Windows\\System32\\mstsc.exe",
            "User": random.choice(_BENIGN_USERS),
            "Initiated": "true",
        })
    elif code == 8:         # CreateRemoteThread — legitimate instrumentation tool (not in exact-path whitelist)
        ev.update({
            "SourceImage": random.choice([
                "C:\\Program Files\\Symantec\\Symantec Endpoint Protection\\Smc.exe",
                "C:\\Program Files (x86)\\VMware\\VMware Tools\\vmtoolsd.exe",
                "C:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe",
            ]),
            "TargetImage": random.choice([
                "C:\\Windows\\System32\\explorer.exe",
                "C:\\Windows\\System32\\notepad.exe",
                "C:\\Program Files\\Internet Explorer\\iexplore.exe",
            ]),
            "StartFunction": "LoadLibraryW",
            "User": random.choice(_BENIGN_USERS),
        })
    elif code == 10:        # Process access to LSASS — legit diagnostic/AV tool (not in exact-path whitelist)
        ev.update({
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "SourceImage": random.choice([
                "C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe",
                "C:\\Program Files (x86)\\Malwarebytes\\Anti-Malware\\mbam.exe",
                "C:\\Program Files\\SysInternals\\procexp64.exe",
            ]),
            "GrantedAccess": "0x1000",   # PROCESS_QUERY_LIMITED_INFORMATION — benign read
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll|C:\\Windows\\System32\\KERNELBASE.dll",
        })
    elif code == 13:        # Registry set — non-persistence key
        ev.update({
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\App",
            "Image": "C:\\Windows\\System32\\msiexec.exe",
        })
    elif code == 4104:      # PowerShell script block — admin automation script using web/IEX patterns
        ev.update({
            "ScriptBlockText": random.choice([
                "# IT health check\n$wc = New-Object System.Net.WebClient\n"
                "$result = $wc.DownloadString('http://10.0.1.1/health-check')",
                "# Module loader\nIEX (Get-Content C:\\Scripts\\CommonFunctions.ps1 -Raw)",
                "$web = New-Object System.Net.WebClient\n"
                "IEX $web.DownloadString('http://scripts.corp.local/Update-Config.ps1')",
            ]),
            "Computer": random.choice(_BENIGN_HOSTS),
            "User": random.choice(_BENIGN_USERS),
            "ScriptBlockId": "{" + "".join(hex(random.randint(0, 15))[2:] for _ in range(32)) + "}",
            "Path": "",
        })
    elif anchor.get("Operation"):   # Cloud / O365 operation
        op = anchor["Operation"]
        ev.update({
            "UserId": f"{random.choice(['jsmith','adavis','mwilson'])}@contoso.com",
            "ClientIP": random.choice(_BENIGN_IPS),
            "ResultStatus": "True",
            "Workload": "Exchange" if "Inbox" in op or "Mailbox" in op else "AzureActiveDirectory",
        })
    elif anchor.get("ResultType") == 0:     # Cloud sign-in
        ev.update({
            "UserPrincipalName": f"{random.choice(['jsmith','adavis'])}@contoso.com",
            "IpAddress": random.choice(_BENIGN_IPS),
            "Location": "US",
            "ClientAppUsed": "Browser",
            "AuthenticationRequirement": "multiFactorAuthentication",
            "RiskLevelDuringSignIn": "none",
        })
    else:
        ev["User"] = random.choice(_BENIGN_USERS)

    # Tag as benign so precision scoring classifies correctly
    ev["benign"] = "true"
    ev["arena_technique"] = "benign"
    ev["arena_generation"] = 0
    return ev


class Poisoner:
    """
    Generates FP-inducing events to degrade a Blue detection rule's precision.

    Usage:
      poisoner = Poisoner(hec, llm, index)
      events = poisoner.poison_rule(technique_id, catching_spl, round_num, count=15)
    """

    def __init__(self, hec: HECClient, llm: LLMClient | None, index: str):
        self.hec = hec
        self.llm = llm
        self.index = index

    def poison_rule(
        self,
        technique_id: str,
        catching_spl: str,
        round_num: int,
        count: int = 15,
    ) -> list[dict]:
        """
        Flood `catching_spl` with legitimate-looking FP events.
        Falls back to template flooding if LLM is unavailable or returns bad output.
        Returns the list of injected events.
        """
        anchor = _extract_anchor(catching_spl)
        if not anchor:
            return []

        # Phase 2: ask LLM for smarter FP events
        llm_events = self._llm_poison(catching_spl, anchor, count) if self.llm else []

        # Phase 1 fallback / supplement: template flooding
        template_events = [_build_fp_event(anchor) for _ in range(count - len(llm_events))]

        all_events = llm_events + template_events
        now = time.time()
        for i, ev in enumerate(all_events):
            ev["arena_round"] = round_num
            ev["arena_technique"] = "benign"
            ev["arena_generation"] = 0
            ev["poison_for"] = technique_id
            ev["_time"] = now - (60 * (len(all_events) - i) / max(len(all_events), 1))

        # Infer sourcetype from the anchor
        sourcetype = self._infer_sourcetype(anchor)
        self.hec.send_events(all_events, index=self.index, sourcetype=sourcetype)
        return all_events

    def _infer_sourcetype(self, anchor: dict) -> str:
        code = anchor.get("EventCode", 0)
        if code in (4624, 4625, 4672, 4698, 4720, 4732):
            return "WinEventLog:Security"
        # Sysmon event codes (1=process create, 3=network, 8=remote thread, 10=process access,
        # 11=file create, 13=registry set, 4104=PS script block)
        if code in (1, 3, 8, 10, 11, 13, 4104):
            return "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
        if anchor.get("ResultType") is not None:
            return "azure:aad:signin"
        if anchor.get("Operation"):
            return "o365:management:activity"
        return "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

    def _llm_poison(self, spl: str, anchor: dict, count: int) -> list[dict]:
        """
        Ask the LLM to craft benign-looking event fields that satisfy the rule.
        Returns a (possibly empty) list of event dicts.
        """
        if not self.llm:
            return []
        prompt = (
            f"You are a red-team adversary. The following Splunk SPL detection rule is "
            f"catching your activity:\n\n{spl}\n\n"
            f"Generate {min(count, 5)} realistic event field dictionaries that look like "
            f"completely legitimate system activity but would MATCH this SPL query, causing "
            f"false positives that degrade the rule's precision.\n"
            f"The events must include these anchor fields: {anchor}.\n"
            f"Return ONLY a valid JSON array of objects, no prose."
        )
        try:
            raw = self.llm.complete(prompt)
            import json, re
            m = re.search(r"\[.*\]", raw, re.DOTALL)
            if not m:
                return []
            events = json.loads(m.group(0))
            if isinstance(events, list):
                return [e for e in events if isinstance(e, dict)][:count]
        except Exception:
            pass
        return []
