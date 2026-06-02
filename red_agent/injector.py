import time
import random
import copy
from splunk_client.hec import HECClient

# Realistic-looking placeholder values for template variable filling
_SAMPLE_USERS = ["jsmith", "adavis", "mwilson", "rthomas", "kbrown", "lgarcia"]
_SAMPLE_IPS = ["10.10.14.23", "192.168.100.45", "172.16.0.88", "10.0.1.200", "192.168.1.77"]
_SAMPLE_HOSTS = ["DESKTOP-A1B2C3", "WORKSTATION-042", "SRV-CORP-01", "LAPTOP-HR-12"]
_SAMPLE_TASKS = ["WindowsUpdateHelper", "SyncAgent", "TelemetryService", "HealthMonitor"]
_SAMPLE_CMDS = [
    "C:\\Windows\\Temp\\update.exe",
    "C:\\ProgramData\\helper.exe",
    "powershell.exe -enc JABjAD0A",
]
_SAMPLE_PROCS = [
    "C:\\Windows\\Temp\\procdump.exe",
    "C:\\Users\\Public\\mimikatz.exe",
    "C:\\Windows\\System32\\rundll32.exe",
]
_SAMPLE_REG_KEYS = ["SyncHelper", "UpdateAgent", "WinDefender", "AudioService"]

# Spec-level keys that control injection behavior — not injected as event fields
_SPEC_KEYS = {"count", "spread_seconds"}


def _fill_template(template: dict) -> dict:
    """Replace {placeholder} strings in a template dict with realistic values."""
    result = {}
    for k, v in template.items():
        if isinstance(v, str):
            v = v.replace("{target_user}", random.choice(_SAMPLE_USERS))
            v = v.replace("{attacker_ip}", random.choice(_SAMPLE_IPS))
            v = v.replace("{workstation}", random.choice(_SAMPLE_HOSTS))
            v = v.replace("{target_host}", random.choice(_SAMPLE_HOSTS))
            v = v.replace("{new_account}", f"svc_{random.randint(100,999)}")
            v = v.replace("{creating_user}", random.choice(_SAMPLE_USERS))
            v = v.replace("{task_name}", random.choice(_SAMPLE_TASKS))
            v = v.replace("{malicious_command}", random.choice(_SAMPLE_CMDS))
            v = v.replace("{dumper_process}", random.choice(_SAMPLE_PROCS))
            v = v.replace("{setting_process}", random.choice(_SAMPLE_PROCS))
            v = v.replace("{reg_key_name}", random.choice(_SAMPLE_REG_KEYS))
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

            # Spec-level overrides can change count and timing
            count = spec_overrides.get("count", event_spec.get("count", 1))
            spread = spec_overrides.get("spread_seconds", event_spec.get("spread_seconds", 1))

            events_to_send = []
            for i in range(count):
                ev = _fill_template(template)
                ev["arena_round"] = round_num
                ev["arena_technique"] = technique_id
                # Spread events backwards in time to simulate a real attack burst.
                # _time is promoted to the outer HEC envelope by HECClient.
                ev["_time"] = now - (spread * (count - i) / max(count, 1))
                events_to_send.append(ev)

            self.hec.send_events(events_to_send, index=self.index, sourcetype=sourcetype)
            injected.extend(events_to_send)

        return injected
