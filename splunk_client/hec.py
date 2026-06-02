import json
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HECClient:
    """
    HTTP Event Collector client for injecting events into Splunk.
    Sends events as NDJSON (newline-delimited JSON) — one object per line.
    Each event's timestamp is passed in the outer HEC payload so Splunk
    honors per-event timing (inner _time field is ignored by HEC).
    """

    def __init__(self, host: str, port: int, token: str, verify_ssl: bool = False):
        self.url = f"https://{host}:{port}/services/collector/event"
        self.headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }
        self.verify = verify_ssl

    def send_event(self, event: dict, index: str, sourcetype: str, time_override: float = None) -> None:
        """Send a single event."""
        self.send_events([event], index=index, sourcetype=sourcetype)

    def send_events(self, events: list[dict], index: str, sourcetype: str) -> None:
        """
        Send multiple events in a single NDJSON HEC batch request.
        Each event dict must contain an '_time' field (Unix epoch float)
        set by the injector — this becomes the outer HEC 'time' field so
        Splunk stores the correct per-event timestamp.
        """
        if not events:
            return

        lines = []
        for ev in events:
            # Pop _time from the event body and promote it to the HEC envelope.
            # This is the only way Splunk honors per-event timestamps via HEC.
            ev_copy = dict(ev)
            ts = ev_copy.pop("_time", time.time())

            hec_obj = {
                "time": ts,
                "index": index,
                "sourcetype": sourcetype,
                "event": ev_copy,
            }
            lines.append(json.dumps(hec_obj))

        # NDJSON: each object on its own line, newline-terminated
        payload = "\n".join(lines) + "\n"

        resp = requests.post(
            self.url,
            data=payload,
            headers=self.headers,
            verify=self.verify,
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") != 0:
            raise RuntimeError(f"HEC error: {result}")
