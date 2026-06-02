import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HECClient:
    """
    HTTP Event Collector client for injecting events into Splunk.
    Sends events in batches to reduce round trips.
    """

    def __init__(self, host: str, port: int, token: str, verify_ssl: bool = False):
        self.url = f"https://{host}:{port}/services/collector/event"
        self.headers = {"Authorization": f"Splunk {token}"}
        self.verify = verify_ssl

    def send_event(self, event: dict, index: str, sourcetype: str, time_override: float = None) -> None:
        """Send a single event."""
        self.send_events([event], index=index, sourcetype=sourcetype, time_override=time_override)

    def send_events(self, events: list[dict], index: str, sourcetype: str, time_override: float = None) -> None:
        """
        Send multiple events in a single HEC batch request.
        Each event dict becomes the 'event' field in the HEC payload.
        """
        if not events:
            return

        batch_payload = ""
        ts = time_override or time.time()
        for ev in events:
            hec_obj = {
                "time": ts,
                "index": index,
                "sourcetype": sourcetype,
                "event": ev,
            }
            import json
            batch_payload += json.dumps(hec_obj)

        resp = requests.post(
            self.url,
            data=batch_payload,
            headers={**self.headers, "Content-Type": "application/json"},
            verify=self.verify,
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("code") != 0:
            raise RuntimeError(f"HEC error: {result}")
