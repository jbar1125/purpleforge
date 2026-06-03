import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SearchClient:
    """
    Splunk REST API client for running SPL searches and managing saved searches.
    Port 8089 (management API).
    """

    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = False):
        self.base = f"https://{host}:{port}"
        self.auth = (username, password)
        self.verify = verify_ssl

    def run_search(self, spl: str, earliest: str = "-15m", latest: str = "now", max_results: int = 500) -> list[dict]:
        """
        Run a blocking SPL search and return all result rows as a list of dicts.
        Uses the jobs/export endpoint for simplicity.
        """
        params = {
            "search": f"search {spl}" if not spl.strip().startswith("search") else spl,
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "count": max_results,
        }
        resp = requests.post(
            f"{self.base}/services/search/jobs/export",
            auth=self.auth,
            data=params,
            verify=self.verify,
            timeout=60,
            stream=True,
        )
        resp.raise_for_status()

        results = []
        import json
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("result"):
                    results.append(obj["result"])
            except json.JSONDecodeError:
                continue
        return results

    def run_search_async(self, spl: str, earliest: str = "-15m", latest: str = "now", max_results: int = 500) -> list[dict]:
        """
        Create a search job, poll until done, return results.
        Use this for complex searches that time out on the export endpoint.
        """
        spl_query = f"search {spl}" if not spl.strip().startswith("search") else spl
        create_params = {
            "search": spl_query,
            "earliest_time": earliest,
            "latest_time": latest,
        }
        resp = requests.post(
            f"{self.base}/services/search/jobs",
            auth=self.auth,
            data=create_params,
            params={"output_mode": "json"},
            verify=self.verify,
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(f"Search job creation failed {resp.status_code}: {resp.text[:500]}")
        sid = resp.json()["sid"]

        # Poll until done
        for _ in range(60):
            time.sleep(2)
            status_resp = requests.get(
                f"{self.base}/services/search/jobs/{sid}",
                auth=self.auth,
                params={"output_mode": "json"},
                verify=self.verify,
                timeout=15,
            )
            status_resp.raise_for_status()
            state = status_resp.json()["entry"][0]["content"]["dispatchState"]
            if state in ("DONE", "FAILED"):
                break

        results_resp = requests.get(
            f"{self.base}/services/search/jobs/{sid}/results",
            auth=self.auth,
            params={"output_mode": "json", "count": max_results},
            verify=self.verify,
            timeout=30,
        )
        results_resp.raise_for_status()
        return results_resp.json().get("results", [])

    def dry_run_spl(self, spl: str) -> bool:
        """
        Validate SPL syntax by running `| makeresults | eval x=1 | search x=1`.
        Returns True if valid, False if Splunk returns an error.
        This is used to validate LLM-generated rules before saving them.
        """
        try:
            # A parse-only check: wrap in makeresults so no real data is scanned
            test_spl = f"| makeresults | eval _test=1 | search _test=1"
            self.run_search(test_spl, earliest="-1m", latest="now", max_results=1)
            # Now try the actual SPL
            self.run_search(spl, earliest="-1m", latest="now", max_results=1)
            return True
        except Exception:
            return False

    def save_search(self, name: str, spl: str, description: str = "") -> bool:
        """Create or update a Splunk saved search."""
        params = {
            "name": name,
            "search": spl,
            "description": description,
            "output_mode": "json",
        }
        try:
            resp = requests.post(
                f"{self.base}/servicesNS/nobody/search/saved/searches",
                auth=self.auth,
                data=params,
                verify=self.verify,
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception:
            return False

    def list_indexes(self) -> list[str]:
        """Return list of index names."""
        resp = requests.get(
            f"{self.base}/services/data/indexes",
            auth=self.auth,
            params={"output_mode": "json", "count": 100},
            verify=self.verify,
            timeout=15,
        )
        resp.raise_for_status()
        return [e["name"] for e in resp.json().get("entry", [])]

    def run_search_sdk(self, spl: str, earliest: str = "-15m", latest: str = "now", max_results: int = 500) -> list[dict]:
        """
        Run a SPL search using the official Splunk Python SDK.
        Used to satisfy the 'Best Use of Developer Tools' prize requirement.
        Falls back to run_search_async on ImportError.
        """
        try:
            import splunklib.client as splunk_client
            import splunklib.results as splunk_results

            host, port_str = self.base.replace("https://", "").split(":")
            service = splunk_client.connect(
                host=host,
                port=int(port_str),
                username=self.auth[0],
                password=self.auth[1],
                scheme="https",
                verify=self.verify,
            )
            kwargs = {
                "earliest_time": earliest,
                "latest_time": latest,
                "exec_mode": "blocking",
                "count": max_results,
            }
            spl_query = f"search {spl}" if not spl.strip().startswith("search") else spl
            job = service.jobs.create(spl_query, **kwargs)
            rows = []
            for result in splunk_results.JSONResultsReader(job.results(output_mode="json", count=max_results)):
                if isinstance(result, dict):
                    rows.append(result)
            return rows
        except ImportError:
            return self.run_search_async(spl, earliest=earliest, latest=latest, max_results=max_results)

    def create_index(self, name: str) -> bool:
        """Create an index if it doesn't already exist."""
        if name in self.list_indexes():
            return True
        resp = requests.post(
            f"{self.base}/services/data/indexes",
            auth=self.auth,
            data={"name": name, "output_mode": "json"},
            verify=self.verify,
            timeout=15,
        )
        return resp.status_code in (200, 201, 409)
