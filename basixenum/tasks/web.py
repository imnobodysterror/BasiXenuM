import json
from pathlib import Path
from basixenum.tasks.base import ReconTask


class FfufTask(ReconTask):
    def parse_output(self, stdout: str, stderr: str):
        findings = []

        ignore_suffixes = {
            "/.",
            "/.html",
            "/.htm",
            "/.ht",
            "/.htc",
            "/.htuser",
            "/.htgroup",
            "/.htpasswds",
        }

        json_path = None
        if "-o" in self.command:
            try:
                json_path = Path(self.command[self.command.index("-o") + 1])
            except (ValueError, IndexError):
                json_path = None

        if json_path and json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8", errors="ignore"))
                for item in data.get("results", []):
                    url = item.get("url", "")
                    status = item.get("status", "")
                    length = item.get("length", "")

                    if not url:
                        continue

                    if any(url.endswith(x) for x in ignore_suffixes):
                        continue

                    findings.append(f"{url} [Status: {status}, Size: {length}]")

            except Exception as e:
                findings.append(f"[ffuf parser error] {e}")

        if not findings:
            for line in stdout.splitlines():
                line = line.strip()
                if "[Status:" in line:
                    findings.append(line)

        return findings[:20]
