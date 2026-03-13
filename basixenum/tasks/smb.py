from basixenum.tasks.base import ReconTask


class NetexecSmbTask(ReconTask):
    def parse_output(self, stdout: str, stderr: str):
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if "signing:" in line.lower() or "smbv1:" in line.lower() or "pwned" in line.lower():
                findings.append(line)
        return findings
