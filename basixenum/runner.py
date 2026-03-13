import subprocess
from pathlib import Path
from basixenum.tasks.base import TaskResult, ReconTask


def run_task(task: ReconTask, outdir: Path) -> TaskResult:
    stdout_file = outdir / f"{task.name}.stdout.txt"
    stderr_file = outdir / f"{task.name}.stderr.txt"

    try:
        proc = subprocess.run(
            task.command,
            capture_output=True,
            text=True,
            timeout=task.timeout
        )
        stdout = proc.stdout
        stderr = proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = (e.stderr or "") + "\n[TIMEOUT]"
        rc = -1

    stdout_file.write_text(stdout, encoding="utf-8", errors="ignore")
    stderr_file.write_text(stderr, encoding="utf-8", errors="ignore")

    findings = task.parse_output(stdout, stderr)

    return TaskResult(
        name=task.name,
        command=task.command,
        returncode=rc,
        stdout=stdout,
        stderr=stderr,
        findings=findings,
        artifacts=[str(stdout_file), str(stderr_file)]
    )

