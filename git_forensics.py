import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone


GITHUB_WEB_FLOW_KEY = "B5690EEEBB952194"
DATE_MISMATCH_THRESHOLD = 300
FUTURE_DATE_THRESHOLD = 300


def run_git(args):
    result = subprocess.run(
        ["git"] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    return result.returncode, result.stdout, result.stderr


def git_output(args):
    code, stdout, stderr = run_git(args)

    if code != 0:
        raise RuntimeError(stderr.strip() or stdout.strip())

    return stdout


def is_git_repository():
    code, _, _ = run_git(["rev-parse", "--is-inside-work-tree"])
    return code == 0


def iso_from_timestamp(timestamp):
    dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    return dt.isoformat()


def parse_iso(value):
    return datetime.fromisoformat(value)


def get_commit_info(commit_hash):
    data = git_output([
        "show",
        "-s",
        "--format=%H%x00%an%x00%aI%x00%cn%x00%cI%x00%P%x00%s",
        commit_hash
    ]).strip()

    parts = data.split("\x00")

    parents = parts[5].split() if parts[5] else []

    return {
        "hash": parts[0],
        "author": parts[1],
        "author_date": parts[2],
        "committer": parts[3],
        "commit_date": parts[4],
        "parents": parents,
        "message": parts[6]
    }


def get_file_commits(path):
    output = git_output([
        "log",
        "--follow",
        "--format=%H",
        "--",
        path
    ])

    commits = []

    for line in output.splitlines():
        line = line.strip()

        if line:
            commits.append(line)

    return commits


def get_first_commit(path):
    commits = get_file_commits(path)

    if not commits:
        raise RuntimeError("Файл не найден в истории Git.")

    return commits[-1]


def get_last_commit(path):
    commits = get_file_commits(path)

    if not commits:
        raise RuntimeError("Файл не найден в истории Git.")

    return commits[0]


def get_all_file_commit_info(path):
    hashes = get_file_commits(path)

    return [get_commit_info(commit_hash) for commit_hash in hashes]


def get_dag(commit_hash, limit=12):
    code, stdout, _ = run_git([
        "log",
        "--graph",
        "--oneline",
        "--decorate",
        "--all",
        f"-{limit}",
        commit_hash
    ])

    if code != 0:
        return ""

    return stdout.strip()


def get_reflog():
    output = git_output(
        "reflog",
        "--all",
        "--date=iso-strict",
        "--format=%H%x00%gd%x00%gs"
    )

    result = []

    for line in output.splitlines():
        parts = line.split("\x00")

        if len(parts) != 3:
            continue

        commit_hash = parts[0]
        selector = parts[1]
        message = parts[2]

        match = re.search(r"@\{(.+)\}$", selector)

        if not match:
            continue

        reflog_date = match.group(1)

        result.append({
            "hash": commit_hash,
            "date": reflog_date,
            "message": message
        })

    return result

def check_reflog(commit_info, reflog_entries):
    anomalies = []

    commit_hash = commit_info["hash"]
    commit_date = parse_date(commit_info["commit_date"])

    for entry in reflog_entries:
        if entry["hash"] != commit_hash:
            continue

        reflog_date = parse_date(entry["date"])

        if reflog_date is None:
            continue

        delta = abs((reflog_date - commit_date).total_seconds())

        if delta > 300:
            anomalies.append({
                "type": "reflog_commit_date_mismatch",
                "commit": commit_hash,
                "reflog_date": entry["date"],
                "commit_date": commit_info["commit_date"],
                "delta_seconds": int(delta)
            })

    return anomalies

def verify_gpg(commit_hash):
    code, stdout, stderr = run_git([
        "verify-commit",
        "--raw",
        commit_hash
    ])

    text = stdout + "\n" + stderr

    if code != 0:
        return {
            "signed": False,
            "key_id": None,
            "source": None,
            "date_verified": None
        }

    key_id = None
    date_verified = None

    for line in text.splitlines():
        if "[GNUPG:] VALIDSIG" in line:
            parts = line.split()

            try:
                index = parts.index("VALIDSIG")
                key_id = parts[index + 1]

                if len(parts) > index + 2:
                    date_verified = parts[index + 2]
            except (ValueError, IndexError):
                pass

    if key_id is None:
        return {
            "signed": False,
            "key_id": None,
            "source": None,
            "date_verified": None
        }

    if key_id.upper().endswith(GITHUB_WEB_FLOW_KEY):
        source = "github"
    else:
        source = "user"

    return {
        "signed": True,
        "key_id": key_id,
        "source": source,
        "date_verified": date_verified
    }


def is_shallow_repository():
    code, stdout, _ = run_git([
        "rev-parse",
        "--is-shallow-repository"
    ])

    return code == 0 and stdout.strip().lower() == "true"


def get_shallow_roots():
    code, stdout, _ = run_git([
        "rev-parse",
        "--git-path",
        "shallow"
    ])

    if code != 0:
        return []

    path = stdout.strip()

    if not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def check_parent_child_order(commits):
    anomalies = []

    for child in commits:
        child_date = parse_iso(child["commit_date"])

        for parent_hash in child["parents"]:
            parent = get_commit_info(parent_hash)
            parent_date = parse_iso(parent["commit_date"])

            if parent_date > child_date:
                anomalies.append({
                    "type": "parent_child_order_violation",
                    "commits": [
                        parent_hash,
                        child["hash"]
                    ],
                    "details":
                        f"Parent CommitDate={parent['commit_date']} "
                        f"is later than child CommitDate={child['commit_date']}"
                })

    return anomalies


def check_author_commit_dates(commits):
    anomalies = []

    for commit in commits:
        author_date = parse_iso(commit["author_date"])
        commit_date = parse_iso(commit["commit_date"])

        delta = abs((commit_date - author_date).total_seconds())

        if delta > DATE_MISMATCH_THRESHOLD:
            anomalies.append({
                "type": "author_commit_date_mismatch",
                "commit": commit["hash"],
                "delta": f"{int(delta)} seconds",
                "details":
                    f"AuthorDate={commit['author_date']}, "
                    f"CommitDate={commit['commit_date']}"
            })

    return anomalies


def check_future_dates(commits):
    anomalies = []

    now = datetime.now(timezone.utc)

    for commit in commits:
        commit_date = parse_iso(commit["commit_date"])

        if commit_date > now:
            delta = (commit_date - now).total_seconds()

            if delta > FUTURE_DATE_THRESHOLD:
                anomalies.append({
                    "type": "future_commit_date",
                    "commit": commit["hash"],
                    "commit_date": commit["commit_date"],
                    "details":
                        f"CommitDate находится примерно на "
                        f"{int(delta)} секунд в будущем."
                })

    return anomalies


def check_reflog_anomalies(commits):
    anomalies = []

    for commit in commits:
        result = check_reflog(
            commit["hash"],
            commit["commit_date"]
        )

        if result:
            anomalies.extend(result)

    return anomalies


def confidence_for_commit(commit, anomalies):
    commit_hash = commit["hash"]

    related = [
        anomaly
        for anomaly in anomalies
        if anomaly.get("commit") == commit_hash
        or commit_hash in anomaly.get("commits", [])
    ]

    if related:
        return "low"

    return "high"


def build_anomalies(commits):
    anomalies = []

    anomalies.extend(
        check_author_commit_dates(commits)
    )

    anomalies.extend(
        check_parent_child_order(commits)
    )

    anomalies.extend(
        check_future_dates(commits)
    )

    anomalies.extend(
        check_reflog_anomalies(commits)
    )

    return anomalies


def final_verdict(anomalies, shallow):
    if anomalies:
        return "suspicious"

    if shallow:
        return "suspicious"

    return "authentic"


def analyze(path):
    if not is_git_repository():
        raise RuntimeError(
            "Текущая папка не является Git-репозиторием."
        )

    commits = get_all_file_commit_info(path)

    if not commits:
        raise RuntimeError(
            f"Файл '{path}' не найден в истории Git."
        )

    first = commits[-1]
    last = commits[0]

    anomalies = build_anomalies(commits)

    shallow = is_shallow_repository()

    if shallow:
        anomalies.append({
            "type": "shallow_clone",
            "details":
                "История репозитория неполная. "
                "Дата создания файла может быть недоступна."
        })

    creation_confidence = confidence_for_commit(
        first,
        anomalies
    )

    last_confidence = confidence_for_commit(
        last,
        anomalies
    )

    gpg_creation = verify_gpg(first["hash"])
    gpg_last = verify_gpg(last["hash"])

    report = {
        "file": path,

        "created_at": {
            "value": first["commit_date"],
            "commit": first["hash"],
            "confidence": creation_confidence,
            "reason":
                f"Первый доступный в истории commit с файлом: "
                f"{first['hash']}. "
                f"AuthorDate={first['author_date']}, "
                f"CommitDate={first['commit_date']}."
        },

        "last_modified_at": {
            "value": last["commit_date"],
            "commit": last["hash"],
            "confidence": last_confidence,
            "reason":
                f"Последний commit, затронувший файл: "
                f"{last['hash']}. "
                f"AuthorDate={last['author_date']}, "
                f"CommitDate={last['commit_date']}."
        },

        "anomalies": anomalies,

        "gpg_verification": gpg_last,

        "final_verdict": final_verdict(
            anomalies,
            shallow
        ),

        "summary":
            f"Файл: {path}. "
            f"Создание: {first['hash']} "
            f"({first['commit_date']}). "
            f"Последнее изменение: {last['hash']} "
            f"({last['commit_date']}). "
            f"Обнаружено аномалий: {len(anomalies)}.",

        "technical": {
            "shallow_clone": shallow,
            "shallow_roots": get_shallow_roots(),

            "creation_commit": first,

            "last_modified_commit": last,

            "file_history_commits": [
                commit["hash"]
                for commit in commits
            ],

            "dag_creation": get_dag(
                first["hash"]
            ),

            "dag_last_modified": get_dag(
                last["hash"]
            ),

            "gpg_creation": gpg_creation,

            "gpg_last_modified": gpg_last
        }
    }

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Git forensic analyzer"
    )

    parser.add_argument(
        "file",
        help="Путь к файлу"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Файл для сохранения JSON"
    )

    args = parser.parse_args()

    try:
        report = analyze(args.file)

        result = json.dumps(
            report,
            ensure_ascii=False,
            indent=2
        )

        print(result)

        if args.output:
            with open(
                args.output,
                "w",
                encoding="utf-8"
            ) as file:
                file.write(result)

    except Exception as error:
        print(
            json.dumps(
                {
                    "error": str(error)
                },
                ensure_ascii=False,
                indent=2
            )
        )


if __name__ == "__main__":
    main()