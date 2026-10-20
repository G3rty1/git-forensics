"""Ядро Git Forensics: проверка дат файла в истории Git.

Все обращения к git принимают необязательный параметр repo — папку
репозитория. Если он не задан, используется текущая папка (как раньше).
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

GITHUB_WEB_FLOW_KEY = "B5690EEEBB952194"
DATE_MISMATCH_THRESHOLD = 300
FUTURE_DATE_THRESHOLD = 300
GIT_TIMEOUT_SECONDS = 60
BATCH_SIZE = 50
COMMIT_FORMAT = "%H%x00%an%x00%aI%x00%cn%x00%cI%x00%P%x00%s%x00"
FIELD_COUNT = 7  # %H %an %aI %cn %cI %P %s


class GitError(RuntimeError):
    """Git не найден, не ответил за отведённое время или вернул ошибку."""


def run_git(args, repo=None):
    """Запуск git; repo — папка репозитория (None = текущая папка)."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        raise GitError(
            "Git не найден. Установите его с https://git-scm.com "
            "и добавьте в PATH."
        )
    except subprocess.TimeoutExpired:
        command = " ".join(args[:3])
        raise GitError(
            f"Git-команда не завершилась за {GIT_TIMEOUT_SECONDS} секунд "
            f"(git {command}…)."
        )
    return result.returncode, result.stdout, result.stderr


def git_output(args, repo=None):
    code, stdout, stderr = run_git(args, repo)
    if code != 0:
        raise GitError(stderr.strip() or stdout.strip())
    return stdout


def is_git_repository(repo=None):
    code, _, _ = run_git(["rev-parse", "--is-inside-work-tree"], repo)
    return code == 0


def iso_from_timestamp(timestamp):
    dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    return dt.isoformat()


def parse_iso(value):
    return datetime.fromisoformat(value)


def literal_pathspec(path):
    """Путь как литерал: символы *. [] в имени файла не трактуются как шаблон."""
    return f":(literal){path}"


def _parse_commit_records(stdout):
    """Разбор записей git show с полями, разделёнными NUL.

    Формат заканчивается %x00, поэтому каждая запись содержит ровно
    FIELD_COUNT полей, а разбор не зависит от переносов строк внутри
    полей (например, в имени автора). Последняя пустая часть отбрасывается.
    """
    if not stdout:
        return []
    parts = stdout.split("\x00")
    records = []
    for start in range(0, len(parts) - 1, FIELD_COUNT):
        chunk = parts[start:start + FIELD_COUNT]
        records.append({
            "hash": chunk[0].lstrip("\n"),
            "author": chunk[1],
            "author_date": chunk[2],
            "committer": chunk[3],
            "commit_date": chunk[4],
            "parents": chunk[5].split() if chunk[5] else [],
            "message": chunk[6].rstrip("\n"),
        })
    return records


def get_commit_info(commit_hash, repo=None):
    data = git_output(
        ["show", "-s", f"--format={COMMIT_FORMAT}", commit_hash], repo
    ).strip()
    records = _parse_commit_records(data)
    if not records:
        raise GitError(f"Не удалось получить данные коммита {commit_hash}.")
    return records[0]


def get_commits_info(hashes, repo=None):
    """Метаданные списка коммитов за минимум запусков git.

    Возвращает (dict хэш → информация, список недоступных хэшей).
    Хэши запрашиваются пачками; если пачка не удалась (например, в ней
    есть отсутствующий объект), она разбирается по одному, чтобы один
    битый объект не ломал весь анализ.
    """
    info = {}
    unavailable = []
    hashes = list(hashes)
    for start in range(0, len(hashes), BATCH_SIZE):
        chunk = hashes[start:start + BATCH_SIZE]
        code, stdout, _ = run_git(
            ["show", "-s", f"--format={COMMIT_FORMAT}"] + chunk, repo
        )
        if code == 0:
            for record in _parse_commit_records(stdout):
                info[record["hash"]] = record
        else:
            # пачка не прошла — пробуем каждый хэш отдельно
            for commit_hash in chunk:
                code_one, stdout_one, _ = run_git(
                    ["show", "-s", f"--format={COMMIT_FORMAT}", commit_hash],
                    repo,
                )
                if code_one == 0:
                    for record in _parse_commit_records(stdout_one):
                        info[record["hash"]] = record
                else:
                    unavailable.append(commit_hash)
    for commit_hash in hashes:
        if commit_hash not in info and commit_hash not in unavailable:
            unavailable.append(commit_hash)
    return info, unavailable


def get_file_commits(path, repo=None):
    output = git_output(
        ["log", "--follow", "--topo-order", "--format=%H", "--",
         literal_pathspec(path)],
        repo,
    )
    return [line.strip() for line in output.splitlines() if line.strip()]


def get_first_commit(path, repo=None):
    commits = get_file_commits(path, repo)
    if not commits:
        raise RuntimeError("Файл не найден в истории Git.")
    return commits[-1]


def get_last_commit(path, repo=None):
    commits = get_file_commits(path, repo)
    if not commits:
        raise RuntimeError("Файл не найден в истории Git.")
    return commits[0]


def get_all_file_commit_info(path, repo=None):
    commits = get_file_commits(path, repo)
    if not commits:
        raise RuntimeError(f"Файл '{path}' не найден в истории Git.")
    info, unavailable = get_commits_info(commits, repo)
    if unavailable:
        raise GitError(
            "Не удалось получить данные коммитов: "
            + ", ".join(unavailable[:3])
        )
    return [info[commit_hash] for commit_hash in commits]


def get_dag(commit_hash, limit=12, repo=None):
    code, stdout, _ = run_git(
        ["log", "--graph", "--oneline", "--decorate", "--all",
         f"-{limit}", commit_hash],
        repo,
    )
    if code != 0:
        return ""
    return stdout.strip()


def get_reflog(repo=None):
    output = git_output([
        "reflog", "--all", "--date=iso-strict",
        "--format=%H%x00%gd%x00%gs"
    ], repo)
    result = []
    for line in output.splitlines():
        parts = line.split("\x00")
        if len(parts) != 3:
            continue
        commit_hash, selector, message = parts
        match = re.search(r"@\{(.+)\}$", selector)
        if not match:
            continue
        result.append({
            "hash": commit_hash,
            "date": match.group(1),
            "message": message
        })
    return result


def index_reflog_entries(reflog_entries):
    """Индекс записей reflog по хэшу коммита: один проход вместо
    полного перебора на каждый коммит."""
    index = {}
    for entry in reflog_entries:
        index.setdefault(entry["hash"], []).append(entry)
    return index


def check_reflog(commit_info, reflog_index):
    # для совместимости принимается и список записей, и индекс по хэшу
    """Вспомогательная проверка по reflog.

    Учитываются только записи операций создания коммитов (commit, amend).
    Записи clone / checkout / reset / pull законно происходят позже
    создания коммита и не являются признаком подделки.
    Дубликаты (одна операция в reflog нескольких ссылок) учитываются один раз.
    """
    if isinstance(reflog_index, list):
        reflog_index = index_reflog_entries(reflog_index)
    anomalies = []
    commit_hash = commit_info["hash"]
    commit_date = parse_iso(commit_info["commit_date"])
    seen = set()

    for entry in reflog_index.get(commit_hash, []):
        operation = entry["message"].split(":", 1)[0].strip()
        if not operation.startswith("commit"):
            continue
        key = (entry["hash"], entry["date"])
        if key in seen:
            continue
        seen.add(key)
        reflog_date = parse_iso(entry["date"])
        delta = abs((reflog_date - commit_date).total_seconds())
        if delta > DATE_MISMATCH_THRESHOLD:
            anomalies.append({
                "type": "reflog_commit_date_mismatch",
                "commit": commit_hash,
                "reflog_date": entry["date"],
                "commit_date": commit_info["commit_date"],
                "delta_seconds": int(delta),
                "details": (
                    "Вспомогательный признак: время операции commit в reflog "
                    "расходится с CommitDate. Может иметь добросовестные "
                    "причины (amend, перенос истории); не является "
                    "доказательством подделки. Reflog локален и отсутствует "
                    "в чужих клонах."
                )
            })
    return anomalies


def has_signature(commit_hash, repo=None):
    """Есть ли в объекте коммита подпись (заголовок gpgsig).

    Не зависит от наличия gpg и от текста сообщений git, который
    различается между системами.
    """
    code, stdout, _ = run_git(["cat-file", "commit", commit_hash], repo)
    if code != 0:
        return None
    header = stdout.split("\n\n", 1)[0]
    return any(line.startswith("gpgsig") for line in header.splitlines())


def verify_gpg(commit_hash, repo=None):
    code, stdout, stderr = run_git(["verify-commit", "--raw", commit_hash], repo)
    text = stdout + "\n" + stderr

    if code != 0:
        # На Windows git может молча завершиться с ошибкой для неподписанного
        # коммита, поэтому наличие подписи проверяем и по самому коммиту.
        if "no signature" in text.lower() or has_signature(commit_hash, repo) is False:
            return {
                "signed": False,
                "verification_status": "unsigned",
                "key_id": None,
                "source": None,
                "date_verified": None
            }
        return {
            "signed": False,
            "verification_status": "verification_failed",
            "key_id": None,
            "source": None,
            "date_verified": None,
            "details": text.strip()[:200]
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
            "verification_status": "verification_failed",
            "key_id": None,
            "source": None,
            "date_verified": None
        }

    source = "github" if key_id.upper().endswith(GITHUB_WEB_FLOW_KEY) else "user"
    return {
        "signed": True,
        "verification_status": "verified",
        "key_id": key_id,
        "source": source,
        "date_verified": date_verified
    }


def is_shallow_repository(repo=None):
    code, stdout, _ = run_git(["rev-parse", "--is-shallow-repository"], repo)
    return code == 0 and stdout.strip().lower() == "true"


def get_shallow_roots(repo=None):
    code, stdout, _ = run_git(["rev-parse", "--git-path", "shallow"], repo)
    if code != 0:
        return []
    path = stdout.strip()
    if not path:
        return []
    if not os.path.isabs(path):
        # git возвращает путь относительно папки репозитория
        base = repo if repo else os.getcwd()
        path = os.path.join(base, path)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def collect_parent_hashes(commits):
    """Хэши родителей, которых нет в самом списке (их метаданные
    нужно запросить отдельно)."""
    known = {commit["hash"] for commit in commits}
    parents = set()
    for commit in commits:
        for parent_hash in commit["parents"]:
            if parent_hash not in known:
                parents.add(parent_hash)
    return sorted(parents)


def check_parent_child_order(commits, parent_info=None, repo=None):
    """Проверка порядка родитель/потомок.

    parent_info — карта метаданных (включая сами коммиты истории файла).
    Если не задана, родители запрашиваются отдельно.
    Недоступные родители пропускаются.
    """
    if parent_info is None:
        fetched, _ = get_commits_info(collect_parent_hashes(commits), repo)
        parent_info = {commit["hash"]: commit for commit in commits}
        parent_info.update(fetched)
    anomalies = []
    for child in commits:
        child_date = parse_iso(child["commit_date"])
        for parent_hash in child["parents"]:
            parent = parent_info.get(parent_hash)
            if parent is None:
                continue
            parent_date = parse_iso(parent["commit_date"])
            if parent_date > child_date:
                anomalies.append({
                    "type": "parent_child_order_violation",
                    "commits": [parent_hash, child["hash"]],
                    "details":
                        f"Дата коммита-родителя ({parent['commit_date']}) "
                        f"позже даты дочернего коммита ({child['commit_date']})."
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


def check_reflog_anomalies(commits, reflog_index):
    anomalies = []
    for commit in commits:
        result = check_reflog(commit, reflog_index)
        if result:
            anomalies.extend(result)
    return anomalies


def confidence_for_commit(commit, anomalies, shallow=False):
    commit_hash = commit["hash"]
    related = [
        a for a in anomalies
        if a.get("commit") == commit_hash
        or commit_hash in a.get("commits", [])
    ]
    if related or shallow:
        return "low"
    # "medium", а не "high": даты Git задаёт клиент, поэтому даже без
    # обнаруженных аномалий дату нельзя считать доказанной.
    return "medium"


def dedupe_anomalies(anomalies):
    seen = set()
    result = []
    for anomaly in anomalies:
        key = json.dumps(anomaly, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            result.append(anomaly)
    return result


def build_anomalies(commits, reflog_entries, *, parent_info=None, repo=None):
    if isinstance(reflog_entries, list):
        reflog_entries = index_reflog_entries(reflog_entries)
    if parent_info is None:
        fetched, _ = get_commits_info(collect_parent_hashes(commits), repo)
        parent_info = {commit["hash"]: commit for commit in commits}
        parent_info.update(fetched)
    anomalies = []
    anomalies.extend(check_author_commit_dates(commits))
    anomalies.extend(check_parent_child_order(commits, parent_info))
    anomalies.extend(check_future_dates(commits))
    anomalies.extend(check_reflog_anomalies(commits, reflog_entries))
    return anomalies


def final_verdict(anomalies, shallow):
    if anomalies:
        return "anomalies_found"
    if shallow:
        return "insufficient_data"
    return "no_anomalies_detected"


def analyze(path, repo=None):
    if repo:
        repo = os.path.abspath(repo)
    if not is_git_repository(repo):
        raise RuntimeError("Указанная папка не является Git-репозиторием.")

    commits = get_all_file_commit_info(path, repo)
    if not commits:
        raise RuntimeError(f"Файл '{path}' не найден в истории Git.")

    first = commits[-1]
    last = commits[0]

    try:
        reflog_entries = get_reflog(repo)
    except Exception:
        reflog_entries = []
    reflog_index = index_reflog_entries(reflog_entries)

    # Метаданные родителей, которых нет в истории файла, запрашиваем
    # отдельно — но тоже пачкой. В карту метаданных входят и сами коммиты
    # истории файла: родитель может присутствовать в этой истории.
    parent_info, unavailable_parents = get_commits_info(
        collect_parent_hashes(commits), repo
    )
    metadata = {commit["hash"]: commit for commit in commits}
    metadata.update(parent_info)

    anomalies = dedupe_anomalies(
        build_anomalies(commits, reflog_index, parent_info=metadata, repo=repo)
    )
    shallow = is_shallow_repository(repo)

    limitations = [{
        "type": "methodology",
        "details": (
            "Даты в Git задаёт клиент. Первый доступный коммит фиксирует "
            "появление файла в доступной истории, а не объективное время "
            "написания кода. Согласованное датирование задним числом может "
            "не обнаруживаться. Отсутствие найденных аномалий не доказывает "
            "подлинность истории."
        )
    }]

    if not reflog_entries:
        limitations.append({
            "type": "no_reflog",
            "details": (
                "Локальный reflog недоступен — вспомогательная проверка "
                "по reflog не выполнена. Невыполненная проверка не равна "
                "проверке без аномалий."
            )
        })

    if shallow:
        limitations.append({
            "type": "shallow_clone",
            "details": (
                "История репозитория неполная (shallow clone). "
                "Первый доступный коммит может не быть реальным "
                "началом истории файла."
            )
        })

    if unavailable_parents:
        limitations.append({
            "type": "parent_check_incomplete",
            "details": (
                "Не удалось получить данные "
                f"{len(unavailable_parents)} родительских коммитов "
                "(например, объект отсутствует в репозитории): "
                + ", ".join(unavailable_parents[:3])
                + (", …" if len(unavailable_parents) > 3 else "")
                + ". Проверка порядка родитель/потомок для них выполнена "
                "не полностью."
            )
        })

    analysis_status = (
        "partial"
        if (shallow or not reflog_entries or unavailable_parents)
        else "completed"
    )

    gpg_creation = verify_gpg(first["hash"], repo)
    gpg_last = verify_gpg(last["hash"], repo)

    return {
        "file": path,
        "created_at": {
            "value": first["commit_date"],
            "commit": first["hash"],
            "confidence": confidence_for_commit(first, anomalies, shallow),
            "reason":
                f"Первый доступный в истории commit с файлом: "
                f"{first['hash']}. "
                f"AuthorDate={first['author_date']}, "
                f"CommitDate={first['commit_date']}. "
                f"Уверенность относится к положению коммита в доступной "
                f"истории, а не к достоверности даты."
        },
        "last_modified_at": {
            "value": last["commit_date"],
            "commit": last["hash"],
            "confidence": confidence_for_commit(last, anomalies, shallow),
            "reason":
                f"Последний commit, затронувший файл: "
                f"{last['hash']}. "
                f"AuthorDate={last['author_date']}, "
                f"CommitDate={last['commit_date']}. "
                f"Уверенность относится к положению коммита в доступной "
                f"истории, а не к достоверности даты."
        },
        "analysis_status": analysis_status,
        "anomalies": anomalies,
        "limitations": limitations,
        "gpg_verification": gpg_last,
        "final_verdict": final_verdict(anomalies, shallow),
        "summary":
            f"Файл: {path}. "
            f"Создание: {first['hash']} ({first['commit_date']}). "
            f"Последнее изменение: {last['hash']} ({last['commit_date']}). "
            f"Обнаружено аномалий: {len(anomalies)}.",
        "technical": {
            "shallow_clone": shallow,
            "shallow_roots": get_shallow_roots(repo),
            "creation_commit": first,
            "last_modified_commit": last,
            "file_history_commits": [c["hash"] for c in commits],
            "dag_creation": get_dag(first["hash"], repo=repo),
            "dag_last_modified": get_dag(last["hash"], repo=repo),
            "gpg_creation": gpg_creation,
            "gpg_last_modified": gpg_last
        }
    }


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="Git forensic analyzer")
    parser.add_argument("file", help="Путь к файлу")
    parser.add_argument(
        "-C", "--repo",
        help="Папка репозитория (по умолчанию — текущая)"
    )
    parser.add_argument("-o", "--output", help="Файл для сохранения JSON")
    args = parser.parse_args()

    try:
        report = analyze(args.file, repo=args.repo)
        result = json.dumps(report, ensure_ascii=False, indent=2)
        print(result)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as file:
                file.write(result)
    except Exception as error:
        print(json.dumps(
            {"analysis_status": "failed", "error": str(error)},
            ensure_ascii=False, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
