import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import git_forensics as gf


def git_run(args, cwd, env_extra=None):
    env = os.environ.copy()
    env.update(env_extra or {})
    return subprocess.run(
        ["git"] + args,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


class RepoFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        r = git_run(["init", "-q"], self.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        git_run(["config", "user.email", "test@example.com"], self.repo)
        git_run(["config", "user.name", "Tester"], self.repo)
        self._old_cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._old_cwd)
        self._tmp.cleanup()

    def commit(self, message, dates=None, add_all=True):
        env_extra = {}
        if dates:
            env_extra["GIT_AUTHOR_DATE"] = dates[0]
            env_extra["GIT_COMMITTER_DATE"] = dates[1]
        if add_all:
            git_run(["add", "-A"], self.repo)
        r = git_run(["commit", "-q", "-m", message], self.repo, env_extra)
        self.assertEqual(r.returncode, 0, r.stderr)

    def analyze(self, path):
        os.chdir(self.repo)
        return gf.analyze(path)


class TestCoreScenarios(RepoFixture):
    def test_normal_history(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt", ("2026-10-01T10:00:00+04:00",) * 2)
        (self.repo / "file.txt").write_text("v1\nv2\n")
        self.commit("Update file.txt", ("2026-10-01T11:00:00+04:00",) * 2)

        report = self.analyze("file.txt")

        self.assertEqual(report["analysis_status"], "completed")
        self.assertEqual(report["final_verdict"], "no_anomalies_detected")
        self.assertEqual(report["anomalies"], [])

        limit_types = [l["type"] for l in report["limitations"]]
        self.assertIn("methodology", limit_types)
        self.assertNotIn("shallow_clone", limit_types)
        self.assertNotIn("no_reflog", limit_types)
        self.assertEqual(report["created_at"]["value"], "2026-10-01T10:00:00+04:00")
        self.assertEqual(report["last_modified_at"]["value"], "2026-10-01T11:00:00+04:00")
        self.assertEqual(report["created_at"]["confidence"], "medium")

        self.assertNotIn(report["final_verdict"], ("authentic", "suspicious"))

    def test_author_commit_date_mismatch(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit(
            "Backdated author date",
            ("2025-01-01T12:00:00+04:00", "2026-10-05T23:30:00+04:00"),
        )

        report = self.analyze("file.txt")

        self.assertEqual(report["final_verdict"], "anomalies_found")
        types = [a["type"] for a in report["anomalies"]]
        self.assertIn("author_commit_date_mismatch", types)

    def test_future_date(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Future commit", ("2030-01-01T12:00:00+04:00",) * 2)

        report = self.analyze("file.txt")

        types = [a["type"] for a in report["anomalies"]]
        self.assertIn("future_commit_date", types)
        self.assertEqual(report["final_verdict"], "anomalies_found")

    def test_parent_child_order_violation(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Parent", ("2026-10-05T23:30:00+04:00",) * 2)
        (self.repo / "file.txt").write_text("v1\nv2\n")
        self.commit("Child backdated", ("2026-10-01T00:00:00+04:00",) * 2)

        report = self.analyze("file.txt")

        types = [a["type"] for a in report["anomalies"]]
        self.assertIn("parent_child_order_violation", types)

    def test_rename_and_delete_follow(self):
        (self.repo / "old.txt").write_text("data\n")
        self.commit("Create old.txt", ("2026-10-01T10:00:00+04:00",) * 2)
        (self.repo / "new.txt").write_text("data\n")
        (self.repo / "old.txt").unlink()
        self.commit("Rename old.txt to new.txt", ("2026-10-01T11:00:00+04:00",) * 2)
        (self.repo / "new.txt").unlink()
        self.commit("Delete new.txt", ("2026-10-01T12:00:00+04:00",) * 2)

        report = self.analyze("new.txt")

        self.assertEqual(report["final_verdict"], "no_anomalies_detected")
        self.assertEqual(len(report["technical"]["file_history_commits"]), 3)
        self.assertEqual(report["last_modified_at"]["value"], "2026-10-01T12:00:00+04:00")

    def test_missing_file_raises(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")

        with self.assertRaises(RuntimeError):
            self.analyze("nope.txt")

    def test_not_a_git_repository(self):
        outside = Path(self._tmp.name) / "notrepo"
        outside.mkdir()
        os.chdir(outside)
        with self.assertRaises(RuntimeError):
            gf.analyze("file.txt")


class TestReflog(RepoFixture):
    def test_fresh_clone_no_false_positive(self):
        """Регрессионный тест: запись clone: в reflog законно позже коммита
        и не должна давать reflog_commit_date_mismatch."""
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt", ("2026-10-01T10:00:00+04:00",) * 2)

        clone = Path(self._tmp.name) / "clone"
        r = subprocess.run(
            ["git", "clone", "-q", str(self.repo), str(clone)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

        os.chdir(clone)
        report = gf.analyze("file.txt")

        types = [a["type"] for a in report["anomalies"]]
        self.assertNotIn("reflog_commit_date_mismatch", types)
        self.assertEqual(report["final_verdict"], "no_anomalies_detected")

    def test_forged_committer_date_documented_limitation(self):
        """Документация ограничения: запись reflog, создаваемая git commit,
        наследует подделанную GIT_COMMITTER_DATE, поэтому согласованное
        датирование не обнаруживается по reflog. Проверка не падает и не
        выдаёт ложных признаков; честная история ответа 'подлинно' не даёт."""
        (self.repo / "file.txt").write_text("v1\n")
        self.commit(
            "Forged",
            ("2026-01-01T10:00:00+04:00",) * 2,
        )

        report = self.analyze("file.txt")

        self.assertEqual(report["final_verdict"], "no_anomalies_detected")
        self.assertEqual(report["created_at"]["value"], "2026-01-01T10:00:00+04:00")
        limit_types = [l["type"] for l in report["limitations"]]
        self.assertIn("methodology", limit_types)


class TestShallow(RepoFixture):
    def test_shallow_clone_partial_status(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("First", ("2026-10-01T10:00:00+04:00",) * 2)
        (self.repo / "file.txt").write_text("v1\nv2\n")
        self.commit("Second", ("2026-10-01T11:00:00+04:00",) * 2)

        clone = Path(self._tmp.name) / "shallow"
        r = subprocess.run(
            ["git", "clone", "-q", "--depth", "1", self.repo.as_uri(), str(clone)],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

        os.chdir(clone)
        report = gf.analyze("file.txt")

        self.assertEqual(report["analysis_status"], "partial")
        self.assertEqual(report["final_verdict"], "insufficient_data")
        limit_types = [l["type"] for l in report["limitations"]]
        self.assertIn("shallow_clone", limit_types)
        self.assertIn("methodology", limit_types)
        self.assertEqual(report["created_at"]["confidence"], "low")


class TestVerdicts(unittest.TestCase):
    def test_final_verdict_matrix(self):
        self.assertEqual(gf.final_verdict([{"type": "x"}], False), "anomalies_found")
        self.assertEqual(gf.final_verdict([], True), "insufficient_data")
        self.assertEqual(gf.final_verdict([], False), "no_anomalies_detected")

    def test_dedupe_anomalies(self):
        a = {"type": "reflog_commit_date_mismatch", "commit": "abc"}
        result = gf.dedupe_anomalies([a, dict(a), {"type": "other"}])
        self.assertEqual(len(result), 2)


class TestGpg(unittest.TestCase):
    """Проверка веток verify_gpg без развёртывания реальных GPG-ключей:
    подменяем результат запуска git."""

    def test_unsigned(self):
        with patch.object(gf, "run_git", return_value=(1, "", "error: no signature found")):
            result = gf.verify_gpg("abc")
        self.assertFalse(result["signed"])
        self.assertEqual(result["verification_status"], "unsigned")

    def test_github_web_flow_key(self):
        raw = "[GNUPG:] VALIDSIG B5690EEEBB952194 2026-10-05"
        with patch.object(gf, "run_git", return_value=(0, raw, "")):
            result = gf.verify_gpg("abc")
        self.assertTrue(result["signed"])
        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(result["source"], "github")

    def test_user_key(self):
        raw = "[GNUPG:] VALIDSIG 0123456789ABCDEF 2026-10-05"
        with patch.object(gf, "run_git", return_value=(0, raw, "")):
            result = gf.verify_gpg("abc")
        self.assertTrue(result["signed"])
        self.assertEqual(result["source"], "user")

    def test_verification_failed(self):
        with patch.object(gf, "run_git", return_value=(1, "", "gpg: key expired")):
            result = gf.verify_gpg("abc")
        self.assertFalse(result["signed"])
        self.assertEqual(result["verification_status"], "verification_failed")


class TestCLI(RepoFixture):
    def test_cli_success_and_output_file(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")

        out = Path(self._tmp.name) / "report.json"
        r = subprocess.run(
            [sys.executable, gf.__file__, "file.txt", "-o", str(out)],
            cwd=self.repo,
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(out.exists())
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("final_verdict", data)
        self.assertIn("analysis_status", data)

    def test_cli_missing_file_fails_nonzero(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")

        r = subprocess.run(
            [sys.executable, gf.__file__, "nope.txt"],
            cwd=self.repo,
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertNotEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["analysis_status"], "failed")



class TestSpecialCases(RepoFixture):
    def test_parent_outside_file_history(self):
        """Родитель, не трогавший файл, всё равно проверяется:
        его дата сравнивается с датой дочернего коммита."""
        (self.repo / "other.txt").write_text("data\n")
        self.commit("Parent touches other.txt", ("2026-10-05T23:30:00+04:00",) * 2)
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Child backdated", ("2026-10-01T00:00:00+04:00",) * 2)

        report = self.analyze("file.txt")

        types = [a["type"] for a in report["anomalies"]]
        self.assertIn("parent_child_order_violation", types)

    def test_special_chars_filename(self):
        name = "данные [v1] (финал).txt"
        (self.repo / name).write_text("v1\n")
        self.commit("Create special name", ("2026-10-01T10:00:00+04:00",) * 2)

        report = self.analyze(name)

        self.assertEqual(report["final_verdict"], "no_anomalies_detected")
        self.assertEqual(len(report["technical"]["file_history_commits"]), 1)

    def test_missing_parent_tolerated(self):
        """Недоступный родитель не ломает анализ и не даёт ложной аномалии."""
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")
        child = dict(gf.get_all_file_commit_info("file.txt", repo=str(self.repo))[0], parents=["0" * 40])

        anomalies = gf.check_parent_child_order([child], {})

        self.assertEqual(anomalies, [])

    def test_get_commits_info_fallback(self):
        """Пачка с несуществующим хэшем разбирается по одному:
        валидные хэши получаются, битые попадают в unavailable."""
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")
        good = gf.get_file_commits("file.txt", repo=str(self.repo))[0]
        bad = "0" * 40

        info, unavailable = gf.get_commits_info([good, bad], repo=str(self.repo))

        self.assertIn(good, info)
        self.assertEqual(unavailable, [bad])


class TestMissingParentInAnalyze(RepoFixture):
    def test_unavailable_parent_gives_partial_report(self):
        """Если метаданные родителя получить не удалось, анализ завершается
        со статусом partial и ограничением parent_check_incomplete,
        а не падает."""
        (self.repo / "other.txt").write_text("data\n")
        self.commit("Parent touches other.txt")
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")

        real_get_commits_info = gf.get_commits_info
        calls = {"n": 0}

        def mocked(hashes, repo=None):
            calls["n"] += 1
            if calls["n"] == 1:
                # первый вызов — метаданные коммитов истории файла
                return real_get_commits_info(hashes, repo)
            # второй вызов — родители: сообщаем, что они недоступны
            return {}, list(hashes)

        with patch.object(gf, "get_commits_info", side_effect=mocked):
            report = self.analyze("file.txt")

        self.assertEqual(report["analysis_status"], "partial")
        types = [l["type"] for l in report["limitations"]]
        self.assertIn("parent_check_incomplete", types)
        self.assertEqual(report["final_verdict"], "no_anomalies_detected")


class TestBuildAnomaliesCompat(RepoFixture):
    def test_two_argument_form(self):
        """Прежняя форма: build_anomalies(commits, reflog_entries)."""
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")
        commits = gf.get_all_file_commit_info("file.txt", repo=str(self.repo))
        reflog = gf.get_reflog(str(self.repo))

        anomalies = gf.build_anomalies(commits, reflog)

        self.assertEqual(anomalies, [])


class TestRepoParam(RepoFixture):
    def test_repo_param_cwd_unchanged(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")

        target = str(self._tmp.name)
        os.chdir(target)
        try:
            report = gf.analyze("file.txt", repo=str(self.repo))
            self.assertEqual(os.getcwd(), target)
        finally:
            os.chdir(self._old_cwd)

        self.assertEqual(report["analysis_status"], "completed")
        self.assertEqual(report["final_verdict"], "no_anomalies_detected")

    def test_concurrent_repos(self):
        """Параллельный анализ двух репозиториев без смены рабочей папки."""
        repos = []
        for name in ("a", "b"):
            repo = Path(self._tmp.name) / name
            repo.mkdir()
            git_run(["init", "-q"], repo)
            git_run(["config", "user.email", "test@example.com"], repo)
            git_run(["config", "user.name", "Tester"], repo)
            (repo / "file.txt").write_text(name + "\n")
            git_run(["add", "-A"], repo)
            r = git_run(
                ["commit", "-q", "-m", "Create " + name], repo,
                {"GIT_AUTHOR_DATE": "2026-10-01T10:00:00+04:00",
                 "GIT_COMMITTER_DATE": "2026-10-01T10:00:00+04:00"},
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            repos.append(repo)

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(lambda rp: gf.analyze("file.txt", repo=str(rp)), repos)
            )

        for repo, report in zip(repos, results):
            self.assertEqual(report["analysis_status"], "completed")
            self.assertEqual(report["final_verdict"], "no_anomalies_detected")
            message = report["technical"]["creation_commit"]["message"]
            self.assertEqual(message, "Create " + repo.name)
            # графы истории непустые даже при анализе из посторонней папки
            self.assertTrue(report["technical"]["dag_creation"])
            self.assertTrue(report["technical"]["dag_last_modified"])


class TestCLIOption(RepoFixture):
    def test_cli_repo_option(self):
        (self.repo / "file.txt").write_text("v1\n")
        self.commit("Create file.txt")

        r = subprocess.run(
            [sys.executable, gf.__file__, "file.txt", "-C", str(self.repo)],
            cwd=self._tmp.name,
            capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["analysis_status"], "completed")


class TestUIServer(unittest.TestCase):
    """Проверка HTTP-интерфейса: валидация запросов и защита эндпоинта."""

    @classmethod
    def setUpClass(cls):
        import ui_server
        cls.ui = ui_server
        cls.server = ui_server.make_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        cls.repo = Path(tempfile.mkdtemp()) / "repo"
        cls.repo.mkdir()
        git_run(["init", "-q"], cls.repo)
        git_run(["config", "user.email", "test@example.com"], cls.repo)
        git_run(["config", "user.name", "Tester"], cls.repo)
        (cls.repo / "file.txt").write_text("v1\n")
        git_run(["add", "-A"], cls.repo)
        git_run(
            ["commit", "-q", "-m", "Create file.txt"], cls.repo,
            {"GIT_AUTHOR_DATE": "2026-10-01T10:00:00+04:00",
             "GIT_COMMITTER_DATE": "2026-10-01T10:00:00+04:00"},
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        import shutil
        shutil.rmtree(cls.repo.parent, ignore_errors=True)

    def _post(self, body, headers=None):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            payload = body if isinstance(body, bytes) else body.encode("utf-8")
            all_headers = {"Content-Type": "application/json"}
            all_headers.update(headers or {})
            conn.request(
                "POST", "/analyze", body=payload, headers=all_headers
            )
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, data
        finally:
            conn.close()

    def _valid_body(self):
        return json.dumps({"repo": str(self.repo), "file": "file.txt"})

    def test_valid_request(self):
        status, data = self._post(self._valid_body())
        self.assertEqual(status, 200)
        report = json.loads(data)
        self.assertEqual(report["analysis_status"], "completed")
        self.assertEqual(report["final_verdict"], "no_anomalies_detected")

    def test_foreign_origin_rejected(self):
        status, _ = self._post(
            self._valid_body(), {"Origin": "http://evil.example"}
        )
        self.assertEqual(status, 403)

    def test_host_wrong_port_rejected(self):
        status, _ = self._post(
            self._valid_body(), {"Host": f"127.0.0.1:{self.port + 1}"}
        )
        self.assertEqual(status, 403)

    def test_localhost_origin_wrong_port_rejected(self):
        status, _ = self._post(
            self._valid_body(),
            {"Origin": f"http://127.0.0.1:{self.port + 1}"},
        )
        self.assertEqual(status, 403)

    def test_jsonp_content_type_rejected(self):
        status, _ = self._post(
            self._valid_body(), {"Content-Type": "application/jsonp"}
        )
        self.assertEqual(status, 400)

    def test_wrong_content_type_rejected(self):
        status, _ = self._post(
            self._valid_body(), {"Content-Type": "text/plain"}
        )
        self.assertEqual(status, 400)

    def test_bad_json_rejected(self):
        status, _ = self._post("{not json")
        self.assertEqual(status, 400)

    def test_non_object_json_rejected(self):
        status, _ = self._post("[1, 2]")
        self.assertEqual(status, 400)

    def test_non_string_fields_rejected(self):
        status, _ = self._post(json.dumps({"repo": 1, "file": "x"}))
        self.assertEqual(status, 400)

    def test_oversized_body_rejected(self):
        status, _ = self._post("x" * 200000)
        self.assertEqual(status, 400)

    def test_get_page(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", "/")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8")
            self.assertEqual(resp.status, 200)
            self.assertIn("Git Forensics", body)
            self.assertIn("например: C:\\projects\\my-repo", body)
        finally:
            conn.close()

    def test_run_analysis_validates_input(self):
        code, data = self.ui.run_analysis(str(self.repo), "-evil")
        self.assertEqual(code, 400)
        code, data = self.ui.run_analysis("/nonexistent/dir", "file.txt")
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main()
