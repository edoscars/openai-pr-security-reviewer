from types import SimpleNamespace

from pr_security_reviewer.diff_extractor import (
    DEFAULT_MAX_PATCH_BYTES,
    filter_reviewable_files,
    get_git_diff,
    is_reviewable_path,
    parse_unified_diff,
)


PATCH = """diff --git a/src/auth/login.py b/src/auth/login.py
index 1111111..2222222 100644
--- a/src/auth/login.py
+++ b/src/auth/login.py
@@ -10,3 +10,4 @@ def login(username):
     query = \"SELECT * FROM users\"
-    return execute(query)
+    query += \" WHERE name = '%s'\" % username
+    audit_login(username)
+    return execute(query)
diff --git a/requirements.lock b/requirements.lock
index 1111111..2222222 100644
--- a/requirements.lock
+++ b/requirements.lock
@@ -1 +1 @@
-old
+new
"""


def test_parses_added_lines_with_new_file_line_numbers() -> None:
    files = parse_unified_diff(PATCH)

    assert len(files) == 2
    login = files[0]
    assert login.path == "src/auth/login.py"
    assert [(line.number, line.text) for line in login.added_lines] == [
        (11, '    query += " WHERE name = \'%s\'" % username'),
        (12, "    audit_login(username)"),
        (13, "    return execute(query)"),
    ]


def test_filters_non_python_and_generated_or_vendored_paths() -> None:
    files = parse_unified_diff(PATCH)

    assert [file.path for file in filter_reviewable_files(files)] == ["src/auth/login.py"]
    assert is_reviewable_path("src/handler.py")
    assert not is_reviewable_path("vendor/handler.py")
    assert not is_reviewable_path("src/client_generated.py")
    assert not is_reviewable_path("requirements.lock")


def test_filters_patches_over_the_configured_size_limit() -> None:
    files = parse_unified_diff(PATCH)

    assert filter_reviewable_files(files, max_patch_bytes=1) == []
    assert DEFAULT_MAX_PATCH_BYTES > len(files[0].patch.encode())


def test_empty_diff_has_no_files() -> None:
    assert parse_unified_diff("") == []


def test_get_git_diff_uses_argument_list_without_a_shell(monkeypatch) -> None:
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stdout="diff")

    monkeypatch.setattr("pr_security_reviewer.diff_extractor.subprocess.run", fake_run)

    assert get_git_diff("base", "head") == "diff"
    assert calls == [
        (
            (["git", "diff", "--no-ext-diff", "--unified=3", "base...head"],),
            {"check": True, "capture_output": True, "text": True},
        )
    ]
