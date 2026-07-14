import os
from pathlib import Path

from pr_security_reviewer.config import load_local_env


def test_loads_simple_local_values_without_overriding_existing_environment(tmp_path: Path, monkeypatch) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("# local only\nOPENAI_API_KEY=local-key\nGITHUB_TOKEN='local-token'\nINVALID-KEY=no\n")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "ci-token")

    load_local_env(dotenv)

    assert os.environ["OPENAI_API_KEY"] == "local-key"
    assert os.environ["GITHUB_TOKEN"] == "ci-token"
    assert "INVALID-KEY" not in os.environ


def test_missing_local_env_file_is_a_no_op(tmp_path: Path) -> None:
    load_local_env(tmp_path / ".env")
