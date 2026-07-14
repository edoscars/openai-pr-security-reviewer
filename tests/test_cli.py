import sys

from openai import OpenAIError

from pr_security_reviewer import __main__


def test_main_reports_openai_failures_cleanly(monkeypatch, capsys) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(sys, "argv", ["pr_security_reviewer", "--base-sha", "a", "--head-sha", "b", "--repo", "o/r", "--pull-number", "1"])
    monkeypatch.setattr(__main__, "OpenAI", lambda **_: object())

    def fail(**_):
        raise OpenAIError("insufficient quota")

    monkeypatch.setattr(__main__, "run_pipeline", fail)

    assert __main__.main() == 2
    assert "PR security review failed: insufficient quota" in capsys.readouterr().err
