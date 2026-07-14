from pathlib import Path


def test_readme_documents_the_deployment_and_safety_contract() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    for heading in ("## Architecture", "## Confidence and gate policy", "## Security boundaries", "## Testing and evaluation"):
        assert heading in readme
    assert "pull_request_target" in readme
    assert "never applies fixes" in readme
    assert "store=False" in readme
    assert "Idempotent comments" in readme
    assert "Live validation" in readme


def test_demo_exposes_the_real_confidence_gate_policy() -> None:
    demo = Path("demo.html").read_text(encoding="utf-8")

    assert 'id="confidence"' in demo
    assert 'id="severity"' in demo
    assert "confidence.value === 'confirmed'" in demo
    assert "['critical', 'high']" in demo
