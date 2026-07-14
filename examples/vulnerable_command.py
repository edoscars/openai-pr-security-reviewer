"""Deliberately vulnerable code used only to validate the PR reviewer demo."""

import subprocess


def search_users(query: str) -> None:
    subprocess.run(f"grep {query} users.txt", shell=True, check=True)
