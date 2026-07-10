"""Deliberately vulnerable code used only to validate the PR reviewer demo."""

import sqlite3


def find_user(connection: sqlite3.Connection, username: str):
    return connection.execute(
        "SELECT id, username FROM users WHERE username = '%s'" % username
    ).fetchone()
