"""Select a restore snapshot for the compatibility test's actual migration."""
from pathlib import Path
from contextlib import closing
import sqlite3
import sys


def schema_version(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)) as db:
        return db.execute("PRAGMA user_version").fetchone()[0]


def rollback_snapshot(path, previous_version):
    path = Path(path)
    current_version = schema_version(path)
    if current_version == previous_version:
        # A previous release may have left its initial-creation or older
        # migration snapshots here. They do not describe this upgrade.
        return None
    if current_version < previous_version:
        raise ValueError("current database schema unexpectedly regressed")
    snapshot = path.with_name(f"{path.stem}.pre-v{previous_version}{path.suffix}")
    if not snapshot.is_file():
        raise ValueError("schema changed without a matching restore snapshot")
    if schema_version(snapshot) != previous_version:
        raise ValueError("restore snapshot schema does not match the previous server")
    with closing(sqlite3.connect(snapshot.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("restore snapshot failed integrity_check")
    return snapshot


if __name__ == "__main__":
    selected = rollback_snapshot(sys.argv[1], int(sys.argv[2]))
    print(selected if selected is not None else "")
