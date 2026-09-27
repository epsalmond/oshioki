import importlib.util
from pathlib import Path
from contextlib import closing
import shutil
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("rollback", Path(__file__).with_name("compat-rollback-snapshot.py"))
rollback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rollback)


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.live = Path(self.temp.name) / "state.sqlite3"

    def database(self, path, version, enrolled=True):
        with closing(sqlite3.connect(path)) as db:
            db.execute(f"PRAGMA user_version={version}")
            db.execute("CREATE TABLE devices (credential TEXT)")
            db.execute("CREATE TABLE requests (id TEXT, state TEXT)")
            if enrolled:
                db.execute("INSERT INTO devices VALUES ('enrolled-test-credential')")
                db.execute("INSERT INTO requests VALUES ('in-flight-test-request', 'pending')")
            db.commit()

    def assert_state(self, path):
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute("SELECT credential FROM devices").fetchall(), [("enrolled-test-credential",)])
            self.assertEqual(db.execute("SELECT id, state FROM requests").fetchall(), [("in-flight-test-request", "pending")])

    def test_patch_rollback_reuses_enrolled_database_and_ignores_initial_snapshot(self):
        self.database(self.live, 3)
        self.database(self.live.with_name("state.pre-v0.sqlite3"), 0, enrolled=False)
        self.database(self.live.with_name("state.pre-v3.sqlite3"), 3, enrolled=False)
        self.assertIsNone(rollback.rollback_snapshot(self.live, 3))
        self.assert_state(self.live)

    def test_schema_change_restores_exact_previous_version_not_sorted_snapshot(self):
        self.database(self.live, 10)
        expected = self.live.with_name("state.pre-v9.sqlite3")
        self.database(expected, 9)
        self.database(self.live.with_name("state.pre-v10.sqlite3"), 10, enrolled=False)
        self.assertEqual(rollback.rollback_snapshot(self.live, 9), expected)
        shutil.copyfile(expected, self.live)
        self.assertEqual(rollback.schema_version(self.live), 9)
        self.assert_state(self.live)

    def test_schema_change_requires_valid_matching_snapshot(self):
        self.database(self.live, 4)
        with self.assertRaisesRegex(ValueError, "without a matching"):
            rollback.rollback_snapshot(self.live, 3)
        snapshot = self.live.with_name("state.pre-v3.sqlite3")
        self.database(snapshot, 2)
        with self.assertRaisesRegex(ValueError, "does not match"):
            rollback.rollback_snapshot(self.live, 3)
        snapshot.write_bytes(b"invalid SQLite database")
        with self.assertRaises(sqlite3.DatabaseError):
            rollback.rollback_snapshot(self.live, 3)

    def test_schema_regression_fails(self):
        self.database(self.live, 2)
        with self.assertRaisesRegex(ValueError, "regressed"):
            rollback.rollback_snapshot(self.live, 3)


if __name__ == "__main__":
    unittest.main()
