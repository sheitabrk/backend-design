"""Tests for the PreToolUse hooks. Run: python3 -m unittest discover -s tests"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(ROOT, "hooks")

# Fake credentials, assembled at runtime so no secret scanner trips on this file.
AWS = "AKIA" + "Z" * 16
ANTHROPIC = "sk-ant-api03-" + "A" * 40
SUPABASE = "sb_secret_" + "B" * 30
DB_URL = "postgresql://admin:" + "hunter2pw" + "@db.internal:5432/app"


def run_raw(script, stdin):
    return subprocess.run(
        [sys.executable, "-B", os.path.join(HOOKS, script)],
        input=stdin, capture_output=True, text=True, timeout=30,
    )


def run(case, script, tool_name, tool_input, cwd="/p"):
    """Return the text the hook hands to Claude, or "" when it stays quiet."""
    payload = {"tool_name": tool_name, "tool_input": tool_input, "cwd": cwd}
    result = run_raw(script, json.dumps(payload))
    case.assertEqual(result.returncode, 0, result.stderr)
    if not result.stdout.strip():
        return ""
    out = json.loads(result.stdout)
    specific = out["hookSpecificOutput"]
    case.assertEqual(specific["hookEventName"], "PreToolUse")
    # A warning must never approve or block the write.
    case.assertNotIn("permissionDecision", specific)
    return specific["additionalContext"]


class Config(unittest.TestCase):
    def test_every_registered_hook_prefers_python3_and_exists(self):
        with open(os.path.join(HOOKS, "hooks.json")) as handle:
            config = json.load(handle)
        commands = [h["command"] for entry in config["hooks"]["PreToolUse"] for h in entry["hooks"]]
        self.assertEqual(len(commands), 2)
        for command in commands:
            first, fallback = command.split(" || ")
            self.assertTrue(first.startswith("python3 "), command)
            self.assertEqual(fallback, first.replace("python3 ", "python ", 1))
            name = first.rsplit("/", 1)[1].rstrip('"')
            self.assertTrue(os.path.isfile(os.path.join(HOOKS, name)), name)

    @unittest.skipIf(os.name == "nt", "needs a POSIX shell")
    def test_commands_warn_with_only_one_interpreter_name_on_path(self):
        with open(os.path.join(HOOKS, "hooks.json")) as handle:
            command = json.load(handle)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        payload = json.dumps({"tool_name": "Write", "tool_input": {
            "file_path": "/p/migrations/1.sql", "content": "DROP TABLE a;"}})
        for name in ("python3", "python"):
            with self.subTest(only=name), tempfile.TemporaryDirectory() as bin_dir:
                os.symlink(sys.executable, os.path.join(bin_dir, name))
                result = subprocess.run(
                    ["/bin/sh", "-c", command], input=payload, capture_output=True, text=True,
                    timeout=30, env={"PATH": bin_dir, "CLAUDE_PLUGIN_ROOT": ROOT})
                self.assertIn("DROP TABLE", result.stdout, result.stderr)


class Robustness(unittest.TestCase):
    def test_odd_input_exits_quietly(self):
        for script in ("check_migration.py", "check_security.py"):
            for stdin in ("", "not json", "[]", "null", '{"tool_name":"Write","tool_input":[]}',
                          '{"tool_name":"Write","tool_input":{"file_path":5,"content":7}}'):
                with self.subTest(script=script, stdin=stdin):
                    result = run_raw(script, stdin)
                    self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)


class Migration(unittest.TestCase):
    PATH = "/p/supabase/migrations/20261127_change.sql"

    def check(self, sql, path=None):
        return run(self, "check_migration.py", "Write", {"file_path": path or self.PATH, "content": sql})

    def assert_flags(self, name, *statements):
        for sql in statements:
            with self.subTest(sql=sql):
                self.assertIn(name, self.check(sql))

    def assert_quiet(self, *statements):
        for sql in statements:
            with self.subTest(sql=sql):
                self.assertEqual(self.check(sql), "")

    def test_rename(self):
        self.assert_flags(
            "RENAME",
            "ALTER TABLE users RENAME TO accounts;",
            "ALTER TABLE users RENAME COLUMN a TO b;",
            "ALTER TABLE IF EXISTS public.users RENAME a TO b;",
            'ALTER TABLE "User Data" RENAME TO u;',
            "ALTER TYPE status RENAME TO state;",
            "RENAME TABLE a TO b;",
        )
        self.assert_quiet("ALTER INDEX a_idx RENAME TO b_idx;", "ALTER TABLE u RENAME CONSTRAINT a TO b;")

    def test_drop_column(self):
        self.assert_flags(
            "DROP COLUMN",
            "ALTER TABLE IF EXISTS users DROP COLUMN a;",
            "ALTER TABLE ONLY users DROP COLUMN IF EXISTS a;",
            "ALTER TABLE users ADD COLUMN b int, DROP COLUMN a;",
            "ALTER TABLE users DROP a;",
        )
        self.assert_quiet(
            "ALTER TABLE u DROP CONSTRAINT u_a_check;",
            "ALTER TABLE u ALTER COLUMN a DROP NOT NULL;",
            "ALTER TABLE u ALTER COLUMN a DROP DEFAULT;",
        )

    def test_not_null(self):
        self.assert_flags(
            "NOT NULL",
            "ALTER TABLE u ADD COLUMN a text NOT NULL;\nCREATE TABLE z (b int DEFAULT 0);",
            "ALTER TABLE u ADD COLUMN a numeric(10, 2) NOT NULL;",
            "ALTER TABLE u ADD a timestamp with time zone NOT NULL;",
            "ALTER TABLE u ADD COLUMN a int DEFAULT 1, ADD COLUMN b int NOT NULL;",
            "ALTER TABLE u ALTER COLUMN a SET NOT NULL;",
        )
        self.assert_quiet(
            "ALTER TABLE u ADD COLUMN a numeric(10, 2) NOT NULL DEFAULT 0;",
            "ALTER TABLE u ADD COLUMN a text CHECK (a IS NOT NULL);",
        )

    def test_check_constraint(self):
        self.assert_flags("CHECK", "ALTER TABLE u\n  ADD CONSTRAINT c CHECK (\n    a > 0\n  );")
        self.assert_quiet("ALTER TABLE u ADD CONSTRAINT c CHECK (a > 0) NOT VALID;")

    def test_index(self):
        self.assert_flags("CONCURRENTLY", "CREATE INDEX i ON u (a);", "CREATE UNIQUE INDEX i ON u (a);")
        self.assert_quiet(
            "CREATE INDEX  CONCURRENTLY i ON u (a);",
            "CREATE TABLE u (a int);\nCREATE INDEX i ON u (a);",
        )

    def test_comments_and_literals_are_ignored(self):
        self.assert_quiet(
            "-- DROP TABLE users;",
            "/* ALTER TABLE u DROP COLUMN a; */",
            "COMMENT ON TABLE u IS 'never DROP TABLE this';",
        )

    def test_drop_table_and_backfill(self):
        self.assert_flags("DROP TABLE", "DROP TABLE users;")
        self.assert_flags("backfill", "UPDATE users SET a = 1;", "INSERT INTO users (a) VALUES (1);")

    def test_sql_inside_code_migrations(self):
        path = "/p/alembic/versions/ab12_change.py"
        out = self.check('op.execute("ALTER TABLE u ADD COLUMN a int NOT NULL")\nx = dict(DEFAULT=1)\n', path)
        self.assertIn("NOT NULL", out)
        self.assertIn("DROP COLUMN", self.check('op.execute("ALTER TABLE u DROP COLUMN a")', path))

    def test_quotes_inside_sql_do_not_cut_a_code_statement_short(self):
        path = "/p/alembic/versions/ab12_change.py"
        safe = 'op.execute("ALTER TABLE u ADD CONSTRAINT c CHECK (s IN (\'a\')) NOT VALID")'
        self.assertEqual(self.check(safe, path), "")
        unsafe = 'op.execute("ALTER TABLE u ADD COLUMN s text CHECK (s IN (\'a\')) NOT NULL")'
        self.assertIn("NOT NULL", self.check(unsafe, path))

    def test_only_migration_files(self):
        for path in ("/p/2026-11-27-notes.md", "/p/migrations/README.md", "/p/scripts/2026-11-27_fix.py"):
            with self.subTest(path=path):
                self.assertEqual(self.check("DROP TABLE users;", path), "")
        self.assertIn("DROP TABLE", self.check("DROP TABLE users;", "/p/sql/V12__drop.sql"))

    def edit(self, before, old, new, replace_all=False):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "migrations"))
            path = os.path.join(tmp, "migrations", "001.sql")
            with open(path, "w") as handle:
                handle.write(before)
            tool_input = {"file_path": path, "old_string": old, "new_string": new, "replace_all": replace_all}
            return run(self, "check_migration.py", "Edit", tool_input, cwd=tmp)

    def test_edit_reports_only_what_it_introduces(self):
        self.assertEqual(self.edit("DROP TABLE users;\n", "DROP TABLE users;", "-- kept"), "")
        self.assertEqual(self.edit("DROP TABLE a;\nSELECT 1;\n", "SELECT 1;", "SELECT 2;"), "")
        # A fragment that is only dangerous in context.
        self.assertIn("NOT NULL", self.edit("ALTER TABLE u ADD COLUMN a int;\n", "a int", "a int NOT NULL"))
        self.assertIn("DROP TABLE", self.edit("SELECT 1;\n", "SELECT 1;", "DROP TABLE a;"))

    def test_edit_of_unreadable_file_still_checks_new_text(self):
        tool_input = {"file_path": "/nonexistent/migrations/1.sql", "old_string": "x", "new_string": "DROP TABLE a;"}
        self.assertIn("DROP TABLE", run(self, "check_migration.py", "Edit", tool_input))


class Security(unittest.TestCase):
    def check(self, content, path="/p/src/a.ts", cwd="/p"):
        return run(self, "check_security.py", "Write", {"file_path": path, "content": content}, cwd)

    def test_new_secret_shapes(self):
        for value in (DB_URL, ANTHROPIC, SUPABASE, DB_URL.replace("postgresql", "postgresql+asyncpg")):
            with self.subTest(value=value[:14]):
                self.assertIn("secret-shape", self.check('const a = "%s";' % value))

    def test_placeholders_are_not_secrets(self):
        for url in ("postgresql://u:${DB_PASS}@h/db", "postgres://u:<password>@h/db",
                    "postgresql://postgres:[YOUR-PASSWORD]@h/db"):
            with self.subTest(url=url):
                self.assertEqual(self.check('const a = "%s";' % url), "")

    def test_matched_text_is_never_repeated(self):
        content = "\n".join([
            'const k = "%s";' % AWS,
            'const d = "%s";' % DB_URL,
            'fetch("https://x.test/?token=abcdef123456");',
            'logger.info("password is hunter2pw")',
            'os.system("mysql -phunter2pw")',
        ])
        out = self.check(content)
        for leaked in (AWS, "hunter2pw", "abcdef123456", "ZZZZ"):
            self.assertNotIn(leaked, out)
        self.assertIn("line 1", out)

    def test_config_files_get_secret_rules_only(self):
        for path in ("/p/config.json", "/p/app.yaml", "/p/.env.example"):
            with self.subTest(path=path):
                self.assertIn("secret-shape", self.check('"key": "%s"' % AWS, path))
        self.assertEqual(self.check('{"note": "eval(x) verify=False"}', "/p/config.json"), "")

    def test_real_env_files_are_left_alone(self):
        for path in ("/p/.env", "/p/.env.local"):
            with self.subTest(path=path):
                self.assertEqual(self.check("AWS_KEY=" + AWS, path), "")

    def test_prefixed_variable_names(self):
        self.assertIn("secret-shape", self.check('OPENAI_API_KEY = "%s"' % ("q" * 32), "/p/src/s.py"))

    def test_template_and_triple_quoted_sql(self):
        cases = {
            "/p/src/db.ts": [
                "await client.query(`SELECT * FROM u WHERE id = ${id}`);",
                "await pool.query<Row>(\n  `UPDATE u SET a = ${a}`\n);",
                "await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE id = ${id}`)",
            ],
            "/p/src/db.py": [
                'cur.execute(f"""\n  SELECT * FROM u WHERE id={i}""")',
                "cur.executemany(f'DELETE FROM u WHERE id={i}', rows)",
            ],
        }
        for path, snippets in cases.items():
            for snippet in snippets:
                with self.subTest(snippet=snippet):
                    self.assertIn("sql-injection", self.check(snippet, path))

    def test_safe_sql_is_quiet(self):
        for snippet in ("await client.query(`SELECT * FROM u WHERE id = $1`, [id]);",
                        "await sql`SELECT * FROM u WHERE id = ${id}`;"):
            with self.subTest(snippet=snippet):
                self.assertEqual(self.check(snippet), "")

    def test_exec(self):
        self.assertEqual(self.check("const m = pattern.exec(input);"), "")
        self.assertEqual(self.check("model.eval()", "/p/src/m.py"), "")
        for snippet in ("exec(cmd);", "child_process.exec(cmd);", "require('child_process').execSync(cmd);"):
            with self.subTest(snippet=snippet):
                self.assertIn("command-injection", self.check(snippet))

    def test_skip_paths_match_whole_segments(self):
        secret = 'const k = "%s";' % AWS
        for path in ("/p/src/testimonials/api.ts", "/p/src/test-results/api.ts", "/p/src/builder/api.ts"):
            with self.subTest(path=path):
                self.assertIn("secret-shape", self.check(secret, path))
        for path in ("/p/tests/a.ts", "/p/src/__tests__/a.ts", "/p/src/a.test.ts", "/p/test_a.py", "/p/dist/a.js"):
            with self.subTest(path=path):
                self.assertEqual(self.check(secret, path), "")

    def test_folders_above_the_project_do_not_skip(self):
        out = self.check('const k = "%s";' % AWS, "/home/x/build/app/src/a.ts", cwd="/home/x/build/app")
        self.assertIn("secret-shape", out)


if __name__ == "__main__":
    unittest.main()
