"""Run the same suite against MySQL:  LP_TEST_STORE=mysql pytest
(needs scripts/mysql.sh start; LP_TEST_MYSQL overrides the server url, default mysql://root@127.0.0.1:13306).

Every store a test opens by path, directly or through open_engine / the service, becomes its own fresh MySQL
database named after the path; the databases are dropped at the end of the session."""
import hashlib
import os

import pytest

MYSQL = os.environ.get("LP_TEST_STORE") == "mysql"
SERVER = os.environ.get("LP_TEST_MYSQL", "mysql://root@127.0.0.1:13306")
_made: set = set()


def _db_name(path: str) -> str:
    return "lpt_" + hashlib.sha1(os.path.abspath(path).encode()).hexdigest()[:16]


def _mysql_store(path: str):
    from logparser.store_mysql import MySQLStore, parse_url
    import pymysql
    name = _db_name(path)
    if name not in _made:          # a path seen for the first time in this session starts empty
        p = parse_url(SERVER + "/mysql")
        cx = pymysql.connect(**{k: v for k, v in p.items() if k != "database"}, autocommit=True)
        with cx.cursor() as c:
            c.execute(f"DROP DATABASE IF EXISTS `{name}`")
        cx.close()
        _made.add(name)
    st = MySQLStore(f"{SERVER}/{name}", create_database=True)
    st.path = path                 # code that derives file names from the store path keeps working
    return st


if MYSQL:
    import logparser.cli
    import logparser.store
    _orig = logparser.store.open_store

    def open_store(url: str):
        if url.startswith("mysql") or url == ":memory:":
            return _orig(url)
        return _mysql_store(url[len("sqlite:///"):] if url.startswith("sqlite:///") else url)

    logparser.store.open_store = open_store
    logparser.cli.open_store = open_store


def new_store(path: str):
    """A store for a test: SQLite at `path`, or the MySQL database for that path."""
    from logparser.store import SqliteStore
    return _mysql_store(path) if MYSQL else SqliteStore(path)


@pytest.fixture(scope="session", autouse=True)
def _drop_mysql_databases():
    yield
    if MYSQL and _made:
        import pymysql
        from logparser.store_mysql import parse_url
        p = parse_url(SERVER + "/mysql")
        cx = pymysql.connect(**{k: v for k, v in p.items() if k != "database"}, autocommit=True)
        with cx.cursor() as c:
            for name in _made:
                c.execute(f"DROP DATABASE IF EXISTS `{name}`")
        cx.close()
