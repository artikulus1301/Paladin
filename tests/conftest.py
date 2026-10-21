"""
Pytest glue for Paladin's test suite.

* async def tests run via asyncio.run (no pytest-asyncio dependency);
* legacy script-style tests that return (passed, failed) fail when failed > 0
  instead of silently passing;
* tests/test_total.py calls sys.exit() at import time, so it is not collected
  directly — tests/test_core.py runs it as a subprocess instead.
"""
import asyncio
import inspect
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_PASSWORD", "test")
os.environ.setdefault("POSTGRES_DSN", "postgresql://x:x@localhost/x")

collect_ignore = ["test_total.py"]


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    func = pyfuncitem.obj
    kwargs = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
    result = asyncio.run(func(**kwargs)) if inspect.iscoroutinefunction(func) else func(**kwargs)
    if (isinstance(result, tuple) and len(result) == 2
            and all(isinstance(x, int) for x in result)):
        passed, failed = result
        assert failed == 0, f"{failed} check(s) failed ({passed} passed) — see captured output"
    return True
