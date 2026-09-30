import shutil
import sys
from pathlib import Path

from pyflink.datastream import StreamExecutionEnvironment


def use_this_interpreter(env: StreamExecutionEnvironment) -> None:
    """Make Flink's Python workers run in the interpreter that has PyFlink installed.

    Flink launches workers from a command line, so an interpreter path containing spaces breaks it (the worker
    dies immediately with exit code 0). Preferred: activate the venv so `python` on PATH is this interpreter.
    """
    on_path = shutil.which("python")
    if on_path and Path(on_path).resolve() == Path(sys.executable).resolve():
        return                                                   # PATH already points here; workers find it
    if any(c.isspace() for c in sys.executable):
        raise SystemExit(
            f"Flink can't launch Python workers from a path with spaces ({sys.executable}).\n"
            f"Put the venv's Scripts/bin directory first on PATH (or activate it) and run again.")
    env.set_python_executable(sys.executable)
