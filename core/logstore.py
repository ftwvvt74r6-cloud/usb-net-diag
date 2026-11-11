"""唯一日志出口：目录、按日文件、裁剪、环境快照、分析记录、崩溃快照。

为什么要有这一层（M1）：程序分发出去后**不会联网上报**，排障只能靠「把日志带回来」。
所以所有日志必须落到同一种结构里、有上限、能回答「谁在什么环境跑了什么」：

* 统一目录（:func:`log_root`，可用 ``NETDIAG_LOG_DIR`` 指到临时目录，测试靠它隔离）；
* 按日文件 + 单文件/总量上限（:func:`prune`，启动时执行一次）；
* 每次启动一份环境快照（:func:`write_env_snapshot`）；
* 每次分析一条结构化记录（:func:`record_run`）；
* 未捕获异常与进程级崩溃各留一份快照（:func:`record_crash` /
  :func:`install_excepthooks`）。

目录结构::

    logs/
      app-YYYYMMDD.log   启动器 / stdout / stderr
      diag-YYYYMMDD.log  诊断与服务运行日志
      env.json           本次启动的环境快照（覆盖写）
      runs/              每次分析一条 JSON（<ts>-<8位随机>.json）
      crashes/           Python 异常快照（<ts>-<pid>-<tid>-<rand>.txt）与 faulthandler（fatal-<ts>.log）

原则：**日志失败绝不影响诊断** —— 每个落盘操作都吞掉 ``OSError``，只返回 ``None``。
"""
from __future__ import annotations

import datetime as dt
import faulthandler
import json
import locale
import os
import platform
import re
import secrets
import sys
import threading
import traceback
from pathlib import Path

try:                                              # 扁平导入：core/ 在 sys.path
    from version import read_version
except ModuleNotFoundError:                        # 包方式：仓库根在 sys.path
    from core.version import read_version

ROOT = Path(__file__).resolve().parents[1]

#: 日志根目录环境变量；测试必须用它把日志指到临时目录，禁止写仓库 ``logs/``。
ENV_LOG_DIR = "NETDIAG_LOG_DIR"

#: 单文件上限（字节）。超过后只保留尾部（见 :func:`prune` 与 ``_DailySink``）。
MAX_FILE_BYTES = 5 << 20
#: ``logs/`` 总量上限（字节）。超过后按最旧优先删除，当天文件不动。
MAX_TOTAL_BYTES = 100 << 20
#: ``runs/`` 保留条数。
KEEP_RUNS = 200
#: ``crashes/`` 保留文件数（含 faulthandler 的 ``fatal-*.log``）。
KEEP_CRASHES = 50

#: 保护文件：总量裁剪永远不删（正在被读取/写或被别的进程使用）。
_PROTECTED_NAMES = ("env.json", "netdiag.pid", "netdiag.port")

_LOCK = threading.RLock()
_SINKS: dict[str, "_DailySink"] = {}
_FAULT_FILE = None
_ENV_CACHE: dict = {}
_HOOKS = {"installed": False, "sys": None, "thread": None}


# ---------------------------------------------------------------- 目录与时间
def log_root() -> Path:
    """返回日志根目录。

    Returns:
        Path: 环境变量 ``NETDIAG_LOG_DIR`` 非空时用它，否则 ``<仓库>/logs``。
            每次调用都重新读环境变量，测试可以在同一进程里切换临时目录。
    """
    raw = (os.environ.get(ENV_LOG_DIR) or "").strip()
    return Path(raw) if raw else ROOT / "logs"


def _today() -> str:
    return dt.date.today().strftime("%Y%m%d")


def _stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def _hms() -> str:
    return dt.datetime.now().strftime("%H:%M:%S")


def ensure_dirs() -> Path:
    """创建日志目录树（``logs/``、``runs/``、``crashes/``）与当天的两个日文件。

    当天的 ``app-YYYYMMDD.log`` / ``diag-YYYYMMDD.log`` 会以空文件形式先建出来，
    这样「跑一次分析后的目录树」是稳定的，不依赖先打印了哪条日志。

    Returns:
        Path: 日志根目录（创建失败也返回路径，真正写盘时再静默失败）。
    """
    root = log_root()
    for d in (root, root / "runs", root / "crashes"):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    for prefix in ("app", "diag"):
        path = root / f"{prefix}-{_today()}.log"
        try:
            if not path.exists():
                path.touch()
        except OSError:
            pass
    return root


# ---------------------------------------------------------------- 文件写入
def _truncate_tail(path: Path, keep: int) -> bool:
    """把文件截成「最后 ``keep`` 字节」，并从行首开始（避免半行）。

    Args:
        path: 目标文件。
        keep: 保留的尾部字节数（至少 1）。

    Returns:
        bool: 真的截短了返回 True；文件不存在、不够长或没有权限返回 False。
    """
    try:
        data = path.read_bytes()
        stat = path.stat()
    except OSError:
        return False
    if len(data) <= keep:
        return False
    tail = data[-max(1, keep):]
    cut = tail.find(b"\n")
    if cut >= 0:
        tail = tail[cut + 1:]
    try:
        path.write_bytes(tail)
        # 保留原 mtime：总量裁剪按「最旧优先」，截尾不该把历史文件洗成最新。
        try:
            os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        except OSError:
            pass
    except OSError:
        return False
    return True


def _write_json_atomic(path: Path, payload: dict) -> bool:
    """先写 ``.tmp`` 再 ``os.replace``，避免进程中断留下半个 JSON。"""
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        os.replace(tmp, path)
        return True
    except (OSError, TypeError, ValueError):
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


class _DailySink:
    """按天切换、按大小截尾的追加写句柄（同一进程内复用，不反复开文件）。"""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self._day = ""
        self._fh = None
        self._size = 0

    def _path(self) -> Path:
        return log_root() / f"{self.prefix}-{self._day}.log"

    def _open(self) -> None:
        root = ensure_dirs()
        path = root / f"{self.prefix}-{_today()}.log"
        self._fh = path.open("a", encoding="utf-8", newline="", buffering=1)
        self._day = _today()
        try:
            self._size = path.stat().st_size
        except OSError:
            self._size = 0

    def close(self) -> None:
        """关闭当前句柄；可重复调用。"""
        fh, self._fh = self._fh, None
        self._size = 0
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass

    def _rotate(self) -> None:
        """超过单文件上限：关句柄 → 截掉前半 → 重开（不换文件名，目录保持干净）。"""
        path = self._path()
        self.close()
        self._day = self._day or _today()
        _truncate_tail(path, max(1, MAX_FILE_BYTES // 2))
        try:
            self._open()
        except OSError:
            self._fh = None

    def write(self, text: str) -> None:
        """追加一段文本；失败时静默丢弃（下一行会重试打开）。

        Args:
            text: 要写入的文本；空串直接忽略。

        Returns:
            None: 写盘失败只关闭句柄，不抛异常。
        """
        if not text:
            return
        with _LOCK:
            try:
                if self._fh is None or self._day != _today():
                    self.close()
                    self._open()
                if self._fh is None:
                    return
                if self._size and self._size + len(text.encode("utf-8")) > MAX_FILE_BYTES:
                    self._rotate()
                if self._fh is None:
                    return
                self._fh.write(text)
                self._fh.flush()
                self._size += len(text.encode("utf-8"))
            except (OSError, ValueError):
                self.close()


class _Stream:
    """``sys.stdout`` / ``sys.stderr`` 的替身：把 ``print`` 原样写进 app 日志。"""

    encoding = "utf-8"
    errors = "replace"

    def __init__(self, sink: "_DailySink") -> None:
        self._sink = sink

    def write(self, text) -> int:
        """写一段文本（兼容 ``print`` 的调用方式）。

        Args:
            text: 字符串；非字符串按 0 长度处理。

        Returns:
            int: 实际写入的字符数（``print`` 不看，但文件协议要求返回）。
        """
        if isinstance(text, str) and text:
            self._sink.write(text)
            return len(text)
        return 0

    def writelines(self, lines) -> None:
        """逐行写入。

        Args:
            lines: 字符串序列。

        Returns:
            None: 空序列直接返回。
        """
        for line in lines or ():
            self.write(line)

    def flush(self) -> None:
        """空实现：底层每次写入已 flush，``print(..., flush=True)`` 不会报错。"""
        return

    def isatty(self) -> bool:
        """永远不是终端（日志流不交互）。

        Returns:
            bool: 恒为 ``False``。
        """
        return False

    def writable(self) -> bool:
        """可写：与真实 stdout 保持一致。

        Returns:
            bool: 恒为 ``True``。
        """
        return True

    def readable(self) -> bool:
        """不可读：日志流只写。

        Returns:
            bool: 恒为 ``False``。
        """
        return False

    def fileno(self) -> int:
        """没有真实 fd；需要 fd 的库（如 faulthandler）必须用 ``logstore`` 的日文件。

        Returns:
            int: 永不返回 —— 总是抛 ``OSError``，避免调用方拿到错误 fd。

        Raises:
            OSError: 任何调用都会抛出（日志流不是真实文件）。
        """
        raise OSError("日志流没有真实文件描述符")

    @property
    def closed(self) -> bool:
        """永不关闭：句柄由 :func:`close_streams` 统一管理。

        Returns:
            bool: 恒为 ``False``。
        """
        return False

    def close(self) -> None:
        """空实现：防止 ``print`` 的消费方误关共享句柄。"""
        return


def _sink(prefix: str) -> "_DailySink":
    with _LOCK:
        sink = _SINKS.get(prefix)
        if sink is None:
            sink = _DailySink(prefix)
            _SINKS[prefix] = sink
        return sink


def _log(prefix: str, msg: str) -> None:
    text = "" if msg is None else str(msg)
    if not text:
        return
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    try:
        sink = _sink(prefix)
        for line in lines:
            sink.write(f"[{_hms()}] [INFO] {line}\n")
    except Exception:  # noqa: BLE001  日志绝不影响业务
        pass


def app_log(msg: str) -> None:
    """写一条启动器日志到 ``app-YYYYMMDD.log``，行格式 ``[HH:MM:SS] [INFO] msg``。

    Args:
        msg: 日志正文；多行会逐行加前缀。

    Returns:
        None: 写盘失败静默忽略。
    """
    _log("app", msg)


def diag_log(msg: str) -> None:
    """写一条诊断/服务日志到 ``diag-YYYYMMDD.log``，行格式同 :func:`app_log`。

    Args:
        msg: 日志正文；多行（如 traceback）会逐行加前缀。

    Returns:
        None: 写盘失败静默忽略。
    """
    _log("diag", msg)


def open_stream() -> "_Stream":
    """返回写往 ``app-YYYYMMDD.log`` 的文本流（供 ``app.redirect_output()`` 使用）。

    Returns:
        _Stream: 具备 ``write`` / ``flush`` 的伪文件对象。底层句柄在进程内复用，
            不会每来一次 ``print`` 就打开一个文件。
    """
    return _Stream(_sink("app"))


def close_streams() -> None:
    """关闭并清空进程内所有日志句柄（含 faulthandler 文件；测试与退出时用）。

    Returns:
        None: 关闭失败静默忽略。
    """
    global _FAULT_FILE
    with _LOCK:
        for sink in list(_SINKS.values()):
            sink.close()
        _SINKS.clear()
        fault, _FAULT_FILE = _FAULT_FILE, None
        if fault is not None:
            try:
                faulthandler.disable()
            except (OSError, ValueError):
                pass
            try:
                fault.close()
            except OSError:
                pass


# ---------------------------------------------------------------- 环境快照
def _import_core(name: str):
    """导入 ``core/`` 下的模块，兼容「脚本方式」与「包方式」两种运行形态。"""
    try:
        return __import__(name)
    except ImportError:
        import importlib

        return importlib.import_module(f"core.{name}")


def _env_info() -> dict:
    """采集本机环境摘要（:func:`write_env_snapshot` 与崩溃快照共用）。"""
    info = {
        "version": "",
        "windows": platform.platform(),
        "windows_version": platform.version(),
        "admin": False,
        "npcap": None,
        "tshark_version": "",
        "tshark_path": "",
        "python_version": platform.python_version(),
        "console_encoding": "",
        "config_sha256": "",
        "started_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    info["version"] = read_version(ROOT)
    try:
        tshark = _import_core("tshark")
        ts = tshark.find_tshark()
        info["tshark_path"] = str(ts or "")
        info["tshark_version"] = tshark.version(ts)
        info["npcap"] = bool(tshark.npcap_installed())
        info["admin"] = bool(tshark.is_admin())
    except Exception:  # noqa: BLE001  环境探测失败不能拖垮启动
        pass
    try:
        info["config_sha256"] = str(_import_core("config").config_sha256())
    except Exception:  # noqa: BLE001
        pass
    try:
        info["console_encoding"] = (getattr(sys.stdout, "encoding", None)
                                    or locale.getpreferredencoding(False) or "")
    except Exception:  # noqa: BLE001
        pass
    return info


def write_env_snapshot(extra: dict | None = None) -> dict:
    """写 ``logs/env.json``（覆盖写）并返回快照内容。

    Args:
        extra: 追加/覆盖的字段（如入口名 ``{"entry": "app"}``）；``None`` 表示不加。

    Returns:
        dict: 环境快照。文件写不进去也返回内容，只是没有落盘。
    """
    ensure_dirs()
    info = _env_info()
    if extra:
        try:
            info.update(dict(extra))
        except (TypeError, ValueError):
            pass
    _ENV_CACHE.clear()
    _ENV_CACHE.update(info)
    try:
        (log_root() / "env.json").write_text(
            json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass
    return info


# ---------------------------------------------------------------- 运行记录
def record_run(record: dict) -> Path | None:
    """把一次分析写成 ``runs/<ts>-<8位随机>.json``。

    字段约定见 ``docs/logging.md``：``mode`` / ``params`` / ``duration_ms`` /
    ``level`` / ``critical`` / ``warning`` / ``sufficiency_ok`` / ``error_code`` /
    ``tshark_version``。文件名带随机后缀，避免并发同秒撞名（Windows 文件名里
    也不能出现 ``:``）。

    Args:
        record: 记录内容（会被 JSON 序列化）。

    Returns:
        Path | None: 写成功返回文件路径；目录不可写或内容不可序列化返回 ``None``
            （日志失败不影响分析本身）。
    """
    root = ensure_dirs()
    path = root / "runs" / f"{_stamp()}-{secrets.token_hex(4)}.json"
    return path if _write_json_atomic(path, dict(record or {})) else None


def _create_crash_file(directory: Path) -> tuple[Path, int] | None:
    """用 ``O_CREAT | O_EXCL`` 创建唯一的崩溃快照文件（并发同秒也不覆盖）。

    文件名 = ``<ts>-<pid>-<线程 id>-<4 位随机十六进制>.txt``。撞名时换随机后缀
    重试；**不能**用「先 ``exists()`` 再写」—— 多线程同秒崩溃会全部看到同一个
    不存在的路径，最后只落 1 个文件。

    Args:
        directory: ``crashes/`` 目录（已由 :func:`ensure_dirs` 创建）。

    Returns:
        tuple[Path, int] | None: ``(路径, 已打开的 fd)``；连试 10 次都失败返回 ``None``。
    """
    base = f"{_stamp()}-{os.getpid()}-{threading.get_ident()}"
    for _ in range(10):
        path = directory / f"{base}-{secrets.token_hex(2)}.txt"
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        except OSError:
            return None
        return path, fd
    return None


def record_crash(exc_type, exc, tb) -> Path | None:
    """把一次未捕获异常写成 ``crashes/<ts>-<pid>-<tid>-<rand>.txt``（类型/消息/traceback/环境摘要）。

    Args:
        exc_type: 异常类（``sys.excepthook`` 的第一个参数）。
        exc: 异常实例。
        tb: traceback 对象；为 ``None`` 时退化为「类型: 消息」。

    Returns:
        Path | None: 写成功返回文件路径；写盘失败返回 ``None``。
    """
    root = ensure_dirs()
    opened = _create_crash_file(root / "crashes")
    if opened is None:
        return None
    path, fd = opened
    name = getattr(exc_type, "__name__", str(exc_type))
    message = "" if exc is None else str(exc)
    if tb is not None:
        tb_text = "".join(traceback.format_exception(exc_type, exc, tb)).rstrip()
    else:
        tb_text = f"{name}: {message}"
    env = dict(_ENV_CACHE) or _env_info()
    lines = [
        "=" * 78,
        f"时间: {dt.datetime.now():%Y-%m-%d %H:%M:%S}",
        f"类型: {name}",
        f"消息: {message}",
        "-" * 78,
        tb_text,
        "-" * 78,
        "环境摘要:",
        f"  版本: {env.get('version', '')}",
        f"  Python: {env.get('python_version', '')}",
        f"  系统: {env.get('windows', '')}",
        f"  管理员: {env.get('admin')}",
        f"  Npcap: {env.get('npcap')}",
        f"  tshark: {env.get('tshark_version', '')}",
        f"  tshark 路径: {env.get('tshark_path', '')}",
        f"  控制台编码: {env.get('console_encoding', '')}",
        "=" * 78,
    ]
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return path


# ---------------------------------------------------------------- 异常钩子
def _excepthook(exc_type, exc, tb) -> None:
    """主线程未捕获异常：先写崩溃快照，再交给原钩子（保留控制台输出）。"""
    try:
        record_crash(exc_type, exc, tb)
    except Exception:  # noqa: BLE001
        pass
    original = _HOOKS.get("sys")
    if original is not None and original is not _excepthook:
        try:
            original(exc_type, exc, tb)
        except Exception:  # noqa: BLE001
            pass


def _thread_excepthook(args) -> None:
    """子线程未捕获异常：写崩溃快照后交给原钩子。"""
    try:
        record_crash(args.exc_type, args.exc_value, args.exc_traceback)
    except Exception:  # noqa: BLE001
        pass
    original = _HOOKS.get("thread")
    if original is not None and original is not _thread_excepthook:
        try:
            original(args)
        except Exception:  # noqa: BLE001
            pass


def install_excepthooks() -> None:
    """启用崩溃兜底：``sys.excepthook`` + ``threading.excepthook`` + ``faulthandler``。

    幂等：重复调用只补装缺失的部分。``faulthandler`` 的文件对象保存在模块级变量里，
    否则它会被 GC 回收，进程真崩时什么也写不出来（见 SPEC 陷阱 3）。

    Returns:
        None: 钩子/文件装不上时静默降级，不影响程序运行。
    """
    global _FAULT_FILE
    ensure_dirs()
    if not _HOOKS["installed"]:
        _HOOKS["sys"] = sys.excepthook
        _HOOKS["thread"] = getattr(threading, "excepthook", None)
        sys.excepthook = _excepthook
        if hasattr(threading, "excepthook"):
            threading.excepthook = _thread_excepthook
        _HOOKS["installed"] = True
    if _FAULT_FILE is None:
        try:
            fh = (log_root() / "crashes" / f"fatal-{_stamp()}.log").open(
                "a", encoding="utf-8")
        except OSError:
            return
        try:
            faulthandler.enable(file=fh, all_threads=True)
            _FAULT_FILE = fh
        except (OSError, ValueError, RuntimeError):
            try:
                fh.close()
            except OSError:
                pass


# ---------------------------------------------------------------- 裁剪
def _is_today(path: Path) -> bool:
    """判断文件是不是「今天正在写/刚写的」——总量裁剪要跳过它。"""
    today = _today()
    if today in path.name:
        return True
    if re.search(r"\d{8}", path.name):
        return False  # 名字里带日期但不是今天 → 历史文件，可删
    if path.suffix.lower() in (".log", ".txt") and path.name.startswith(
            ("app", "diag", "fatal")):
        try:
            return dt.date.fromtimestamp(path.stat().st_mtime).strftime("%Y%m%d") == today
        except OSError:
            return True
    return False


def _trim_count(directory: Path, keep: int, suffixes: tuple) -> int:
    """按 mtime（旧的最先删）保留最新 ``keep`` 个；mtime 相同再按文件名兜底。

    不能按文件名字典序：``crashes/`` 里 ``fatal-*.log`` 以字母开头，永远排在
    数字开头的 ``<ts>.txt`` 之后，会把真正的崩溃快照优先删光。
    """
    try:
        files = [p for p in directory.iterdir()
                 if p.is_file() and p.suffix.lower() in suffixes]
    except OSError:
        return 0

    def _age(path: Path) -> tuple:
        try:
            return (path.stat().st_mtime_ns, path.name)
        except OSError:
            return (0, path.name)

    files.sort(key=_age)
    removed = 0
    for path in files[: max(0, len(files) - max(0, int(keep)))]:
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def _iter_log_files(root: Path):
    """列出日志根目录下的日文件（含历史命名 ``app.log`` / ``diag_*.log``）。"""
    for pattern in ("app-*.log", "diag-*.log", "app.log", "diag_*.log"):
        try:
            yield from root.glob(pattern)
        except OSError:
            continue


def _iter_all_files(root: Path):
    """递归列出 ``logs/`` 下所有文件（总量裁剪用）。"""
    try:
        for path in root.rglob("*"):
            if path.is_file():
                yield path
    except OSError:
        return


def prune() -> dict:
    """执行保留策略（启动时调用一次，也可手动跑）。

    顺序：单文件截尾 → ``runs/`` 数量 → ``crashes/`` 数量 → ``logs/`` 总量。
    总量删除按「最旧优先」，并跳过 ``env.json`` / ``netdiag.pid`` / 当天的日志 ——
    **绝不删除正在写的文件**（SPEC V2 / 陷阱 4）。

    Returns:
        dict: ``{"truncated", "removed", "freed_bytes", "total_bytes"}`` 计数摘要。
            单个文件失败只跳过，不抛异常。
    """
    root = ensure_dirs()
    stats = {"truncated": 0, "removed": 0, "freed_bytes": 0, "total_bytes": 0}
    for path in _iter_log_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                if _truncate_tail(path, max(1, MAX_FILE_BYTES // 2)):
                    stats["truncated"] += 1
        except OSError:
            continue
    stats["removed"] += _trim_count(root / "runs", KEEP_RUNS, (".json",))
    stats["removed"] += _trim_count(root / "crashes", KEEP_CRASHES, (".txt", ".log"))
    entries = []
    for path in _iter_all_files(root):
        try:
            entries.append((path.stat().st_mtime, path.name, path, path.stat().st_size))
        except OSError:
            continue
    total = sum(item[3] for item in entries)
    for _mtime, _name, path, size in sorted(entries):
        if total <= MAX_TOTAL_BYTES:
            break
        if path.name in _PROTECTED_NAMES or _is_today(path):
            continue
        try:
            path.unlink()
            total -= size
            stats["removed"] += 1
            stats["freed_bytes"] += size
        except OSError:
            continue
    stats["total_bytes"] = total
    return stats
