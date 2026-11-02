"""ssh-executor MCP：SSH 命令执行、SFTP 文件传输、目录列举与审计。

工具：ssh_exec / sftp_upload / sftp_download / sftp_list，参数说明见各自的 docstring。
返回 content（人读文本）与 structuredContent（机器解析，恒含 text 与 ok）。
"""
import atexit
import codecs
import collections
import dataclasses
import datetime
import errno
import hashlib
import os
import posixpath
import stat as statmod
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import anyio
import paramiko
from fastmcp import Context, FastMCP
from fastmcp.tools import ToolResult

from audit import AuditEvent, audit, audit_event

mcp = FastMCP("ssh")

_CMD_CLIP = 2000              # 审计中命令最大保留长度
_ERR_CLIP = 1000              # 审计与返回体中错误信息最大保留长度
# 内联上限取自客户端单次工具结果的上限：实测 64 KB 以上会被转存、正文不可见。
# 超过即完整落盘（原始字节，可校验）；需要单次放宽时传 inline_limit。
_MAX_STDOUT = int(os.environ.get("SSH_MCP_INLINE_STDOUT", 64 * 1024))         # 内联上限
_MAX_STDERR = int(os.environ.get("SSH_MCP_INLINE_STDERR", 64 * 1024))
_OUTPUT_DIR = os.environ.get("SSH_MCP_OUTPUT_DIR") or os.path.join(
    tempfile.gettempdir(), "ssh_mcp_output")
_OUTPUT_PREVIEW = 8192        # 回给模型的预览长度
_POLL_INTERVAL = 0.005        # 通道轮询间隔（秒）
_EXIT_WAIT = 5                # 输出收完后等待退出码的上限（秒）；命令已结束，通常瞬时返回
_XFER_CHUNK = 262144          # 传输分块大小（字节）
_DIR_WORKERS = 8              # 目录递归时的并发度；实测 8 比 4 快约 26%，再高会接近 sshd MaxStartups

# 连接复用（可用环境变量覆盖）
_IDLE_TTL = float(os.environ.get("SSH_MCP_IDLE_TTL", "300"))
_KEEPALIVE = int(os.environ.get("SSH_MCP_KEEPALIVE", "30"))
_MAX_IDLE_PER_KEY = 8         # 与目录并发度匹配；池比并发小会反复建连，实测拖慢约 10%
_SWEEP_INTERVAL = 30

_EXISTS_POLICIES = ("overwrite", "skip", "backup", "rename", "error")


class _RemotePathError(Exception):
    """远端/本地路径不满足前置条件（例如目标目录不存在）。消息本身即为用户可读提示。"""


# ---------------------------------------------------------------- 通用工具

def _clip(s, n):
    s = str(s)
    return s if len(s) <= n else s[:n] + f"...(+{len(s) - n} chars)"


def _new_trace() -> str:
    return "t" + os.urandom(3).hex()


def _fmt_mtime(ts):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return "unknown"


def _iso_ts(epoch):
    try:
        return datetime.datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")
    except Exception:
        return None


def _human_size(n) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{int(v)} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024.0
    return f"{v:.1f} TB"


def _speed_kbps(size, dur_ms):
    try:
        if not dur_ms or dur_ms <= 0:
            return None
        return round(float(size) / (dur_ms / 1000.0) / 1024.0, 1)
    except Exception:
        return None


def _elapsed_ms(t0) -> float:
    return max(round((time.time() - t0) * 1000, 2), 0.01)


def _res(text: str, data: dict | None = None) -> ToolResult:
    """content 给人读，structuredContent 给程序解析；正文同时进结构化结果。

    不设 isError：主流客户端在该字段为真时会抛异常并跳过 structuredContent，
    反而丢掉 error_type、trace 和超时前的输出。失败一律用 ok/status 表达。
    """
    payload = dict(data or {})
    payload.setdefault("text", text)
    return ToolResult(content=text, structured_content=payload)


def _fail(text: str, error, *, error_type: str = "", trace: str = "",
          status: str = "error", started: float | None = None, **extra) -> ToolResult:
    """统一的失败返回：可读文本 + 结构化错误字段。

    error 接受异常对象或字符串；超长按 _ERR_CLIP 截断，避免回灌巨量文本。
    """
    kind = error_type or (type(error).__name__ if isinstance(error, BaseException) else "Error")
    payload = {
        "ok": False,
        "status": status,
        "error_type": kind,
        "error": _clip(error, _ERR_CLIP),
        "trace": trace,
    }
    if started is not None:
        payload["duration_ms"] = int((time.time() - started) * 1000)
    payload.update(extra)
    return _res(text, payload)


def _audit_error(action, host, user, port, trace, error_type, message, **extra) -> None:
    """失败路径统一落审计：动作、主机、状态、错误类型与文本。

    参数校验失败同样入账，不只记录真正发出请求的调用。
    参数名用 error_type 而非 kind，避免与调用方传入的 kind="dir" 冲突。
    """
    audit(action, host, user, port, "error", trace=trace,
          error_type=error_type, error=_clip(message, _ERR_CLIP), **extra)


def _file_error(kind: str, message: str, trace: str = "", status: str = "error",
                **extra) -> dict:
    """单文件/目录传输的结构化错误字段（由外层 _res 组装成 ToolResult）。"""
    data = {"ok": False, "status": status, "error_type": kind,
            "error": _clip(message, _ERR_CLIP), "trace": trace}
    data.update(extra)
    return data


def _progress(ctx, done, total):
    """上报进度：目录传输每完成一个文件调用一次。

    客户端不支持 progressToken、或当前线程不是 anyio 工作线程时静默跳过，
    进度失败绝不影响传输本身。
    """
    if ctx is None:
        return
    try:
        anyio.from_thread.run(ctx.report_progress, done, total)
    except Exception:
        pass


def _progress_cb(ctx):
    """单文件传输的 callback，按百分比上报（节流到每 1% 一次）。

    传 (百分比, 100)，客户端显示即为 45/100 这类形式。
    """
    if ctx is None:
        return None
    state = {"pct": -1}

    def cb(done, total):
        try:
            if not total:
                return
            pct = int(done * 100 / total)
            if pct != state["pct"]:
                state["pct"] = pct
                _progress(ctx, pct, 100)
        except Exception:
            pass

    return cb


# ---------------------------------------------------------------- 审计

@dataclasses.dataclass
class FileOp:
    """一次文件操作的审计字段。"""
    direction: str
    src: str
    dst: str
    file: str = ""
    rel: str = ""
    size: int = 0
    size_human: str = ""
    if_exists: str = "overwrite"
    local_path: str = ""
    remote_path: str = ""
    target: str = ""
    backup: str | None = None
    src_mtime: str | None = None
    connect_ms: float | None = None
    transfer_ms: float | None = None
    speed_kbps: float | None = None
    duration_ms: int | None = None
    error_type: str = ""
    error: str = ""
    existing_bytes: int | None = None


def _audit_file(action, host, user, port, status, trace, op: FileOp) -> None:
    fields = dataclasses.asdict(op)
    for k in ("rel", "backup", "error_type", "error", "src_mtime"):
        if not fields.get(k):
            fields.pop(k, None)
    audit_event(AuditEvent(action, host, user, port, status, trace, fields))


def _audit_file_safe(*args, **kwargs):
    try:
        _audit_file(*args, **kwargs)
    except Exception:
        pass


# ---------------------------------------------------------------- 路径

def _remote_stat(sftp, path):
    """取远端属性；只有"不存在"返回 None，权限不足等其他错误照常抛出。

    吞掉全部 OSError 会把"权限不足"误报成"目录不存在，请先创建"。
    """
    try:
        return sftp.stat(path)
    except (IOError, OSError) as e:
        if getattr(e, "errno", None) == errno.ENOENT:
            return None
        raise


def _require_remote_dir(sftp, path):
    """目标目录必须已存在，不替调用方创建。"""
    st = _remote_stat(sftp, path)
    if st is None:
        raise _RemotePathError(f"目标目录不存在: {path}（请先在服务器创建）")
    if not statmod.S_ISDIR(st.st_mode):
        raise _RemotePathError(f"目标路径不是目录: {path}")


def _ensure_remote_dir(sftp, path):
    """逐级创建远端目录（用于目标目录之下与源同名的层级）。"""
    if path in ("", ".", "/"):
        return
    absolute = path.startswith("/")
    cur = "/" if absolute else ""
    for part in [p for p in path.split("/") if p and p != "."]:
        if cur in ("", "/"):
            cur = ("/" + part) if absolute else part
        else:
            cur = posixpath.join(cur, part)
        if _remote_stat(sftp, cur) is None:
            try:
                sftp.mkdir(cur)
            except (IOError, OSError):
                pass


def _next_free_name(sftp, base):
    if _remote_stat(sftp, base) is None:
        return base
    for i in range(1, 1000):
        cand = f"{base}.{i}"
        if _remote_stat(sftp, cand) is None:
            return cand
    raise RuntimeError(f"找不到可用的远端文件名（基于 {base}）")


def _next_free_local(base):
    if not os.path.exists(base):
        return base
    for i in range(1, 1000):
        cand = f"{base}.{i}"
        if not os.path.exists(cand):
            return cand
    raise RuntimeError(f"找不到可用的本地文件名（基于 {base}）")


def _atomic_replace(sftp, src, dst):
    """优先 posix-rename（真原子），不支持时退化为 remove + rename。"""
    try:
        sftp.posix_rename(src, dst)
        return
    except (IOError, OSError):
        pass
    try:
        sftp.remove(dst)
    except (IOError, OSError):
        pass
    sftp.rename(src, dst)


def _walk_local(root: str):
    """递归列出本地内容，返回 (files, dirs, skipped)。

    files:   [(abs_path, rel_posix)]
    dirs:    [rel_posix]，含空目录
    skipped: [(rel_posix, 原因)]，符号链接、fifo、socket、设备等

    用 lstat 判类型：fifo 被当成普通文件读取会永久阻塞，必须识别出来。
    """
    files, dirs, skipped = [], [], []

    def _walk_err(e):
        # os.walk 默认忽略 listdir 失败，不可读子目录会被静默跳过
        rel = os.path.relpath(e.filename, root).replace(os.sep, "/") if e.filename else "."
        skipped.append((rel, f"无法读取目录（{type(e).__name__}）"))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=_walk_err):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if rel_dir != ".":
            dirs.append(rel_dir)
        for d in list(dirnames):
            ap = os.path.join(dirpath, d)
            if os.path.islink(ap):
                dirnames.remove(d)        # 链接目录不进入，也不建空目录
                skipped.append((os.path.relpath(ap, root).replace(os.sep, "/"), "符号链接"))
        for fn in sorted(filenames):
            ap = os.path.join(dirpath, fn)
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            try:
                mode = os.lstat(ap).st_mode
            except OSError as e:
                skipped.append((rel, f"无法读取（{type(e).__name__}）"))
                continue
            if statmod.S_ISREG(mode):
                files.append((ap, rel))
            elif statmod.S_ISLNK(mode):
                skipped.append((rel, "符号链接"))
            else:
                skipped.append((rel, "特殊文件"))
    return files, dirs, skipped


def _walk_remote(sftp, root: str):
    """递归列出远端内容，返回 (files, dirs, skipped)。

    files:   [(abs_path, rel_posix, size, mtime)]
    dirs:    [rel_posix]，含空目录
    skipped: [(rel_posix, 原因)]，符号链接、fifo、socket、设备等
    """
    files, dirs, skipped = [], [], []
    stack = [("", root)]
    while stack:
        rel, path = stack.pop()
        for a in sftp.listdir_attr(path):
            name = a.filename
            child_rel = posixpath.join(rel, name) if rel else name
            child_abs = posixpath.join(path, name)
            if statmod.S_ISDIR(a.st_mode):
                dirs.append(child_rel)
                stack.append((child_rel, child_abs))
            elif statmod.S_ISREG(a.st_mode):
                files.append((child_abs, child_rel, a.st_size or 0, a.st_mtime))
            elif statmod.S_ISLNK(a.st_mode):
                skipped.append((child_rel, "符号链接"))
            else:
                skipped.append((child_rel, "特殊文件"))
    files.sort(key=lambda x: x[1])
    dirs.sort()
    skipped.sort()
    return files, dirs, skipped


def _render_skipped(skipped) -> list:
    """把无法通过 SFTP 传输的条目转成可读行；空列表返回空。"""
    if not skipped:
        return []
    return ([f"跳过 {len(skipped)} 项（SFTP 无法传输）："]
            + [f"[skip] {rel}  {why}" for rel, why in skipped])


def _safe_local(root: str, rel: str) -> bool:
    """rel 拼到 root 之下是否仍在 root 内；跨盘符或含 .. 判为越界。"""
    base = os.path.abspath(root)
    try:
        target = os.path.abspath(os.path.join(base, str(rel).replace("/", os.sep)))
        return os.path.commonpath([base, target]) == base
    except ValueError:            # Windows 不同盘符无法比较
        return False


# ---------------------------------------------------------------- 连接

def _connect(host: str, port: int, user: str, password: str, key_path: str,
             timeout: int) -> paramiko.SSHClient:
    """认证优先级：password → key_path 指定的私钥 → agent / ~/.ssh/id_*。"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if password:
        client.connect(hostname=host, port=port, username=user, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
    elif key_path:
        client.connect(hostname=host, port=port, username=user,
                       key_filename=os.path.expanduser(key_path),
                       timeout=timeout, allow_agent=False, look_for_keys=False)
    else:
        client.connect(hostname=host, port=port, username=user, timeout=timeout,
                       allow_agent=True, look_for_keys=True)
    try:
        client.get_transport().set_keepalive(_KEEPALIVE)
    except Exception:
        pass
    return client


def _healthy(client) -> bool:
    try:
        t = client.get_transport()
        return bool(t and t.is_active() and t.is_authenticated())
    except Exception:
        return False


def _safe_close(client):
    if client is None:
        return
    try:
        client.close()
    except Exception:
        pass


class _ConnPool:
    """按 (host, port, user, 凭据摘要) 复用已认证连接；借出独占，空闲超时回收。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._idle = {}
        threading.Thread(target=self._sweep, daemon=True).start()

    @staticmethod
    def _key(host, port, user, password, key_path):
        if password:
            tag = "p:" + hashlib.sha256(password.encode("utf-8")).hexdigest()[:12]
        elif key_path:
            tag = "k:" + hashlib.sha256(os.path.abspath(key_path).encode("utf-8")).hexdigest()[:12]
        else:
            tag = "-"
        return (host, int(port), user, tag)

    def acquire(self, host, port, user, password, key_path, timeout):
        """返回 (client, key, reused)。"""
        key = self._key(host, port, user, password, key_path)
        while True:
            with self._lock:
                bucket = self._idle.get(key)
                if not bucket:
                    break
                client, _ts = bucket.popleft()
                if not bucket:
                    self._idle.pop(key, None)
            if _healthy(client):
                return client, key, True
            _safe_close(client)
        return _connect(host, port, user, password, key_path, timeout), key, False

    def release(self, client, key, reusable=True):
        if client is None:
            return
        if not reusable or not _healthy(client):
            _safe_close(client)
            return
        with self._lock:
            bucket = self._idle.setdefault(key, collections.deque())
            if len(bucket) < _MAX_IDLE_PER_KEY:
                bucket.append((client, time.monotonic()))
                return
        _safe_close(client)

    def close_all(self):
        with self._lock:
            buckets = list(self._idle.values())
            self._idle.clear()
        for bucket in buckets:
            for client, _ts in bucket:
                _safe_close(client)

    def stats(self):
        with self._lock:
            return {"keys": len(self._idle),
                    "idle": sum(len(b) for b in self._idle.values()),
                    "idle_ttl": _IDLE_TTL}

    def _sweep(self):
        while True:
            time.sleep(_SWEEP_INTERVAL)
            self.sweep_once()

    def sweep_once(self):
        now = time.monotonic()
        expired = []
        with self._lock:
            for key in list(self._idle):
                bucket = self._idle[key]
                keep = collections.deque()
                while bucket:
                    client, ts = bucket.popleft()
                    if now - ts > _IDLE_TTL:
                        expired.append(client)
                    else:
                        keep.append((client, ts))
                if keep:
                    self._idle[key] = keep
                else:
                    self._idle.pop(key, None)
        for client in expired:
            _safe_close(client)


_POOL = _ConnPool()
atexit.register(_POOL.close_all)


def _sftp_connect(host, port, user, password, key_path, timeout):
    """返回 (client, sftp, key, reused)。"""
    client, key, reused = _POOL.acquire(host, port, user, password, key_path, timeout)
    try:
        return client, client.open_sftp(), key, reused
    except Exception:
        _POOL.release(client, key, reusable=False)
        raise


def _release(client, key, sftp=None, reusable=True):
    if sftp is not None:
        try:
            sftp.close()
        except Exception:
            pass
    _POOL.release(client, key, reusable)


# ---------------------------------------------------------------- 单文件传输

def _upload_file(host, local_file, remote_dir, user, port, password, key_path,
                 timeout, if_exists, trace, rel="", ctx=None):
    """上传一个文件到 remote_dir 下（文件名保持不变）。返回 (ok, 文本, 明细)。"""
    client = sftp = key = None
    start = time.time()
    name = os.path.basename(local_file)
    target = posixpath.join(remote_dir, name)
    op = FileOp(direction="upload", src=f"local:{local_file}",
                dst=f"{user}@{host}:{target}", file=name, rel=rel,
                local_path=local_file, remote_path=target,
                if_exists=if_exists)
    if if_exists not in _EXISTS_POLICIES:
        msg = f"if_exists 取值无效：{if_exists}"
        _audit_file_safe("sftp_upload", host, user, port, "error", trace, op)
        return False, f"ERROR: {msg}", _file_error("ValueError", msg, trace)

    try:
        nbytes = os.path.getsize(local_file)
        mtime = os.path.getmtime(local_file)
    except OSError as e:
        # walk 之后文件可能被删，别让它裸抛到调用方
        msg = f"无法读取本地文件 {local_file}: {e}"
        _audit_file_safe("sftp_upload", host, user, port, "error", trace, op)
        return False, f"ERROR: {msg}", _file_error("OSError", msg, trace)
    op.size = nbytes
    op.size_human = _human_size(nbytes)
    op.src_mtime = _iso_ts(mtime)
    part = None
    try:
        client, sftp, key, reused = _sftp_connect(host, port, user, password, key_path, timeout)
        op.connect_ms = _elapsed_ms(start)
        _require_remote_dir(sftp, remote_dir)
        saved_as = None
        existing = _remote_stat(sftp, target)
        if existing is not None:
            op.existing_bytes = existing.st_size
            old = f"{existing.st_size} 字节，mtime {_fmt_mtime(existing.st_mtime)}"
            if if_exists == "skip":
                _audit_file_safe("sftp_upload", host, user, port, "skipped", trace, op)
                return False, f"SKIP: 远端已存在 {target}（{old}），按 skip 未覆盖", \
                    {"ok": False, "status": "skipped", "skipped": True,
                     "reason": "remote_exists", "trace": trace,
                     "error_type": "Skipped", "error": f"远端已存在 {target}"}
            if if_exists == "error":
                _audit_file_safe("sftp_upload", host, user, port, "conflict", trace, op)
                msg = f"ERROR: 远端已存在 {target}（{old}），按 error 中止"
                return False, msg, _file_error("RemoteExists", msg, trace, status="conflict")
            if if_exists == "backup":
                saved_as = _next_free_name(sftp, f"{target}.bak")
                sftp.rename(target, saved_as)
                op.backup = saved_as
            elif if_exists == "rename":
                target = _next_free_name(sftp, target)
                op.target = target
                op.dst = f"{user}@{host}:{target}"

        t_xfer = time.time()
        part = f"{target}.part"
        sftp.put(local_file, part, callback=_progress_cb(ctx))   # confirm=True 会校验大小
        _atomic_replace(sftp, part, target)
        part = None
        op.transfer_ms = _elapsed_ms(t_xfer)
        op.duration_ms = int((time.time() - start) * 1000)
        op.speed_kbps = _speed_kbps(nbytes, op.transfer_ms)
        op.target = target
        _audit_file_safe("sftp_upload", host, user, port, "ok", trace, op)
        extra = ""
        if saved_as:
            extra += f"；原文件备份为 {saved_as}"
        if target != posixpath.join(remote_dir, name):
            extra += f"；目标已存在，实际写入 {target}"
        msg = f"OK: 上传 {local_file} -> {target}（{_human_size(nbytes)}，{op.duration_ms} ms）{extra}"
        return True, msg, {
            "ok": True, "kind": "file", "direction": "upload", "file": name, "rel": rel,
            "size": nbytes, "src": op.src, "dst": op.dst, "target": target,
            "duration_ms": op.duration_ms, "trace": trace,
        }
    except _RemotePathError as e:
        op.error_type = "RemotePathError"
        op.error = str(e)
        op.duration_ms = int((time.time() - start) * 1000)
        _audit_file_safe("sftp_upload", host, user, port, "error", trace, op)
        return False, f"ERROR: {e}", _file_error("RemotePathError", str(e), trace)
    except Exception as e:
        if part and sftp is not None:
            try:
                sftp.remove(part)
            except Exception:
                pass
        op.error_type = type(e).__name__
        op.error = _clip(e, _ERR_CLIP)
        op.duration_ms = int((time.time() - start) * 1000)
        _audit_file_safe("sftp_upload", host, user, port, "error", trace, op)
        return False, f"ERROR: {type(e).__name__}: {e}", \
            _file_error(type(e).__name__, str(e), trace)
    finally:
        _release(client, key, sftp)


def _download_file(host, remote_file, local_dir, user, port, password, key_path,
                   timeout, if_exists, trace, rel="", ctx=None, conn=None):
    """下载一个远端文件到 local_dir 下（文件名保持不变）。返回 (ok, 文本, 明细)。

    conn 传入 (client, sftp, key) 时复用已有连接（释放责任归调用方），
    避免为判断"文件还是目录"再建一次连接。
    """
    client = sftp = key = None
    owns_conn = conn is None
    if conn is not None:
        client, sftp, key = conn
    start = time.time()
    name = posixpath.basename(remote_file)
    # 远端文件名可能是 \evil / D:evil / ..，在 Windows 上会写出目标目录
    if not name or name in (".", "..") or not _safe_local(local_dir, name):
        msg = f"文件名越界，已拒绝: {remote_file}"
        _audit_error("sftp_download", host, user, port, trace, "BadName", msg, remote_path=remote_file)
        return False, f"ERROR: {msg}", _file_error("BadName", msg, trace)
    target = os.path.join(local_dir, name)
    op = FileOp(direction="download", src=f"{user}@{host}:{remote_file}",
                dst=f"local:{target}", file=name, rel=rel,
                local_path=target, remote_path=remote_file,
                if_exists=if_exists)
    if if_exists not in _EXISTS_POLICIES:
        msg = f"if_exists 取值无效：{if_exists}"
        _audit_file_safe("sftp_download", host, user, port, "error", trace, op)
        return False, f"ERROR: {msg}", _file_error("ValueError", msg, trace)

    try:
        if owns_conn:
            client, sftp, key, _reused = _sftp_connect(host, port, user, password, key_path, timeout)
            op.connect_ms = _elapsed_ms(start)
        else:
            op.connect_ms = 0.0
        st = sftp.stat(remote_file)
        size = st.st_size
        op.size = size
        op.size_human = _human_size(size)
        op.src_mtime = _iso_ts(st.st_mtime)
        saved_as = None
        if os.path.exists(target):
            op.existing_bytes = os.path.getsize(target)
            old = f"{op.existing_bytes} 字节"
            if if_exists == "skip":
                _audit_file_safe("sftp_download", host, user, port, "skipped", trace, op)
                return False, f"SKIP: 本地已存在 {target}（{old}），按 skip 未下载", \
                    {"ok": False, "status": "skipped", "skipped": True,
                     "reason": "local_exists", "trace": trace,
                     "error_type": "Skipped", "error": f"本地已存在 {target}"}
            if if_exists == "error":
                _audit_file_safe("sftp_download", host, user, port, "conflict", trace, op)
                msg = f"ERROR: 本地已存在 {target}（{old}），按 error 中止"
                return False, msg, _file_error("LocalExists", msg, trace, status="conflict")
            if if_exists == "backup":
                saved_as = _next_free_local(f"{target}.bak")
                os.replace(target, saved_as)
                op.backup = saved_as
            elif if_exists == "rename":
                target = _next_free_local(target)
                op.target = target
                op.dst = f"local:{target}"

        t_xfer = time.time()
        part = f"{target}.part"
        try:
            sftp.get(remote_file, part, callback=_progress_cb(ctx))
            got = os.path.getsize(part)
            if got != size:          # 服务端提前 EOF 时会静默留下截断文件
                raise IOError(f"传输不完整：期望 {size} 字节，实际 {got} 字节")
            os.replace(part, target)
        except Exception:
            try:
                os.remove(part)
            except OSError:
                pass
            raise
        op.transfer_ms = _elapsed_ms(t_xfer)
        op.duration_ms = int((time.time() - start) * 1000)
        op.speed_kbps = _speed_kbps(size, op.transfer_ms)
        op.target = target
        _audit_file_safe("sftp_download", host, user, port, "ok", trace, op)
        extra = ""
        if saved_as:
            extra += f"；原文件备份为 {saved_as}"
        if target != os.path.join(local_dir, name):
            extra += f"；本地已存在，实际写入 {target}"
        msg = f"OK: 下载 {remote_file} -> {target}（{_human_size(size)}，{op.duration_ms} ms）{extra}"
        return True, msg, {
            "ok": True, "kind": "file", "direction": "download", "file": name, "rel": rel,
            "size": size, "src": op.src, "dst": op.dst, "target": target,
            "duration_ms": op.duration_ms, "trace": trace,
        }
    except _RemotePathError as e:
        op.error_type = "RemotePathError"
        op.error = str(e)
        op.duration_ms = int((time.time() - start) * 1000)
        _audit_file_safe("sftp_download", host, user, port, "error", trace, op)
        return False, f"ERROR: {e}", _file_error("RemotePathError", str(e), trace)
    except Exception as e:
        op.error_type = type(e).__name__
        op.error = _clip(e, _ERR_CLIP)
        op.duration_ms = int((time.time() - start) * 1000)
        _audit_file_safe("sftp_download", host, user, port, "error", trace, op)
        return False, f"ERROR: {type(e).__name__}: {e}", \
            _file_error(type(e).__name__, str(e), trace)
    finally:
        if owns_conn:
            _release(client, key, sftp)


# ---------------------------------------------------------------- 目录传输

def _upload_tree(host, local_dir, remote_dir, user, port, password, key_path,
                 timeout, if_exists, trace, ctx=None):
    """把 local_dir 整棵目录树传到 remote_dir/<目录名>/ 下。

    目录结构（含空目录）一并创建；符号链接、fifo、socket、设备等无法通过 SFTP
    表达，记入 skipped 并在结果与审计里列出，不做静默丢弃。
    """
    files, dirs, skipped = _walk_local(local_dir)

    src_name = os.path.basename(os.path.normpath(local_dir))
    if not src_name:                     # 本地目录是盘根时 basename 为空，会少一层
        msg = f"本地目录名无效，请指定具体目录: {local_dir}"
        _audit_error("sftp_upload", host, user, port, trace, "BadDirName", msg,
                     local_path=local_dir)
        return _fail(f"ERROR: {msg}", msg, error_type="BadDirName", trace=trace)
    dest_root = posixpath.join(remote_dir.rstrip("/") or "/", src_name)
    client = sftp = key = None
    created = False
    try:
        client, sftp, key, _reused = _sftp_connect(host, port, user, password, key_path, timeout)
        _require_remote_dir(sftp, remote_dir)
        created = _remote_stat(sftp, dest_root) is None
        _ensure_remote_dir(sftp, dest_root)
        for d in dirs:
            _ensure_remote_dir(sftp, posixpath.join(dest_root, d))
    except _RemotePathError as e:
        _release(client, key, sftp)
        _audit_error("sftp_upload", host, user, port, trace, "RemotePathError", str(e), kind="dir")
        return _fail(f"ERROR: {e}", e, error_type="RemotePathError", trace=trace)
    except Exception as e:
        _release(client, key, sftp)
        _audit_error("sftp_upload", host, user, port, trace, type(e).__name__, str(e), kind="dir")
        return _fail(f"ERROR: {type(e).__name__}: {e}", e,
                     error_type=type(e).__name__, trace=trace)
    _release(client, key, sftp)

    start = time.time()

    def task(item):
        ap, rel = item
        return ap, _upload_file(host, ap, posixpath.join(dest_root, posixpath.dirname(rel)),
                                user, port, password, key_path, timeout,
                                if_exists, trace, rel)

    rows = []
    with ThreadPoolExecutor(max_workers=_DIR_WORKERS) as ex:
        for src, res in ex.map(task, files):
            rows.append((src, res))
            _progress(ctx, len(rows), len(files))
    dur = int((time.time() - start) * 1000)
    okn = sum(1 for _s, (ok, _m, _i) in rows if ok)
    badn = len(rows) - okn
    total = sum(i.get("size", 0) for _s, (ok, _m, i) in rows if ok and i)
    audit("sftp_upload", host, user, port, "ok" if badn == 0 else "partial",
          trace=trace, kind="dir", src=f"local:{local_dir}",
          dst=f"{user}@{host}:{dest_root}", target=dest_root, created_root=created,
          files=len(rows), dirs=len(dirs), succeeded=okn, failed=badn,
          skipped=len(skipped), skipped_items=[r for r, _w in skipped][:50],
          total_bytes=total, total_human=_human_size(total), duration_ms=dur)

    lines = [f"OK: 上传目录 {local_dir} -> {dest_root}（{len(rows)} 个文件，"
             f"{_human_size(total)}，{dur} ms）"]
    if created:
        lines.append(f"（已创建目标目录 {dest_root}）")
    if dirs:
        lines.append(f"（含 {len(dirs)} 个子目录）")
    items = []
    for src, (ok, msg, info) in rows:
        rel = os.path.relpath(src, local_dir).replace(os.sep, "/")
        items.append({"rel": rel, "ok": ok, "size": (info or {}).get("size"),
                      "error": None if ok else msg})
        lines.append(f"[ok]   {rel}" if ok else f"[fail] {rel}  {msg}")
    if badn:
        lines.append(f"失败 {badn} 个")
    lines.extend(_render_skipped(skipped))
    return _res("\n".join(lines), {
        "ok": badn == 0, "kind": "dir", "direction": "upload",
        "src": f"local:{local_dir}", "dst": f"{user}@{host}:{dest_root}",
        "target": dest_root, "created_root": created,
        "files": len(rows), "dirs": len(dirs), "succeeded": okn, "failed": badn,
        "skipped": [{"rel": r, "reason": w} for r, w in skipped],
        "total_bytes": total, "duration_ms": dur, "trace": trace, "items": items,
    })


def _download_tree(host, remote_dir, local_dir, user, port, password, key_path,
                   timeout, if_exists, trace, ctx=None):
    """把远端目录树下载到 local_dir/<目录名>/ 下。"""
    client = sftp = key = None
    try:
        client, sftp, key, _reused = _sftp_connect(host, port, user, password, key_path, timeout)
        try:
            _require_remote_dir(sftp, remote_dir)
            files, dirs, skipped = _walk_remote(sftp, remote_dir)
        except _RemotePathError as e:
            _audit_error("sftp_download", host, user, port, trace, "RemotePathError", str(e), kind="dir")
            return _fail(f"ERROR: {e}", e, error_type="RemotePathError", trace=trace)
        except Exception as e:
            _audit_error("sftp_download", host, user, port, trace, type(e).__name__, str(e), kind="dir")
            return _fail(f"ERROR: 读取远端目录失败: {type(e).__name__}: {e}", e,
                         error_type=type(e).__name__, trace=trace)
    except Exception as e:
        _audit_error("sftp_download", host, user, port, trace, type(e).__name__, str(e), kind="dir")
        return _fail(f"ERROR: 连接失败: {type(e).__name__}: {e}", e,
                     error_type=type(e).__name__, trace=trace)
    finally:
        _release(client, key, sftp)

    # 先归一化：/tmp/x/child/.. 与 /tmp/x 指向同一目录，直接取 basename 会得到 ".."
    dir_name = posixpath.basename(posixpath.normpath(remote_dir))
    # posix 不认反斜杠，目录名 ..\evil 归一化后仍是 ..\evil，必须再按本地路径规则校验
    if (not dir_name or dir_name in (".", "..")
            or not _safe_local(local_dir, dir_name)):
        msg = f"远端目录名无效，已拒绝: {remote_dir}"
        _audit_error("sftp_download", host, user, port, trace, "BadDirName", msg,
                     remote_path=remote_dir)
        return _fail(f"ERROR: {msg}", msg, error_type="BadDirName", trace=trace)
    dest_root = os.path.join(local_dir, dir_name)
    try:
        os.makedirs(dest_root, exist_ok=True)
        for d in list(dirs):             # 空目录也要在本地建出来
            if not _safe_local(dest_root, d):
                dirs.remove(d)
                skipped.append((d, "路径越界"))
                continue
            os.makedirs(os.path.join(dest_root, d.replace("/", os.sep)), exist_ok=True)
    except OSError as e:                 # 目标已存在同名文件等情况，别裸抛
        _audit_error("sftp_download", host, user, port, trace, type(e).__name__, str(e), kind="dir")
        return _fail(f"ERROR: 无法创建本地目录 {dest_root}: {e}", e,
                     error_type=type(e).__name__, trace=trace)

    start = time.time()

    # 传输前统一过滤：越界项与本地路径碰撞项进 skipped，不参与并发下载。
    # Windows 大小写不敏感，Linux 的 A.txt / a.txt 会映射到同一个本地文件，
    # 并发写会互相覆盖、且两边都报成功。
    seen = {}
    unique = []
    for item in files:
        _abs, rel, _sz, _mt = item
        if not _safe_local(dest_root, rel):
            skipped.append((rel, "路径越界"))
            continue
        key = os.path.normcase(os.path.abspath(
            os.path.join(dest_root, rel.replace("/", os.sep))))
        if key in seen:
            skipped.append((rel, f"与 {seen[key]} 在本地映射到同一路径"))
            continue
        seen[key] = rel
        unique.append(item)
    files = unique

    def task(item):
        abs_path, rel, _sz, _mt = item
        lp = os.path.join(dest_root, os.path.dirname(rel).replace("/", os.sep))
        return rel, _download_file(host, abs_path, lp, user, port, password, key_path,
                                   timeout, if_exists, trace, rel)

    rows = []
    with ThreadPoolExecutor(max_workers=_DIR_WORKERS) as ex:
        for rel, res in ex.map(task, files):
            rows.append((rel, res))
            _progress(ctx, len(rows), len(files))
    dur = int((time.time() - start) * 1000)
    okn = sum(1 for _r, (ok, _m, _i) in rows if ok)
    badn = len(rows) - okn
    total = sum(i.get("size", 0) for _r, (ok, _m, i) in rows if ok and i)
    audit("sftp_download", host, user, port, "ok" if badn == 0 else "partial",
          trace=trace, kind="dir", src=f"{user}@{host}:{remote_dir}",
          dst=f"local:{dest_root}", target=dest_root,
          files=len(rows), dirs=len(dirs), succeeded=okn, failed=badn,
          skipped=len(skipped), skipped_items=[r for r, _w in skipped][:50],
          total_bytes=total, total_human=_human_size(total), duration_ms=dur)

    lines = [f"OK: 下载目录 {remote_dir} -> {dest_root}（{len(rows)} 个文件，"
             f"{_human_size(total)}，{dur} ms）"]
    if dirs:
        lines.append(f"（含 {len(dirs)} 个子目录）")
    items = []
    for rel, (ok, msg, info) in rows:
        items.append({"rel": rel, "ok": ok, "size": (info or {}).get("size"),
                      "error": None if ok else msg})
        lines.append(f"[ok]   {rel}" if ok else f"[fail] {rel}  {msg}")
    if badn:
        lines.append(f"失败 {badn} 个")
    lines.extend(_render_skipped(skipped))
    return _res("\n".join(lines), {
        "ok": badn == 0, "kind": "dir", "direction": "download",
        "src": f"{user}@{host}:{remote_dir}", "dst": f"local:{dest_root}",
        "target": dest_root, "files": len(rows), "dirs": len(dirs),
        "succeeded": okn, "failed": badn,
        "skipped": [{"rel": r, "reason": w} for r, w in skipped],
        "total_bytes": total, "duration_ms": dur, "trace": trace, "items": items,
    })


# ---------------------------------------------------------------- 输出接收

class _OutputSink:
    """单流输出缓冲：未超内联上限就留在内存，超出即整段落盘，不丢字节。

    二进制输出一律落盘且不内联：用 replace 解码会把非 UTF-8 字节替换成 U+FFFD，
    原始字节既没返回也没保存，等于静默丢数据。检测到 NUL 或非法 UTF-8 时立即
    转为落盘，返回 binary 标记与文件路径，由调用方自行处理。
    """

    def __init__(self, name, inline_limit, out_dir, trace):
        self.name = name
        self.inline_limit = max(int(inline_limit), 0)
        self.out_dir = out_dir
        self.trace = trace
        self.buf = bytearray()     # 前 inline_limit 字节，用于内联或预览
        self.total = 0             # 远端共产出字节
        self.lines = 0
        self.saved = 0             # 已落盘字节
        self.binary = False        # 已判定为非文本
        self.path = None
        self._fh = None
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")

    def feed(self, chunk):
        if not chunk:
            return
        self.total += len(chunk)
        self.lines += chunk.count(b"\n")

        if not self.binary:
            if b"\x00" in chunk:
                self.binary = True
            elif self._fh is None:
                # 增量解码能正确处理跨块的多字节字符，不会误判为二进制
                try:
                    self._decoder.decode(chunk)
                except UnicodeDecodeError:
                    self.binary = True
            if self.binary:
                self._open()          # 已进 buf 的部分一并落盘，不留丢失窗口
                self._write(chunk)
                return

        if self._fh is not None:
            self._write(chunk)
            return
        if self.total <= self.inline_limit:
            self.buf.extend(chunk)
            return

        room = self.inline_limit - len(self.buf)   # 跨过上限：先补齐预览，再切写盘
        if room > 0:
            self.buf.extend(chunk[:room])
            chunk = chunk[room:]
        self._open()
        self._write(chunk)

    def _open(self):
        if self._fh is not None:
            return
        os.makedirs(self.out_dir, exist_ok=True)
        path = os.path.join(self.out_dir, f"{self.trace}-{self.name}.log")
        self._fh = open(path, "wb")
        self.path = path
        if self.buf:
            self._fh.write(self.buf)
            self.saved = len(self.buf)

    def _write(self, chunk):
        self._fh.write(chunk)
        self.saved += len(chunk)

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    @property
    def spilled(self):
        return self.path is not None

    def finish(self):
        """收尾：缓冲里若残留未完成的 UTF-8 序列，判定为二进制并整段落盘。

        增量解码器遇到"合法开头但不完整"的序列（如单个 \\xe4）不会报错，只是
        等待后续字节。流结束时若不 finalize，这段字节会被 _decode_prefix 当作
        截断尾巴切掉，既没内联也没落盘，是一次静默的数据丢失。
        """
        if self.binary or self._fh is not None:
            return
        try:
            self._decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            self.binary = True
            self._open()          # buf 里的原始字节整段落盘

    def text(self):
        """内联正文。二进制返回空串，避免把替换字符当作内容交给调用方。"""
        if self.binary:
            return ""
        return _decode_prefix(bytes(self.buf))

    def stats(self, prefix: str) -> dict:
        """结构化统计字段；stdout/stderr 共用同一套命名，只换前缀。"""
        return {
            f"{prefix}_bytes": self.total,
            f"{prefix}_newlines": self.lines,
            f"{prefix}_binary": self.binary,
            f"{prefix}_path": self.path,
            f"{prefix}_saved_bytes": self.saved,
            f"{prefix}_spilled": self.spilled,
        }


def _decode_prefix(data):
    """按 UTF-8 解码；尾部被切断的字符丢 1~3 字节，避免出现替换符。"""
    for cut in range(4):
        try:
            return data[:len(data) - cut].decode("utf-8") if cut else data.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _preview_bytes(sink) -> bytes:
    """取前 _OUTPUT_PREVIEW 字节，尽量在行边界截断。"""
    head = bytes(sink.buf[:_OUTPUT_PREVIEW])
    if len(sink.buf) > _OUTPUT_PREVIEW:
        cut = head.rfind(b"\n")
        if cut > _OUTPUT_PREVIEW // 2:
            head = head[:cut + 1]
    return head


def _render_stream(label, sink):
    """把一路输出转成可读段落。"""
    if not sink.total:
        return f"{label}: (空)"
    if sink.binary:
        return (f"{label}: 二进制输出，共 {sink.total} 字节，未内联，"
                f"完整内容已保存到 {sink.path}")
    if not sink.spilled:
        return f"{label}:\n{sink.text()}"

    note = f"{label} 共 {sink.total} 字节，完整内容已保存到 {sink.path}"
    head = _preview_bytes(sink)
    if not head:
        return note + "（本次未内联正文，请直接读取该文件）"
    return (f"{note}：\n{_decode_prefix(head)}"
            f"\n[预览到此为止，其余内容用 Read/Grep 从上面的文件读取]")


def _stream_text(sink):
    """结构化结果里的单流正文：未落盘给全部缓冲，已落盘只给预览，二进制不给。"""
    if not sink.total or sink.binary:
        return ""
    return sink.text() if not sink.spilled else _decode_prefix(_preview_bytes(sink))


def _streams_payload(out_sink, err_sink) -> dict:
    """两路正文与统计字段；成功、超时、异常三个出口共用，避免重复拼装。"""
    return {
        "stdout": _stream_text(out_sink), "stderr": _stream_text(err_sink),
        **out_sink.stats("out"), **err_sink.stats("err"),
    }


# ---------------------------------------------------------------- 命令执行

class _ExecTimeout(TimeoutError):
    """命令超时。已收输出由调用方持有的 sink 承载，异常本身只说明原因。"""

    def __init__(self, message, reason):
        super().__init__(message)
        self.reason = reason        # "idle"（长时间无输出）| "max_runtime"（超过总时长）


def _open_channel(client, command, timeout):
    """建立 channel 并下发命令。timeout 只约束 channel 建立，不约束命令执行。"""
    _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
    return stdout.channel


def _drain(chan, idle_timeout, out, err, max_runtime=0):
    """并发读取 stdout / stderr 并喂给调用方提供的 sink。

    交替读避免 stderr 先塞满通道窗口把远端写阻塞。超时分两种，语义不同：
    - idle_timeout：连续这么多秒没有任何新数据就判超时（静默阶段的等待预算）；
    - max_runtime：整条命令的总时长上限，>0 才生效（持续输出命令的最后一道闸）。

    sink 由调用方创建并持有：连接中断、写盘失败、超时等任何出口，调用方都能
    拿到已收输出并渲染，不存在"数据随异常一起丢失"的路径。
    """
    idle_until = time.monotonic() + idle_timeout
    deadline = time.monotonic() + max_runtime if max_runtime > 0 else None

    def _over_deadline():
        # 放在读取循环内部：远端持续高速输出时，外层检查根本轮不到
        if deadline is not None and time.monotonic() >= deadline:
            raise _ExecTimeout(
                f"命令总运行时间超过 max_runtime={max_runtime}s，已停止读取",
                "max_runtime")

    try:
        while True:
            busy = False
            while chan.recv_ready():
                chunk = chan.recv(65536)
                if not chunk:
                    break
                busy = True
                out.feed(chunk)
                _over_deadline()
            while chan.recv_stderr_ready():
                chunk = chan.recv_stderr(65536)
                if not chunk:
                    break
                busy = True
                err.feed(chunk)
                _over_deadline()

            if busy:
                idle_until = time.monotonic() + idle_timeout

            if not chan.recv_ready() and not chan.recv_stderr_ready():
                if chan.exit_status_ready() or chan.eof_received or chan.closed:
                    break
            _over_deadline()
            if not busy:
                if time.monotonic() >= idle_until:
                    raise _ExecTimeout(
                        f"等待远端输出超时（{idle_timeout}s 内无新数据）",
                        "idle")
                time.sleep(_POLL_INTERVAL)
    finally:
        # 必须在返回前收尾：调用方随后组装的响应与审计才能看到最终状态
        # （finish 可能把缓冲里的半个 UTF-8 序列判定为二进制并落盘）
        out.finish()
        err.finish()


# ---------------------------------------------------------------- 工具

@mcp.tool()
def ssh_exec(host: str, command: str, user: str = "root", port: int = 22,
             password: str = "", key_path: str = "", timeout: int = 30,
             connect_timeout: int = 10, max_runtime: int = 0,
             inline_limit: int = 0) -> ToolResult:
    """在远程服务器上执行 shell 命令，返回 exit_code、stdout、stderr。

    输出不截断：超过内联上限（stdout/stderr 默认各 64 KB）即整段落盘，此时回
    统计、8 KB 预览与 out_path。落盘文件是原始字节流，可 MD5 校验；读多少、
    怎么读（Read / Grep / 再下发远端命令）由调用方决定。磁盘写不下时返回
    文件系统错误，已写入部分保留在 out_path。

    超时语义（与 sftp_* 的 timeout 不同，后者是连接超时）：
    - timeout 是**空闲**超时：连续这么多秒没有任何新输出才判失败，不是命令总时长；
    - connect_timeout 只约束建立连接；
    - max_runtime 是总时长上限，默认 0 表示不限，用于兜住持续输出的命令。

    静默命令的陷阱：命令整段重定向到文件（如 `... > /tmp/x 2>&1`）时，
    本次调用在命令结束前收不到任何输出，必须显式加大 timeout，
    或改成后台执行（nohup ... &）后轮询结果。

    :param host: 服务器 IP 或域名
    :param command: 要执行的命令，例如 'df -h'
    :param user: 登录用户名，默认 root
    :param port: SSH 端口，默认 22
    :param password: 登录密码；留空则用私钥登录
    :param key_path: 私钥文件路径；password 为空时使用，留空则用 SSH agent 或 ~/.ssh/id_*
    :param timeout: 空闲超时秒数，默认 30；连续无输出超过该值即失败
    :param connect_timeout: 建立连接的超时秒数，默认 10
    :param max_runtime: 命令总时长上限秒数，默认 0（不限）；触发后停止读取并丢弃连接
    :param inline_limit: stdout 内联上限（字节）；0 用默认，负数只回路径不内联
    """
    trace = _new_trace()
    if inline_limit == 0:
        out_limit = _MAX_STDOUT
    elif inline_limit < 0:
        out_limit = 0
    else:
        out_limit = inline_limit
    out_sink = _OutputSink("stdout", out_limit, _OUTPUT_DIR, trace)
    err_sink = _OutputSink("stderr", _MAX_STDERR, _OUTPUT_DIR, trace)
    client = key = chan = None
    reused = False
    conn_ok = False          # 只有拿到明确退出码才把连接放回池子
    start = time.time()
    try:
        client, key, reused = _POOL.acquire(host, port, user, password, key_path, connect_timeout)
        # channel 建立用 connect_timeout；timeout 只作为之后读输出的空闲预算。
        # 不自动重试：exec_command 可能已把请求发出去，重发会让命令执行两次。
        chan = _open_channel(client, command, connect_timeout)

        _drain(chan, timeout, out_sink, err_sink, max_runtime)
        code = chan.exit_status if chan.status_event.wait(_EXIT_WAIT) else None
        conn_ok = code is not None
        dur = int((time.time() - start) * 1000)
        status = "ok" if code == 0 else ("nonzero" if code is not None else "unknown")
        audit("exec", host, user, port, status, trace=trace,
              command=_clip(command, _CMD_CLIP), exit_code=code, duration_ms=dur,
              out_bytes=out_sink.total, err_bytes=err_sink.total,
              out_newlines=out_sink.lines, err_newlines=err_sink.lines,
              out_saved=out_sink.saved, err_saved=err_sink.saved,
              out_path=out_sink.path, err_path=err_sink.path,
              conn_reused=reused)
        shown = code if code is not None else "unknown"
        text = "\n".join([f"exit_code: {shown}",
                          _render_stream("STDOUT", out_sink),
                          _render_stream("STDERR", err_sink)])
        data = {
            "ok": code == 0, "exit_code": code, "status": status,
            **_streams_payload(out_sink, err_sink),
            "duration_ms": dur, "conn_reused": reused, "trace": trace,
        }
        # code 为 None 表示命令结束但拿不到退出码，用 status=unknown 表达
        return _res(text, data)
    except _ExecTimeout as e:
        dur = int((time.time() - start) * 1000)
        hint = ("命令连续没有新输出：加大 timeout，或改为后台执行后轮询。"
                if e.reason == "idle" else
                "已超过 max_runtime：长任务改为后台执行后轮询。")
        hint += "断开连接不会终止远端进程，必要时用 pgrep/kill 清理。"
        audit("exec", host, user, port, "timeout", trace=trace,
              command=_clip(command, _CMD_CLIP), timed_out=True,
              timeout_reason=e.reason,
              error_type="TimeoutError", error=_clip(e, _ERR_CLIP), duration_ms=dur,
              out_bytes=out_sink.total, err_bytes=err_sink.total,
              out_path=out_sink.path, err_path=err_sink.path,
              conn_reused=reused)
        text = "\n".join([
            f"ERROR: TimeoutError: {e}",
            f"提示: {hint}",
            _render_stream("STDOUT（超时前已收到）", out_sink),
            _render_stream("STDERR（超时前已收到）", err_sink),
        ])
        return _res(text, {
            "ok": False, "status": "timeout", "timed_out": True,
            "timeout_reason": e.reason,
            "error_type": "TimeoutError", "error": _clip(e, _ERR_CLIP),
            **_streams_payload(out_sink, err_sink),
            "duration_ms": dur, "conn_reused": reused, "trace": trace,
        })
    except Exception as e:
        timed_out = isinstance(e, TimeoutError)
        auth = isinstance(e, paramiko.ssh_exception.AuthenticationException)
        kind = "AuthenticationException" if auth else type(e).__name__
        head = (f"ERROR: 认证失败（密码错误或密钥不可用）: {e}" if auth
                else f"ERROR: {kind}: {e}")
        dur = int((time.time() - start) * 1000)
        audit("exec", host, user, port, "timeout" if timed_out else "error", trace=trace,
              command=_clip(command, _CMD_CLIP), timed_out=timed_out,
              error_type=kind, error=_clip(e, _ERR_CLIP), duration_ms=dur,
              out_bytes=out_sink.total, err_bytes=err_sink.total,
              out_saved=out_sink.saved, err_saved=err_sink.saved,
              out_path=out_sink.path, err_path=err_sink.path,
              conn_reused=reused)
        # 连接中断、写盘失败等通用异常：已收输出照样回传，不随异常丢弃
        text = "\n".join([
            head,
            _render_stream("STDOUT（异常前已收到）", out_sink),
            _render_stream("STDERR（异常前已收到）", err_sink),
        ])
        return _fail(text, e, error_type=kind, trace=trace,
                     status="timeout" if timed_out else "error",
                     started=start, timed_out=timed_out,
                     **_streams_payload(out_sink, err_sink),
                     conn_reused=reused)
    finally:
        out_sink.close()
        err_sink.close()
        if not conn_ok:
            # 未拿到退出码：先关 channel 发 EOF，再由 release(reusable=False) 关 transport。
            # 先关 channel 再关 transport：断开连接不能保证终止远端进程，
            # 这里只是尽快释放本地资源。
            if chan is not None:
                try:
                    chan.close()
                except Exception:
                    pass
        _POOL.release(client, key, reusable=conn_ok)


@mcp.tool()
def sftp_upload(host: str, local_path: str, remote_path: str, user: str = "root",
                port: int = 22, password: str = "", key_path: str = "",
                timeout: int = 120, if_exists: str = "overwrite",
                ctx: Context = None) -> ToolResult:
    """把本地文件或目录上传到远程服务器。

    本地路径是文件时上传该文件，是目录时递归上传整棵目录树。
    remote_path 是目标目录（必须已存在），源的名字会保留在它下面：
    a 传到 /opt → /opt/a；bb 传到 /root → /root/bb/…。
    写入采用先传 .part 再原子替换，中断不会破坏远端既有文件。
    进度：单文件按百分比（0–100）上报，目录按已完成文件数上报；客户端支持 progressToken 时可见。

    :param host: 服务器 IP 或域名
    :param local_path: 本地文件或目录路径
    :param remote_path: 远端目标目录（须已存在）
    :param user: 登录用户名，默认 root
    :param port: SSH 端口，默认 22
    :param password: 登录密码；留空则用私钥登录
    :param key_path: 私钥文件路径；password 为空时使用
    :param timeout: 连接超时秒数，默认 120
    :param if_exists: 远端同名文件的处理：overwrite（默认）/ skip / backup / rename / error
    """
    trace = _new_trace()
    if if_exists not in _EXISTS_POLICIES:
        # 入口先校验：空目录树没有文件经过单文件层，放在那里会漏
        msg = f"if_exists 取值无效：{if_exists}"
        _audit_error("sftp_upload", host, user, port, trace, "ValueError", msg)
        return _fail(f"ERROR: {msg}", msg, error_type="ValueError", trace=trace)
    if not os.path.exists(local_path):
        _audit_error("sftp_upload", host, user, port, trace, "LocalNotFound",
                     f"本地路径不存在: {local_path}", local_path=local_path)
        return _fail(f"ERROR: 本地路径不存在: {local_path}",
                     f"本地路径不存在: {local_path}",
                     error_type="LocalNotFound", trace=trace)
    if os.path.isdir(local_path):
        return _upload_tree(host, local_path, remote_path, user, port, password,
                            key_path, timeout, if_exists, trace, ctx)
    if not os.path.isfile(local_path):
        _audit_error("sftp_upload", host, user, port, trace, "NotAFile",
                     f"不是普通文件或目录: {local_path}", local_path=local_path)
        return _fail(f"ERROR: 不是普通文件或目录: {local_path}",
                     f"不是普通文件或目录: {local_path}",
                     error_type="NotAFile", trace=trace)
    _ok, msg, info = _upload_file(host, local_path, remote_path, user, port, password,
                                  key_path, timeout, if_exists, trace, "", ctx)
    return _res(msg, info or {"ok": False, "direction": "upload", "trace": trace})


@mcp.tool()
def sftp_download(host: str, remote_path: str, local_path: str, user: str = "root",
                  port: int = 22, password: str = "", key_path: str = "",
                  timeout: int = 120, if_exists: str = "overwrite",
                  ctx: Context = None) -> ToolResult:
    """把远端文件或目录下载到本地。

    远端路径是文件时下载该文件，是目录时递归下载整棵目录树。
    local_path 是本地目标目录（必须已存在），源的名字会保留在它下面：
    /opt/a 下载到 D:\\tmp → D:\\tmp\\a；/root/bb 下载到 D:\\tmp → D:\\tmp\\bb\\…
    写入采用先写 .part 再原子替换，中断不会破坏本地既有文件。
    进度：单文件按百分比（0–100）上报，目录按已完成文件数上报；客户端支持 progressToken 时可见。

    :param host: 服务器 IP 或域名
    :param remote_path: 远端文件或目录路径
    :param local_path: 本地目标目录（须已存在）
    :param user: 登录用户名，默认 root
    :param port: SSH 端口，默认 22
    :param password: 登录密码；留空则用私钥登录
    :param key_path: 私钥文件路径；password 为空时使用
    :param timeout: 连接超时秒数，默认 120
    :param if_exists: 本地同名文件的处理：overwrite（默认）/ skip / backup / rename / error
    """
    trace = _new_trace()
    if if_exists not in _EXISTS_POLICIES:
        msg = f"if_exists 取值无效：{if_exists}"
        _audit_error("sftp_download", host, user, port, trace, "ValueError", msg)
        return _fail(f"ERROR: {msg}", msg, error_type="ValueError", trace=trace)
    if not os.path.isdir(local_path):
        _audit_error("sftp_download", host, user, port, trace, "LocalDirNotFound",
                     f"本地目标目录不存在: {local_path}", local_path=local_path)
        return _fail(f"ERROR: 本地目标目录不存在: {local_path}（请先创建）",
                     f"本地目标目录不存在: {local_path}",
                     error_type="LocalDirNotFound", trace=trace)

    client = sftp = key = None
    try:
        client, sftp, key, _reused = _sftp_connect(host, port, user, password, key_path, timeout)
        st = _remote_stat(sftp, remote_path)
    except Exception as e:
        _release(client, key, sftp)
        _audit_error("sftp_download", host, user, port, trace, type(e).__name__, str(e),
                     remote_path=remote_path)
        return _fail(f"ERROR: {type(e).__name__}: {e}", e,
                     error_type=type(e).__name__, trace=trace)

    if st is None:
        _release(client, key, sftp)
        _audit_error("sftp_download", host, user, port, trace, "RemoteNotFound",
                     f"远端路径不存在: {remote_path}", remote_path=remote_path)
        return _fail(f"ERROR: 远端路径不存在: {remote_path}",
                     f"远端路径不存在: {remote_path}",
                     error_type="RemoteNotFound", trace=trace)
    if statmod.S_ISDIR(st.st_mode):
        _release(client, key, sftp)      # 目录传输并发借连接，先归还
        return _download_tree(host, remote_path, local_path, user, port, password,
                              key_path, timeout, if_exists, trace, ctx)

    try:
        _ok, msg, info = _download_file(host, remote_path, local_path, user, port, password,
                                        key_path, timeout, if_exists, trace, "", ctx,
                                        conn=(client, sftp, key))
    finally:
        _release(client, key, sftp)
    return _res(msg, info or {"ok": False, "direction": "download", "trace": trace})


@mcp.tool()
def sftp_list(host: str, remote_path: str = ".", user: str = "root", port: int = 22,
              password: str = "", key_path: str = "", timeout: int = 10,
              max_entries: int = 0, sort_by: str = "time",
              descending: bool = True) -> ToolResult:
    """列出远端目录内容（只读）。

    :param host: 服务器 IP 或域名
    :param remote_path: 远端目录，默认当前目录
    :param user: 登录用户名，默认 root
    :param port: SSH 端口，默认 22
    :param password: 登录密码；留空则用私钥登录
    :param key_path: 私钥文件路径；password 为空时使用
    :param timeout: 连接超时秒数，默认 10
    :param max_entries: 最多返回条数；默认 0 表示全部，需要限制时传正数
    :param sort_by: 排序依据：time（默认）/ name / size
    :param descending: True 为降序（默认，最新在前）
    """
    trace = _new_trace()
    if sort_by not in ("time", "name", "size"):
        _audit_error("sftp_list", host, user, port, trace, "BadSortBy",
                     f"sort_by 取值无效：{sort_by}", remote_path=remote_path)
        return _fail(f"ERROR: sort_by 取值无效：{sort_by}（可选 time/name/size）",
                     f"sort_by 取值无效：{sort_by}",
                     error_type="BadSortBy", trace=trace)
    client = sftp = key = None
    start = time.time()
    try:
        client, sftp, key, reused = _sftp_connect(host, port, user, password, key_path, timeout)
        attrs = sftp.listdir_attr(remote_path)
        entries = [(a.filename, getattr(a, "st_size", None),
                    getattr(a, "st_mode", None), getattr(a, "st_mtime", None))
                   for a in attrs]

        if sort_by == "name":
            entries.sort(key=lambda e: (e[0] or "").lower(), reverse=descending)
        elif sort_by == "size":
            entries.sort(key=lambda e: (e[1] if e[1] is not None else -1), reverse=descending)
        else:
            entries.sort(key=lambda e: (e[3] if e[3] is not None else 0), reverse=descending)

        total = len(entries)
        shown = entries if max_entries <= 0 else entries[:max_entries]
        dur = int((time.time() - start) * 1000)
        audit("sftp_list", host, user, port, "ok", trace=trace, remote_path=remote_path,
              entries=total, shown=len(shown), duration_ms=dur,
              sort_by=sort_by, descending=descending, conn_reused=reused)
        lines = []
        items = []
        for name, size, mode, mtime in shown:
            if mode is not None and statmod.S_ISDIR(mode):
                t = "d"
            elif mode is not None and statmod.S_ISLNK(mode):
                t = "l"
            else:
                t = "-"
            sz = "" if size is None else f"{size:>10}"
            ts = _fmt_mtime(mtime) if mtime else "-"
            lines.append(f"{t} {ts:19} {sz}  {name}")
            items.append({"name": name, "type": t, "size": size,
                          "mtime": _iso_ts(mtime) if mtime else None})
        order = "降序" if descending else "升序"
        head = f"（共 {total} 条，显示前 {len(shown)} 条，按 {sort_by} {order}）" \
            if total > len(shown) else f"（共 {total} 条，按 {sort_by} {order}）"
        return _res(f"目录 {remote_path}:\n{head}\n" + "\n".join(lines), {
            "ok": True, "path": remote_path, "total": total, "shown": len(shown),
            "sort_by": sort_by, "descending": descending, "entries": items,
            "duration_ms": dur, "trace": trace,
        })
    except Exception as e:
        audit("sftp_list", host, user, port, "error", trace=trace, remote_path=remote_path,
              error_type=type(e).__name__, error=_clip(e, _ERR_CLIP))
        return _fail(f"ERROR: {type(e).__name__}: {e}", e,
                     error_type=type(e).__name__, trace=trace, started=start,
                     remote_path=remote_path)
    finally:
        _release(client, key, sftp)


if __name__ == "__main__":
    mcp.run()
