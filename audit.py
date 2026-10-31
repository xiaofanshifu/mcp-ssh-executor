"""audit.py — 结构化审计日志（JSON Lines，分段轮转 + 值级脱敏）。

设计原则：
- 每次 exec / SFTP 操作落一条 JSON 记录，便于事后追溯。
- 容量：活动文件 audit.jsonl 满 10 MB 后改名为 audit.<6 位序号>.jsonl，
  活动文件 + 归档段合计 MAX_FILES(20) 个，约 200 MB；超出时静默删除序号最小的归档。
- 文件锁：Windows 上若活动文件被其他进程持有（os.replace 会失败），
  自动改道写 audit.spill.jsonl，待主文件可轮转后归位，避免单文件无限增长。
- 可观测：轮转/写入失败不再静默吞掉，同一类错误首次出现时向 stderr 告警一次。
- 安全：绝不记录口令。除按 key 过滤外，对字段值做正则脱敏
  （--password=、sshpass/mysql/redis-cli 的 -p/-a、Bearer、*_TOKEN=、URL 内嵌密码、X-Api-Key 等）。
- 崩溃安全：每条 append 后立即 flush + fsync。
"""
import dataclasses
import datetime
import json
import os
import re
import sys
import threading
import time

if os.name == "nt":
    import msvcrt

    def _flock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

    def _funlock(fd: int) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _flock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _funlock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_PATH = os.path.join(BASE_DIR, "audit.jsonl")
SPILL_PATH = os.path.join(BASE_DIR, "audit.spill.jsonl")
LOCK_PATH = os.path.join(BASE_DIR, "audit.lock")   # 跨进程互斥用，非数据文件

SCHEMA_VERSION = 1             # 记录结构版本，字段演进时递增
MAX_BYTES = 10 * 1024 * 1024   # 单文件 10 MB
MAX_FILES = 20                 # 活动文件 + 19 个归档段 ≈ 200 MB
ARCHIVE_FMT = "audit.{:06d}.jsonl"
_ARCHIVE_RE = re.compile(r"^audit\.(\d{6})\.jsonl$")

# 这些 key 一旦出现在记录里就被丢弃（双保险；正常调用本就不传 password）
_SECRET_KEYS = {
    "password", "passwd", "secret", "token",
    "key", "keyref", "keydata", "keyfile", "private_key",
}

# 值级脱敏：按「宁可多遮，不漏凭据」处理常见命令行凭据形态
_REDACT_RULES = (
    # --password=xxx / -password xxx / --passwd xxx
    (re.compile(r"(?i)((?:^|\s)--?(?:password|passwd|pass)(?:=|\s+))(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1***"),
    # Authorization: Bearer/Basic/Token xxx
    (re.compile(r"(?i)((?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic|token)\s+)[^\s\"']+"),
     r"\1***"),
    # 裸 Bearer xxx
    (re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9\-._~+/=]{8,}"), r"\1***"),
    # 敏感变量赋值：XXX_TOKEN=yyy / XXX_SECRET=yyy / API_KEY=yyy
    (re.compile(r"(?i)(\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY"
                r"|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*\s*=\s*)(\"[^\"]*\"|'[^']*'|[^\s;|&]+)"),
     r"\1***"),
    # URL 内嵌凭据：scheme://user:pass@host
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:)[^\s@/]+(@)"), r"\1***\2"),
    # X-Api-Key / X-Auth-Token / X-Access-Token
    (re.compile(r"(?i)((?:x-api-key|x-auth-token|x-access-token)\s*:\s*)[^\s\"']+"), r"\1***"),
    # curl --user / --proxy-user：值整体遮蔽
    (re.compile(r"(?i)((?:^|\s)--(?:user|proxy-user)(?:=|\s+))(\"[^\"]*\"|'[^']*'|[^\s\"']+)"),
     r"\1***"),
    # curl -u user:pass：只遮蔽含冒号的值，避免误伤 sort -u / uniq -u
    (re.compile(r"(?i)((?:^|\s)-u\s+)([^\s:]+:[^\s]+)"), r"\1***"),
)

# 只有这些命令的 -p/-a 才是口令；其他命令（mkdir -p、cp -p、tar -p、ssh -p 22）不得误伤
_SECRET_FLAG_BINS = {
    "sshpass": ("-p",),
    "mysqldump": ("-p",),
    "mariadb-dump": ("-p",),
    "mysqladmin": ("-p",),
    "mariadb": ("-p",),
    "mysql": ("-p",),
    "redis-cli": ("-a",),
}
_FLAG_BIN_RE = re.compile(r"(?i)\b(" + "|".join(_SECRET_FLAG_BINS) + r")\b")
_SEGMENT_RE = re.compile(r"(\|\||&&|;|\n)")


def _redact_flag_secrets(text: str) -> str:
    """仅在 sshpass / mysql / redis-cli 等命令的片段内脱敏 -p / -a 的值。"""
    parts = _SEGMENT_RE.split(text)
    for i, seg in enumerate(parts):
        m = _FLAG_BIN_RE.search(seg)
        if not m:
            continue
        for flag in _SECRET_FLAG_BINS[m.group(1).lower()]:
            seg = re.sub(r"(?i)((?:^|\s)" + re.escape(flag) + r")\s*(\"[^\"]*\"|'[^']*'|\S+)",
                         r"\1 ***", seg)
        parts[i] = seg
    return "".join(parts)


_LOCK = threading.RLock()
_state = {"active": AUDIT_PATH}
_warned = set()


def _now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")


def _warn(tag: str, exc: BaseException) -> None:
    """同类告警只报一次，避免刷屏；写 stderr（不占用 MCP 的 stdout 通道）。"""
    if tag in _warned:
        return
    _warned.add(tag)
    try:
        print(f"[audit] {tag} 失败，已降级：{type(exc).__name__}: {exc}", file=sys.stderr)
    except Exception:
        pass


def _redact(value):
    """递归脱敏：丢弃敏感 key，对字符串值套用凭据正则。"""
    if isinstance(value, str):
        value = _redact_flag_secrets(value)
        for pat, repl in _REDACT_RULES:
            value = pat.sub(repl, value)
        return value
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()
                if str(k).lower() not in _SECRET_KEYS}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


def _size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _archives():
    """返回 [(seq, path)]，按 seq 升序。"""
    out = []
    try:
        for name in os.listdir(BASE_DIR):
            m = _ARCHIVE_RE.match(name)
            if m:
                out.append((int(m.group(1)), os.path.join(BASE_DIR, name)))
    except OSError as e:
        _warn("scan", e)
    out.sort()
    return out


def _next_seq() -> int:
    arcs = _archives()
    return arcs[-1][0] + 1 if arcs else 1


def _rotate(path: str) -> bool:
    """把 path 改名为下一个序号的归档段。成功 True；失败（多为文件被占用）False。"""
    dst = os.path.join(BASE_DIR, ARCHIVE_FMT.format(_next_seq()))
    try:
        os.replace(path, dst)
        return True
    except OSError as e:
        _warn("rotate", e)
        return False


def _prune() -> None:
    """归档段总数不超过 MAX_FILES-1，静默删除最旧的；删不掉（被占用）则跳过。"""
    arcs = _archives()
    excess = len(arcs) - (MAX_FILES - 1)
    if excess <= 0:
        return
    for _seq, path in arcs[:excess]:
        try:
            os.remove(path)
        except OSError as e:
            _warn("prune", e)


def _select_active() -> str:
    """决定本轮写入哪个文件，并保证任何活动文件都不越过 MAX_BYTES。"""
    if _size(AUDIT_PATH) >= MAX_BYTES:
        if _rotate(AUDIT_PATH):
            _prune()
            _state["active"] = AUDIT_PATH
        elif _state["active"] == AUDIT_PATH:
            # 主文件被外部进程占用：改道 spill，避免其继续膨胀
            _state["active"] = SPILL_PATH
    elif _state["active"] != AUDIT_PATH:
        _state["active"] = AUDIT_PATH

    if _state["active"] == SPILL_PATH and _size(SPILL_PATH) >= MAX_BYTES:
        if _rotate(SPILL_PATH):
            _prune()
    return _state["active"]


@dataclasses.dataclass
class AuditEvent:
    """一条审计事件。用数据类承载，避免手拼 dict 造成字段重复或拼写漂移。"""
    action: str
    host: str
    user: str
    port: int
    status: str
    trace: str = ""
    fields: dict = dataclasses.field(default_factory=dict)


def _write(rec: dict) -> None:
    """落盘一条记录；写失败不打断主流程，但会告警一次。

    多实例并发写同一文件必须串行：Windows 的 "a" 模式是 seek+write 模拟，
    两个进程定位到同一位置会互相覆盖（实测 1000 条丢 22 条）。用独立锁文件
    做跨进程互斥，锁固定在第 0 字节，与数据文件长度无关。
    """
    line = json.dumps(_redact(rec), ensure_ascii=False, default=str)
    with _LOCK:
        path = _select_active()
        fd = None
        for attempt in range(4):         # 锁文件本身也可能被并发打开，短暂重试
            try:
                fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR)
                break
            except OSError:
                if attempt == 3:
                    _warn("lock", OSError("审计锁文件忙，跳过本条"))
                    return
                time.sleep(0.003 * (attempt + 1))
        try:
            _flock(fd)
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                _funlock(fd)
        except OSError as e:
            _warn("write", e)
        finally:
            os.close(fd)


def audit_event(ev: AuditEvent) -> None:
    """写入一个审计事件。基础字段不会被 fields 覆盖。"""
    rec = {
        "v": SCHEMA_VERSION,
        "ts": _now(),
        "action": ev.action,
        "host": ev.host,
        "user": ev.user,
        "port": ev.port,
        "status": ev.status,
    }
    if ev.trace:
        rec["trace"] = ev.trace
    for k, val in (ev.fields or {}).items():
        if k not in rec:
            rec[k] = val
    _write(rec)


def audit(action: str, host: str, user: str, port, status: str, **fields) -> None:
    """兼容旧调用方式；内部转成 AuditEvent。trace 可经 fields 传入。"""
    trace = fields.pop("trace", "")
    audit_event(AuditEvent(action, host, user, port, status, trace, fields))
