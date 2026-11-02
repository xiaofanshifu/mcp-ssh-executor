# ssh-executor MCP

基于 [paramiko](https://www.paramiko.org/) 的 SSH MCP 服务，向 agent 提供远程命令执行、文件上传下载与目录列举。

设计原则：

1. **职责单一**：通用远程执行基础设施，提供命令执行、文件上传、文件下载和目录列举，不承担业务决策。
2. **执行透明**：agent 决定操作内容，MCP 如实执行，准确返回状态、结果和明确错误，不隐式修改操作意图。
3. **数据完整**：保证远程输出与文件可完整获取，不静默截断或丢弃数据。
4. **最小充分**：实现优雅、合理，不引入不必要的配置、抽象、开关和防御性分支。
5. **操作审计**：记录所有操作及其结果，包括失败和异常，不记录密码、私钥等认证秘密。

## 能力

| 工具              | 作用                                           |
| --------------- | -------------------------------------------- |
| `ssh_exec`      | 执行 shell 命令，返回 `exit_code` + STDOUT + STDERR |
| `sftp_upload`   | 上传文件或整棵目录树，先写 `.part` 再原子替换                  |
| `sftp_download` | 下载文件或整棵目录树，同上                                |
| `sftp_list`     | 列目录（只读），按时间/名称/大小排序，默认全量                     |

## 输出与数据完整性

命令输出不做内容裁剪：

| 输出大小    | 交付方式                                                    |
| ------- | ------------------------------------------------------- |
| ≤ 64 KB | 全文直接返回                                                  |
| > 64 KB | 完整落盘到 `%TEMP%\ssh_mcp_output\`，返回统计、8 KB 预览与 `out_path` |

落盘不设大小上限。文件是 stdout 的原始字节流，可直接 MD5 比对；磁盘写满时返回文件系统错误，已写入的部分保留在 `out_path`。

二进制输出（含 NUL 或非法 UTF-8）一律落盘不内联，避免替换字符破坏内容。

64 KB 取自客户端单次工具结果的上限：更大的返回体会被客户端转存，正文反而不可见。需要单次放宽时传 `inline_limit`（正数字节数，负数表示只回路径）。

## 超时

三个参数语义不同，不要混用：

| 参数                | 含义                       | 默认 |
| ----------------- | ------------------------ | -- |
| `timeout`         | **空闲**超时：连续这么多秒没有新输出才判失败 | 30 |
| `connect_timeout` | 建立连接、建立 channel 的超时      | 10 |
| `max_runtime`     | 命令总时长上限，0 表示不限           | 0  |

命令整段重定向到文件（`... > /tmp/x 2>&1`）时，本次调用在命令结束前收不到任何输出，必须加大 `timeout`，或改为后台执行后轮询。

## 认证

优先级：`password` → `key_path` → SSH agent / `~/.ssh/id_*`。

传了 `password` 时会禁用 agent 与密钥查找，paramiko 不会读取本机任何私钥文件。

## 目录传输

上传与下载都按原目录名落到目标路径下：`a` 传到 `/opt` → `/opt/a`。

- 空目录会一并创建。
- 符号链接、fifo、socket、设备文件无法通过 SFTP 传输，列在结果的 `[skip]` 行和 `skipped` 字段中，不静默丢弃。
- 目标路径必须已存在，工具不替你创建顶层目录。

## 审计

每次调用向脚本同目录的 `audit.jsonl` 追加一条 JSON，记录动作、主机、用户、状态、耗时、错误类型与命令。成功、失败、异常、参数校验失败都会入账。

口令不入库；命令中的凭据（`--password`、`mysql -p`、`curl -u`、Bearer、URL 内嵌密码等）按值脱敏。文件满 10 MB 轮转，保留约 200 MB。

## 安装与配置

```bash
pip install -r requirements.txt
```

### workbuddy

在 `~/.workbuddy/mcp.json`（Windows 为 `%USERPROFILE%\.workbuddy\mcp.json`）中注册：

```json
{
  "mcpServers": {
    "ssh-executor": {
      "command": "C:\\path\\to\\python.exe",
      "args": ["C:\\path\\to\\mcp-ssh-executor\\ssh_mcp_server.py"]
    }
  }
}
```

保存后在连接器管理页的「自定义连接器」中对该服务点「信任」。

### opencode

注册

```sh
opencode mcp add ssh-executor --global -- "C:\path\to\python.exe" "C:\path\to\mcp-ssh-executor\ssh_mcp_server.py"
```

`--global` 写入用户级配置（`~/.config/opencode/opencode.json`），去掉则写入当前项目的 `opencode.json`。

验证连接

```sh
opencode mcp list
```

## 已知边界

- 落盘文件在系统临时目录，由系统重启时清理，MCP 不做清理或数量控制。
- 超时只断开连接，不终止远端进程：静默命令可能继续跑到自然结束。长任务请用 `nohup` 后台化，或超时后自行 `pgrep` / `kill` 清理。
- 主机密钥采用 `AutoAddPolicy`，首次连接自动信任，不做指纹校验。
