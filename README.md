# Ruijie Campus Auth HXxy

一个面向 Windows 和 Linux 的锐捷校园网认证实验项目，同时提供命令行和 Python API。

> **当前状态：协议分析中，尚不能替代学校原版客户端。** 2026-09-23 使用真实测试
> 账号完成了“原版注销、确认断网、pip 安装、Python API 登录、再次检测网络”的完整
> 回归。Python 客户端能完成网卡选择、Identity 和标准 EAP-MD5，但服务器随后返回
> EAP-Failure。抓包表明学校定制客户端还发送约 569 字节的动态私有校验尾部；该算法
> 尚未完整复现。README 不把原版客户端的成功结果计为 Python 客户端成功。

## 解决的问题

学校提供的锐捷认证客户端只有 Windows 版本，Linux 用户无法使用同一套校园网账号
完成 802.1X 认证。本项目根据 Windows 锐捷客户端的真实网络行为实现兼容客户端，
保留学校服务器原有的账号密码认证方式，不绕过认证，也不修改认证结果。

当前网络实际使用以下流程：

1. 向锐捷组播地址发送 EAPOL-Start；
2. 响应服务器的 EAP Identity 请求；
3. 使用原账号密码完成 EAP-MD5 Challenge；
4. 输出服务器返回的认证成功、认证失败、非认证时段等中文消息；
5. 将完整运行过程同时写入控制台和滚动日志。

项目目标是解决 Linux 无法运行 Windows 锐捷客户端的问题。现阶段适合协议研究、
抓包验证和继续开发，不应当作为已经可用的原版客户端替代品。

## 特性

- Windows、Linux 共用同一套 Python 实现；
- 默认主动探测锐捷认证服务器，自动选择真正连接校园网的网卡；
- 仅在传入 `--interface` 时使用用户指定网卡；
- 支持按名称、描述或 Windows NPF 名称指定网卡；
- 密码默认使用隐藏输入，也支持通过命令行参数传入；
- 账号密码不会写入本工具日志；
- 原样显示锐捷扩展 Success/Failure 中的 GB18030 中文通知；
- 默认复现原客户端的三次应答行为；
- 支持发送 EAPOL-Logoff 注销。

## 安装

需要 Python 3.10 或更高版本。

### Windows

安装 Npcap，并启用 WinPcap API 兼容模式。然后在管理员 PowerShell 中运行：

```powershell
cd D:\Files\Develop\Algorithm\_Development\Python\ruijie-campus-auth-hxxy
python -m pip install -e .
```

### Linux

先安装 libpcap。Debian/Ubuntu 示例：

```bash
sudo apt install python3 python3-pip libpcap-dev
cd /path/to/ruijie-campus-auth
python3 -m pip install --user .
```

也可以直接从 GitHub 安装当前源码：

```bash
python3 -m pip install "git+https://github.com/FairyXH/ruijie-campus-auth-hxxy.git"
```

## 快速使用

安装后直接执行：

```text
ruijie-auth
```

程序会逐个探测物理网卡，并自动选择收到锐捷 Identity 请求的校园网网卡，然后提示
输入账号和密码。它不会因为手机共享网络是系统默认路由而选错网卡：

```text
校园网用户名: YOUR_ID
校园网密码:
```

也可以提前指定用户名，密码仍采用隐藏输入：

```text
ruijie-auth --username YOUR_ID
```

账号密码都通过参数传入，适合启动脚本或无人值守认证：

```text
ruijie-auth --username YOUR_ID --password YOUR_PASSWORD
ruijie-auth -u YOUR_ID -p YOUR_PASSWORD
```

命令行参数可能被系统进程列表或 Shell 历史记录保存；在多人共用环境中建议继续使用
默认的隐藏输入方式。

只有需要覆盖自动选择结果时才指定网卡：

```text
ruijie-auth --interface enp3s0 --username YOUR_ID
ruijie-auth --interface "Realtek USB GbE" --username YOUR_ID
```

查看可用网卡：

```text
ruijie-auth --list-interfaces
```

注销当前认证：

```text
ruijie-auth --logoff
```

直接通过 Python 模块运行也可以：

```text
python -m ruijie_auth
```

## Python API

推荐导入名为 `ruijie_hxxy`。便捷函数会同步执行一次登录，并返回保留本次运行状态和
日志的 `RuijieClient` 对象：

```python
import ruijie_hxxy

client = ruijie_hxxy.login(
    "YOUR_ID",
    "YOUR_PASSWORD",
    # interface="enp3s0",  # 省略时自动探测
)

status = client.status()
print(status["authenticated"])
print(status["message"])
print(status["interface_description"])
print("\n".join(status["logs"]))

# 与最初设计示例兼容，但新代码建议使用 status()。
same_status = client.stat()
```

需要先配置、后执行时使用类接口：

```python
from ruijie_hxxy import RuijieClient

client = RuijieClient(
    "YOUR_ID",
    "YOUR_PASSWORD",
    interface=None,
    timeout=30,
    retries=3,
    repeats=3,
    log_file="ruijie-auth.log",
    verbose=False,
)

success = client.login()
state = client.status()
client.logout()
```

`status()` 返回新的 `dict` 快照，主要字段如下：

- `state`：`idle`、`authenticating`、`authenticated`、`failed`、`error` 或
  `logged_out`；
- `authenticated`：本次登录是否收到 EAP-Success；
- `message`：简短中文状态；
- `interface`、`interface_description`、`ip`、`mac`：实际认证网卡；
- `started_at`、`finished_at`：带时区的 ISO 8601 时间；
- `logs`：本次调用的日志列表，每行均以 `YYYY-MM-DD HH:MM:SS` 开头。

账号和密码只保存在当前 `RuijieClient` 对象内，不会放入状态字典或日志。若将密码直接
写入源码，应自行保护源码文件；命令行 `--password` 还可能被 Shell 历史或进程列表记录。

## 账号兼容性与抓包说明

- 源码、构建产物和 README 均不包含测试账号、密码或捕获报文；
- 当前标准 EAP Identity/EAP-MD5 实现没有绑定某个账号，算法层面对任意账号相同；
- 项目运行时不会读取或重放开发阶段的 pcap；
- 但本校服务器校验锐捷私有动态字段，所以“账号无硬编码”不等于“当前已对所有账号
  认证成功”；
- 私有校验复现完成后仍需至少用两个账号交叉验证，才能确认不存在账号、套餐或策略差异。

## 0.2.0 改动

- 新增 `ruijie_hxxy.login()` 便捷函数；
- 新增可复用的 `RuijieClient` 类及 `login()`、`logout()`、`status()` API；
- 保留 `stat()` 作为 `status()` 的兼容别名；
- 内存日志与文件/控制台日志使用相同的时间在前格式；
- 自动选卡探测到认证服务器后主动发送 Logoff，避免探测遗留临时会话；
- 修正文档中的验证结论，明确当前真实 EAP-Failure 和私有校验缺口。

## 日志

默认日志文件为当前目录下的 `ruijie-auth.log`，最多保留三份轮转文件。日志包括：

- 自动选择或手动指定的网卡；
- 寻找和连接认证服务器；
- Identity 与 EAP-MD5 阶段；
- 服务器返回的中文通知；
- 认证成功、失败、超时和网卡访问错误。

使用 `--log-file PATH` 可修改日志位置，使用 `--verbose` 可在控制台显示协议调试信息。

## 权限

程序需要收发二层 EAPOL 帧：

- Windows：使用管理员终端；
- Linux：使用 `sudo ruijie-auth`，或为 Python/启动器配置等效的原始套接字权限。

## 实网验证结果

Windows 实网已经验证以下事实：

- 自动选卡能定位原版客户端使用的 Realtek 校园网卡；
- EAPOL-Logoff 后，从该网卡访问百度、搜狗、必应均超时；
- 原版客户端认证后，三站均返回 HTTP 200，且双网卡抓包证明流量来自校园网网卡；
- 上述注销/登录网络回归连续执行两轮，结果一致；
- 通过本项目 0.2.0 的 pip 安装包调用 `ruijie_hxxy.login()` 时，服务器在标准
  EAP-MD5 后返回 EAP-Failure，因此 Python 认证尚未通过。

测试账号和密码不包含在源码、配置、README 或安装元数据中。
