# Ruijie Campus Auth HXxy

一个可在 Windows 和 Linux 上运行的锐捷校园网命令行认证工具。

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

项目解决了 Linux 无法运行 Windows 锐捷客户端的问题，同时也可在 Windows 上替代
原图形客户端，适合登录脚本、无桌面环境和 SSH 终端。

## 特性

- Windows、Linux 共用同一套 Python 实现；
- 默认主动探测锐捷认证服务器，自动选择真正连接校园网的网卡；
- 仅在传入 `--interface` 时使用用户指定网卡；
- 支持按名称、描述或 Windows NPF 名称指定网卡；
- 密码使用隐藏输入，不接受命令行密码参数；
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

## 已验证

Windows 实网测试已完成。Python 客户端能够自动选择锐捷原客户端使用的网卡，处理
服务器重复发起的 Identity/MD5 Challenge，收到扩展 EAP Success，并正确输出服务器
中文欢迎消息。生成的 MD5 应答也已与原客户端成功报文进行逐字节对照。

测试账号和密码不包含在源码、配置、README、安装元数据或日志中。
