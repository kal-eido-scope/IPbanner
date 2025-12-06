# IPbanner

搞了个服务器，总有一些喜欢来试密码的，某几个智力缺陷症患者甚至是试个没完，也是纯纯的神人。
写了个简单的python脚本，功能为从事件查看器日志里读取rdp登陆请求信息，筛选出其中所有登陆失败的IP地址，生成脚本将其加入组策略中ban掉。
理论上用批处理文件更容易，然而本人太菜不会，凑合着用吧

## 简介

这是一个用于从 Windows 事件查看器（Evtx）中提取 RDP 登录失败来源 IP，并将这些 IP 列表化以生成用于阻断的批处理脚本（`renewPolicy.bat`）的简易工具。

## 环境与依赖
- 支持平台：Windows（脚本读取 Windows 事件日志并生成 Windows 批处理）。
- Python 版本：建议使用 Python 3.8+。
- 安装依赖：

```shell
pip install -r requirements.txt
```

`requirements.txt` 当前包含：

- `python-evtx`（用于解析 evtx 文件）
- `xmltodict`

## 用法

Flags:

- `--data, -d`: 保存解析后的事件数据到 `data/YYYY-MM-DD-HH-MM-SS/`，包含 `eventList.json` 与 `ipCounts.txt`。
- `--command, -c`: 在处理完事件后生成 `renewPolicy.bat`（使用当前 `suspiciousIPs.txt` + 新发现 IP）。
- `--transfer, -t`: 跳过读取 evtx 的处理，仅根据仓库根目录下的 `suspiciousIPs.txt` 生成 `renewPolicy.bat`。

### 示例

```cmd
REM 仅更新 suspiciousIPs.txt
python ipbanner.py

REM 保存数据并更新 suspiciousIPs.txt
python ipbanner.py -d

REM 更新 suspiciousIPs.txt，并生成 renewPolicy.bat（注意：执行 renewPolicy.bat 需管理员）
python ipbanner.py -c

REM 保存数据，更新suspiciousIPs.txt，生成 renewPolicy.bat
python ipbanner.py -d -c

REM 仅根据现有 suspiciousIPs.txt 生成 renewPolicy.bat
python ipbanner.py -t
```

## 其他说明

### 关于日志文件路径
- 若脚本无法读取本地 `.evtx` 文件，请在 `ipbanner.py` 中修改 `logDir` 为你的事件日志路径（示例配置为 `C:\Windows\System32\winevt\Logs`）。
- 在事件查看器中查找路径：`Win+R` → `eventvwr.msc` → 应用程序和服务日志 → Microsoft → Windows → RemoteDesktopServices-RdpCoreTS → Operational → 右侧 “属性” 查看日志路径。

### 相关风险
- **必须以管理员权限运行生成或应用策略相关命令。** 生成 `renewPolicy.bat` 本身不自动修改策略，但该文件内的 `netsh` 命令在被执行时需要管理员权限；脚本会删除名为 `ip blacklist` 的旧策略并重新创建。有需要的请在使用前对旧策略进行备份。
- **当前脚本会按行读取 `suspiciousIPs.txt` 并将每行写入批处理。** 请确保文件中的每一行都是合法 IP。


### 数据输出说明

- `data/<timestamp>/eventList.json`：解析得到的事件列表（JSON），用于离线分析。
- `data/<timestamp>/ipCounts.txt`：列出被统计的失败登录 IP 及尝试次数，按次数从高到低排列。