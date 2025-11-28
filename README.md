# IPbanner

搞了个服务器，总有一些喜欢来试密码的，某几个智力缺陷症患者甚至是试个没完，也是纯纯的神人。
写了个简单的python脚本，功能为从事件查看器日志里读取rdp登陆请求信息，筛选出其中所有登陆失败的IP地址，生成脚本将其加入组策略中ban掉。
理论上用批处理文件更容易，然而本人太菜不会，凑合着用吧

## Dependency

```shell
pip install -r requirements.txt
```

## Usage

| Flags              | Default | Description                                                                                           |
| ------------------ | ------- | ----------------------------------------------------------------------------------------------------- |
| *--data, -d*     | False   | add this flag to save data or ignore this for only result (suspiciousIPs.txt)                         |
| *--command, -c*  | False   | add this flag to generate a renewPolicy.bat from your evtx or ignore this for no generations          |
| *--transfer, -t* | False   | add this flag to generate a renewPolicy.bat from existing suspiciousIPs.txt without reading your evtx |

### Example

```shell
# 保存日志，生成可疑IP列表
python ipbanner.py -d
# 保存日志，生成可疑IP列表，并生成添加到组策略的批处理文件
python ipbanner.py -d -c
# 不保存日志，不生成可疑IP列表，仅根据根目录下的suspiciousIPs.txt生成批处理文件
python ipbanner.py -t
```

### Others

1. suspiciousIPs.txt默认为追加模式，即将将日志中的ip和suspiciousIPs文件中的ip合并形成新的待ban的ip池。

2. renewPolicy的模式是删除旧的名为ip blacklist的策略，并根据suspiciousIPs文件中的ip列表重新生成一个新的名为ip blacklist的策略，不会保留原有策略。

3. 如果运行失败，请在ipbanner.py的第128行请自行修改evtx文件的位置，位置查看方法：
    * win+R, eventvwr.msc调出事件查看器
    * 应用程序和服务日志 - Microsoft - Windows - RemoteDesktopServices-RdpCoreTS - Operational
    * 右侧列表属性 - 日志路径

### Data contenet

#### Data/
1. ipCounts.txt

```shell
111.111.111.111 55次 
222.222.222.222 44次
```

2. eventList.json

```json
[
    {
        "Event":{
            "key1":"value1",
            "key2":"value2",
        },
        "EventData":{
            "key3":{
                "key3_1":"value3_1",
            }
        }
    },
    {
        "Event":{},
        "EventData":{},
    },{},{},{},
]
```