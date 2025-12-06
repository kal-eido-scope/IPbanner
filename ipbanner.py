# -*- coding: utf-8 -*-
from Evtx import Evtx as evtx
import xmltodict
import os
import time
import json
import logging
import argparse
import subprocess
import tempfile
import ipaddress

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_args():
    """处理参数"""
    args = argparse.ArgumentParser()
    args.add_argument('-d', '--data', action='store_true', help='add this flag for saving data, if not don\'t add it')
    args.add_argument('-c', '--command', action='store_true', help='add this flag for generating renewPolicy.bat from the real-time data')
    args.add_argument('-t', '--transfer', action='store_true', help='skip the processing part, transfer the suspiciousIPs.txt to renewPolicy.bat only')
    return args.parse_args()

def log_name_to_logpath(logDir,logName)->str:
    """根据给出的服务名，返回其日志文件的路径，此处仅实现rdp"""
    fileName = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx'
    return os.path.join(logDir,fileName)

def evtx_to_list(filePath:str)->list:
    """从file_path路径获取事件信息，返回事件列表"""
    eventList =[]
    try:
        with evtx.Evtx(filePath) as rdpEvtx:
            for record in rdpEvtx.records():
                data_dict = xmltodict.parse(record.xml())
                eventList.append(data_dict)
    except Exception as e:
        logging.error('Error happened when opening .evtx\nPerhaps you need to confirm your path for rdp.evtx')
        logging.error(e)
    return eventList

def read_eventlog_from_cache(
    logName: str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
) -> list:
    """获取事件查看器中logName服务的缓存内容，返回事件列表"""
    # 使用安全的临时文件创建方法
    tmp = None
    try:
        logging.info('Reading the evtx from cache.')
        with tempfile.NamedTemporaryFile(suffix='.evtx', delete=False) as tmpf:
            temp_evtx = tmpf.name

        # 导出缓存中的完整日志到临时文件
        export_cmd = [
            'wevtutil', 'epl', logName, temp_evtx,
            '/ow:true',
        ]

        result = subprocess.run(export_cmd, capture_output=True, text=True, encoding='utf-8')

        if result.returncode != 0:
            logging.error(f"Error happened when getting the cache: {result.returncode} {result.stderr}")
            return []

        return evtx_to_list(temp_evtx)

    except Exception as e:
        logging.error(f"Error happened when reading the cache: {str(e)}")
        return []

    finally:
        # 清理临时文件
        try:
            if 'temp_evtx' in locals() and os.path.exists(temp_evtx):
                os.remove(temp_evtx)
        except Exception:
            pass

def is_valid_ip(ip_str: str) -> bool:
    """验证字符串是否为合法 IPv4 或 IPv6 地址（忽略空字符串）。"""
    if not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except Exception:
        return False

def read_eventlog_from_file(
    baseDir: str = r'C:\Windows\System32\winevt\Logs',
        logName: str = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
    )->list:
    """获取事件查看器中logName服务的本地日志文件内容，返回事件列表"""
    logging.info('Reading the evtx from file.')
    filePath = log_name_to_logpath(baseDir,logName)
    return evtx_to_list(filePath)

def merge_event_list(*eventLists):
    """将多个事件列表去重合并为一个列表，采用EventRecordID作为去重标记"""
    allList = []
    for arg in eventLists:
        allList.extend(arg)
    
    seen = set()
    result = []
    for item in allList:
        try:
            if not isinstance(item, dict):
                continue
            evrec = item.get('Event', {}).get('System', {}).get('EventRecordID')
            if evrec is None:
                continue
            # EventRecordID 有时为 dict 包含 '#text'
            if isinstance(evrec, dict):
                uniqueId = evrec.get('#text')
            else:
                uniqueId = str(evrec)

            if uniqueId not in seen:
                seen.add(uniqueId)
                result.append(item)
        except Exception:
            continue
    return result

def find_rdp140_events(eventList:list)->dict:
    """筛选出事件id为140的ip，记录为ipCounts = {'ip':'times'}"""
    ipCounts = {}
    logging.info('Filter out the login failure attempts.')
    for i,event in enumerate(eventList):
        try:
            event_id = event.get('Event', {}).get('System', {}).get('EventID')
            if isinstance(event_id, dict):
                event_id_text = event_id.get('#text')
            else:
                event_id_text = str(event_id)

            if event_id_text == '140':
                data = event.get('Event', {}).get('EventData', {}).get('Data')
                # Data 可能为 dict 或 list
                ip = None
                if isinstance(data, dict):
                    ip = data.get('#text') or next(iter(data.values()), None)
                elif isinstance(data, list):
                    # 尝试从第一个元素获取
                    first = data[0] if data else None
                    if isinstance(first, dict):
                        ip = first.get('#text') or next(iter(first.values()), None)
                    else:
                        ip = first

                if ip:
                    ipCounts[ip] = ipCounts.get(ip, 0) + 1
        except Exception:
            continue
    return ipCounts

def sortedIp(ipList:list)->list:
    """将ip地址列表按从小到大排序（按 IPv4 各段）"""
    def ip_key(x):
        try:
            parts = x.split('.')
            return tuple(int(p) for p in parts)
        except Exception:
            return (999,999,999,999)
    return sorted(ipList, key=ip_key)

def write_data(eventList:list, ipCounts:dict):
    """写入文件至本地"""
    logging.info('Writing data to the data folder.')
    # 创建目录
    os.makedirs('data', exist_ok=True)
    curTime = time.localtime(time.time())
    formatedTime = '%04d-%02d-%02d-%02d-%02d-%02d' % (
        curTime.tm_year,
        curTime.tm_mon,
        curTime.tm_mday,
        curTime.tm_hour,
        curTime.tm_min,
        curTime.tm_sec,
    )
    updateDir = os.path.join('data', formatedTime)
    os.makedirs(updateDir, exist_ok=True)

    # 输出json格式的eventlist日志文件
    eventListPath = os.path.join(updateDir, 'eventList.json')
    try:
        with open(eventListPath, 'w', newline='\n', encoding='utf-8') as f:
            json.dump(eventList, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f'Failed to write eventList.json: {e}')

    # 输出访问失败的ip相应次数
    sortedIpCounts = dict(sorted(ipCounts.items(), key=lambda x: x[1], reverse=True))
    ipCountsPath = os.path.join(updateDir, 'ipCounts.txt')
    with open(ipCountsPath, 'w', encoding='utf-8') as f:
        for ip, counts in sortedIpCounts.items():
            f.write(f'{ip}\t{counts}次\n')

def update_bannedIP(ipCounts:dict):
    """更新可疑IP地址，去重合并模式"""
    logging.info('Updating the suspicious IP addresses.')
    if not os.path.exists('suspiciousIPs.txt'):
        # 初始化文件
        with open('suspiciousIPs.txt', 'w', encoding='utf-8') as f:
            valid_ips = [ip.strip() for ip in list(ipCounts.keys()) if is_valid_ip(ip.strip())]
            for ip in sortedIp(valid_ips):
                f.write(f'{ip}\n')
    else:
        # 去重合并，从小到大排列
        with open('suspiciousIPs.txt', 'r', encoding='utf-8') as f:
            preIpList = [line.strip() for line in f.read().splitlines() if line.strip()]
            pre_valid = [ip for ip in preIpList if is_valid_ip(ip)]
            new_candidates = [ip.strip() for ip in list(ipCounts.keys()) if is_valid_ip(ip.strip())]
            newIpList = sortedIp(list(set(pre_valid + new_candidates)))
        # 写入新文件    
        with open('suspiciousIPs.txt', 'w', encoding='utf-8') as f:
            for ip in newIpList:
                f.write(f'{ip}\n')

def write_command():
    """输出批量禁止的批处理文件"""
    bannedIpList = []
    invalid_lines = []
    try:
        logging.info('Generating renewPolicy.bat from suspiciousIPs.txt.')
        with open('suspiciousIPs.txt', 'r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if is_valid_ip(s):
                    bannedIpList.append(s)
                else:
                    invalid_lines.append(s)

        if invalid_lines:
            logging.warning('Found invalid IP lines in suspiciousIPs.txt (ignored): %s', ', '.join(invalid_lines))

        # 去重并排序
        bannedIpList = sortedIp(list(dict.fromkeys(bannedIpList)))

        with open('renewPolicy.bat', 'w', encoding='utf-8', newline='\n') as f:
            # 删除旧策略
            f.write('netsh ipsec static delete policy name="ip blacklist"\n')
            # 创建新策略    ip blacklist
            f.write('netsh ipsec static add policy name="ip blacklist" description="ban IP requesting rdp login with incorrect passwords"\n')
            # 创建新筛选器操作  block
            f.write('netsh ipsec static add filteraction name="block" action=block\n')
            # 创建新筛选器列表  banned IP
            f.write('netsh ipsec static add filterlist name="banned IP"\n')
            # 在筛选器中添加ip限制
            for ip in bannedIpList:
                f.write(f'netsh ipsec static add filter filterlist="banned IP" srcaddr={ip} dstaddr=me protocol=any mirror=no\n')
            # 将筛选器关联到策略 restrictions from rdp
            f.write('netsh ipsec static add rule name="rdp restrictions" policy="ip blacklist" filterlist="banned IP" filteraction="block"\n')
            # 指派筛选器生效
            f.write('netsh ipsec static set policy name="ip blacklist" assign=yes\n')
            f.write('pause')
    except FileNotFoundError:
        logging.error('suspiciousIPs.txt not found. Please run the script with -d to generate or create the file.')
    except Exception as e:
        logging.error('Error happened when opening suspiciousIPs.txt: %s', e)

def main():
    args = parse_args()
    data_flag, command_flag, transfer_flag = args.data, args.command, args.transfer
    if transfer_flag:
        # 只根据根目录的suspiciousIPs.txt生成bat文件
        write_command()
    else:
        logDir = r'C:\Windows\System32\winevt\Logs'             # 此行请根据自己的情况相应填写事件查看器中rdp.evtx所在的绝对路径
        rdpLogName = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
        rdpEventListFromFile = read_eventlog_from_file(logDir,rdpLogName)
        rdpEventListFromCache = read_eventlog_from_cache(rdpLogName)
        rdpEventList = merge_event_list(rdpEventListFromFile,rdpEventListFromCache)
        ipCounts = find_rdp140_events(rdpEventList)
        if data_flag:
            write_data(rdpEventList, ipCounts)
        update_bannedIP(ipCounts)
        if command_flag:
            write_command()

if __name__ =="__main__":
    main()