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
    temp_evtx = tempfile.mktemp(suffix='.evtx')
    try:

        logging.info('Reading the evtx from cache.')
        # 导出缓存中的完整日志到临时文件
        export_cmd = [
            'wevtutil', 'epl', logName, temp_evtx,
            '/ow:true', 
        ]
        
        result = subprocess.run(export_cmd, capture_output=True, text=True , encoding='utf-8')
        
        if result.returncode != 0:
            logging.error(f"Error happenned when getting the cache: {str(e)}")

        return evtx_to_list(temp_evtx)
        
    except Exception as e:
        logging.error(f"Error happenned when reading the cache: {str(e)}")

    finally:
        # 清理临时文件
        if os.path.exists(temp_evtx):
            try:
                os.remove(temp_evtx)
            except:
                pass

def read_eventlog_from_file(
        baseDir: str = 'C:\Windows\System32\winevt\Logs',
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
        if isinstance(item,dict):
            uniqueId = item['Event']['System']['EventRecordID']
        if uniqueId not in seen:
            seen.add(uniqueId)
            result.append(item)
    return result

def find_rdp140_events(eventList:list)->dict:
    """筛选出事件id为140的ip，记录为ipCounts = {'ip':'times'}"""
    ipCounts = {}
    logging.info('Filter out the login failure attempts.')
    for i,event in enumerate(eventList):
        if event['Event']['System']['EventID']['#text'] == '140':
            ip = event['Event']['EventData']['Data']['#text']
            ipCounts[ip] = ipCounts.get(ip,0) + 1
    return ipCounts

def sortedIp(ipList:dict)->list:
    """将ipCounts字典按ip地址顺序及小到大排列"""
    return sorted(ipList, key = lambda x : (int(x.split('.')[0]),int(x.split('.')[1]),int(x.split('.')[2]),int(x.split('.')[3])))

def write_data(*eventList,ipCounts:dict):
    """写入文件至本地"""
    logging.info('Writing data to the data\ folder.')
    # 创建目录
    os.makedirs('data',exist_ok=True)
    curTime = time.localtime(time.time())
    formatedTime = '%04d-%02d-%02d-%02d-%02d-%02d'%(curTime.tm_year,curTime.tm_mon,curTime.tm_mday,curTime.tm_hour,curTime.tm_min,curTime.tm_sec)
    updateDir = os.path.join('data',formatedTime)
    os.makedirs(updateDir,exist_ok=True)

    # 输出json格式的eventlist日志文件
    for i,item in enumerate(eventList):
        eventListPath = os.path.join(updateDir,f'eventList{i}.json')
        with open(eventListPath,'w',newline='\n')as f:
            json.dump(item,f,indent=4)

    # 输出访问失败的ip相应次数
    sortedIpCounts = dict(sorted(ipCounts.items(),key = lambda x:x[1],reverse=True))
    ipCountsPath = os.path.join(updateDir,'ipCounts.txt')
    with open (ipCountsPath,'w',encoding='utf-8') as f:
        for ip,counts in sortedIpCounts.items():
            f.write(f'{ip}\t{counts}次\n')

def update_bannedIP(ipCounts:dict):
    """更新可疑IP地址，去重合并模式"""
    logging.info('Updating the suspicious IP addresses.')
    if not os.path.exists('suspiciousIPs.txt'):
        # 初始化文件
        with open ('suspiciousIPs.txt','w',encoding='utf-8') as f:
            for ip in sortedIp(list(ipCounts.keys())):
                f.write(f'{ip}\n')
    else:
        # 去重合并，从小到大排列
        with open ('suspiciousIPs.txt','r',encoding='utf-8') as f:
            preIpList = f.read().strip().splitlines()    
            newIpList = sortedIp(list(set(preIpList+list(ipCounts.keys()))))
        # 写入新文件    
        with open ('suspiciousIPs.txt','w',encoding='utf-8') as f:
            for ip in newIpList:
                f.write(f'{ip}\n')

def write_command():
    """输出批量禁止的批处理文件"""
    bannedIpList = []
    try:
        logging.info('Generating renewPolicy.bat from suspiciousIPs.txt.')
        with open('suspiciousIPs.txt','r',encoding='utf-8') as f:
            for line in f:
                bannedIpList.append(line.strip())
        with open('renewPolicy.bat','w',encoding='utf-8',newline='\n') as f:
            # 删除旧策略
            f.write('netsh ipsec static delete policy name="ip blacklist"\n')
            # 创建新策略    ip blacklist
            f.write('netsh ipsec static add policy name="ip blacklist" description="ban IP requesting rdp login with incorrect passwords"\n')
            # 创建新筛选器操作  block
            f.write('netsh ipsec static add filteraction name="block" action=block\n')
            # 创建新筛选器列表  banned IP
            f.write('netsh ipsec static add filterlist name="banned IP"\n')
            # 在筛选器中添加ip限制
            f.writelines([f'netsh ipsec static add filter filterlist="banned IP" srcaddr={ip} dstaddr=me protocol=any mirror=no\n' for ip in bannedIpList])
            # 将筛选器关联到策略 restrictions from rdp
            f.write('netsh ipsec static add rule name="rdp restrictions" policy="ip blacklist" filterlist="banned IP" filteraction="block"\n')
            # 指派筛选器生效
            f.write('netsh ipsec static set policy name="ip blacklist" assign=yes\n')
            f.write('pause')
    except Exception as e:
        logging.error('Error happened when openning suspiciousIPs.txt')
        logging.error(e)

def main():
    args = parse_args()
    data_flag, command_flag, transfer_flag = args.data, args.command, args.transfer
    if transfer_flag:
        # 只根据根目录的suspiciousIPs.txt生成bat文件
        write_command()
    else:
        logDir = 'C:\Windows\System32\winevt\Logs'             # 此行请根据自己的情况相应填写事件查看器中rdp.evtx所在的绝对路径
        rdpLogName = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'
        rdpEventListFromFile = read_eventlog_from_file(logDir,rdpLogName)
        rdpEventListFromCache = read_eventlog_from_cache(rdpLogName)
        rdpEventList = merge_event_list(rdpEventListFromFile,rdpEventListFromCache)
        ipCounts = find_rdp140_events(rdpEventList)
        if data_flag:
            write_data(rdpEventList,ipCounts=ipCounts)
        update_bannedIP(ipCounts)
        if command_flag:
            write_command()

if __name__ =="__main__":
    main()