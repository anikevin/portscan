#coding=utf-8


import socket
import json
import redis
import re
import commands
import os
import datetime
from libnmap.parser import NmapParser
from libnmap.reportjson import ReportEncoder


# 当天日期
today_date = datetime.datetime.today()
today = today_date.strftime('%Y%m%d')


# 端口扫描服务器IP地址列表，至少写一个
SCAN_SERVER = ['1.1.1.1', '2.2.2.2']


# 连接redis
try:
    redis_data = redis.Redis(host='127.0.0.1', port=6379, password='')
except Exception, e:
    print e


# 将待扫描的IP地址写入文件，便于nmap扫描
def ip_write_file():
    # 从redis中获取待扫描IP列表
    ip_list = redis_data.hgetall('ip_addr').keys()
    count = 0
    if os.path.exists('report/{}'.format(today)) == False:
        os.makedirs('report/{}, -p'.format(today))
    # 写入文件内容排除非IP
    for ip in ip_list:
        if re.search(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])', ip):
            print ip
            with open('report/{}/all.txt'.format(today), 'a') as file_ip:
                file_ip.write(ip + '\n')


# 存活IP扫描
def get_host_up():
    # 调用nmap扫描
    commands.getoutput('nmap -v -sP -iL report/{}/all.txt \
                        -oX report/{}/all.xml'.format(today, today))
    xml = NmapParser.parse_fromfile('report/{}/all.xml'.format(today))
    json_format = json.dumps(xml, cls=ReportEncoder)
    dict_report = json.loads(json_format, encoding='utf-8')
    # 存活主机列表
    hostups = []
    lenip = json_format.count('__NmapHost__')
    for i in range(lenip):
        state = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_status']['state']
        address = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_main_address']
        if state == 'up':
            hostups.append(address)
    #将存活主机列表写入redis
    for hostup in hostups:
        redis_data.rpush('hostup', hostup)


# 均分存活主机，计算每台服务器扫描的任务数
def get_task_count(number):
    all_hostups = list(set(redis_data.lrange('hostup', 0, -1)))
    for i in range(0, len(all_hostups), number):
        redis_data.rpush('hostup_32', all_hostups[i:i+number])
    hostup_32 = redis_data.lrange('hostup_32', 0, -1)
    scanip_count = len(hostup_32)
    server_count = len(SCAN_SERVER)
    quotient = scanip_count / server_count
    remainder = scanip_count % server_count
    task_counts =  [quotient] * (server_count - remainder) + [quotient + 1] * remainder
    return hostup_32, task_counts


# 主函数
if __name__ == '__main__':
    # 将待扫描的IP地址写入文件
    ip_write_file()
    # 获取存活主机
    get_host_up()
    # 测试发现每个任务扫描32台主机速度比较快，所以以32每份均等分割存活IP，计算每台服务器扫描的任务数
    hostup_32, task_counts = get_task_count(32)
    # 删除hostup key，防止第二天重用
    redis_data.delete('hostup')
    # 设置扫描任务数
    redis_data.set('nmap_sign', len(hostup_32))
    # 发送要扫描的IP地址给服务端，端口同服务端定义的一致
    for i in range(len(SCAN_SERVER)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65535)
        try:
            sock.connect(('{}'.format(SCAN_SERVER[i]), 666))
            task_data = redis_data.lrange('hostup_32', 0, (task_counts[i]-1))
            print 'send task'+ json.dumps(task_data)
            sock.send(json.dumps(task_data))
            sock.close()
            # pop出已下发扫描任务的IP
            for i in range(task_counts[i]):
                redis_data.lpop('hostup_32')
        except Exception, e:
            print e