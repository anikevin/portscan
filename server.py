#coding=utf-8


import socket
import json
import redis
import re
import commands
import os
import datetime
import argparse
from libnmap.parser import NmapParser
from libnmap.reportjson import ReportEncoder
from multiprocessing.dummy import Pool as ThreadPool
from IPy import IP


# 昨天和前天日期
today_date = datetime.datetime.today()
today = today_date.strftime('%Y%m%d')


# IP地址字典和列表
ip_dict = redis_data.hgetall('ip_addr')
ip_list = redis_data.hgetall('ip_addr').keys()

# 连接redis
try:
    redis_data = redis.Redis(host='127.0.0.1', port=6379, password='')
except Exception, e:
    print e


# IP地址平均分配写入文件
def ip_write_file():
    if os.path.exists('report/{}'.format(today)) == False:
        os.mkdir('report/{}'.format(today))
    for i in range(len(task_data)):
        task = json.loads(task_data[i].replace('\'', '\"'))
        with open('report/{}/{}.txt'.format(today, i), 'a') as ip_file:
            for ip in task:
                ip_file.write(ip + '\n')


# 调用nmap扫描
def nmap_scan():
   # 设置NMAP扫描进程数和主机扫描超时时间
   parser = argparse.ArgumentParser()
   parser.add_argument('-t', '--nmap_thread', default=8, help='NMAP扫描进程数', type=int)
   parser.add_argument('-ht', '--host_timeout', default='420m', help='主机扫描超时时间, 单位建议为m(分), 如360m')
   args = parser.parse_args()
   nmap_thread = args.nmap_thread
   host_timeout = args.host_timeout
   # 多进程扫描
   arg_list = []
   for i in range(len(task_data)):
       arg = 'nmap -sT -sV --open -v --version-all --host-timeout {} \
       -T4 -p 1-65535 -iL report/{}/{}.txt -oX report/{}/{}.xml'.format(host_timeout, today, i, today, i)
       arg_list.append(arg)
   pool = ThreadPool(nmap_thread)
   scan = pool.map(commands.getoutput, arg_list)
   pool.close()
   pool.join()


# 获取IP归属业务
def verify_ip_business(address):
    business = ''
    for ip in ip_list:
        if re.search(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])', ip):
            try:
                if address in IP(ip, make_net=True):
                    business = json.loads(ip_dict[ip])['business']
            except Exception, e:
                   continue
                   print e
    return business


# 扫描完成后扫描结果发送到redis
def generate_report(count):
    report_list = []
    xml = NmapParser.parse_fromfile('report/{}/{}.xml'.format(today, count))
    json_format = json.dumps(xml, cls=ReportEncoder)
    dict_report = json.loads(json_format, encoding='utf-8')
    # 统计存活IP个数
    lenip = json_format.count('__NmapHost__')
    for i in range(lenip):
        # 统计每个IP开放的端口数量
        lenport = str(dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']).count('_portid')
        address = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_address'][0]['addr']
        business = verify_ip_business(address)
        for j in range(lenport):
            service = ''
            product = ''
            version = ''
            extrainfo = ''
            state = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                               ['__NmapService__']['_state']['state']
            port = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                              ['__NmapService__']['_portid']
            protocol = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                  ['__NmapService__']['_protocol']
            if 'name' in dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                    ['__NmapService__']['_service']:
                service = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                     ['__NmapService__']['_service']['name']
            if 'product' in dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                       ['__NmapService__']['_service']:
                product = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                     ['__NmapService__']['_service']['product']
            if 'version' in dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                       ['__NmapService__']['_service']:
                version = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                     ['__NmapService__']['_service']['version']
            if 'extrainfo' in dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                         ['__NmapService__']['_service']:
                extrainfo = dict_report['__NmapReport__']['_hosts'][int(i)]['__NmapHost__']['_services'][int(j)] \
                                       ['__NmapService__']['_service']['extrainfo']
            if state == 'open':
                report = json.dumps({'address': address, 'port': port, 'protocol': protocol, 'service': service,
                                     'version': version, 'product': product, 'business': business, 'extrainfo': extrainfo},
                                      sort_keys=True)
                report_list.append(report)
    return report_list


# 将扫描结果发送回redis
def to_redis():
    to_redis_list = []
    for count in range(len(task_data)):
        if generate_report(count) != None:
            to_redis_list += generate_report(count)
    for report in to_redis_list:
        redis_data.rpush('scan_report_{}'.format(today), report)
    # 每个nmap扫描任务结束后标志位减一
    for count in range(len(task_data)):
        redis_data.decr('nmap_sign')


# 服务端监听，等待客户端脚本推送当天扫描的IP地址, 开始扫描，并将扫描结果发送回redis
if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 666))
    sock.listen(10)
    print "listen 666......"
    while 1:
        connection, address = sock.accept()
        try:
            # 判断数据是否是从客户端发的
            if address[0] == '3.3.3.3':
                connection.settimeout(50)
                global task_data
                total_data = []
                # 循环接收数据
                while 1:
                    recv_data = connection.recv(8192)
                    if not recv_data:
                        break
                    total_data.append(recv_data)
                total_datas = ''.join(total_data)
                task_data = json.loads(total_datas)
                print task_data
                # 将IP地址写入文件
                ip_write_file()
                # 开始调用nmap进行扫描
                nmap_scan()
                # 将扫描结果推送到redis
                to_redis()
                break
        except socket.timeout:
            print 'timeout'
        connection.close()