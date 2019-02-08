#coding=utf-8


import redis
import json
import datetime
import time
import smtplib
import sys
from email.mime.text import MIMEText


reload(sys)
sys.setdefaultencoding('utf8')


# 定义今天，昨天和前天日期
today_date = datetime.datetime.today()
today = today_date.strftime('%Y%m%d')
yesterday_date = today_date + datetime.timedelta(days=-1)
yesterday = yesterday_date.strftime('%Y%m%d')
b_yesterday_date = today_date + datetime.timedelta(days=-2)
b_yesterday = b_yesterday_date.strftime('%Y%m%d')


# 连接redis
try:
    redis_data = redis.Redis(host='127.0.0.1', port=6379, password='')
except Exception, e:
    print e


# 对比今天和昨天报表，找出开放的端口
def get_open_port():
    report_list = []
    global today_reports
    today_reports = redis_data.lrange('scan_report_{}'.format(today), 0, -1)
    yesterday_reports = redis_data.lrange('scan_report_{}'.format(yesterday), 0, -1)
    for today_report in today_reports:
        if today_report not in yesterday_reports:
            report_list.append(today_report)
    return report_list


# 发送邮件
def send_mail():
    report_list = get_open_port()
    content =  '''
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>端口扫描报表</title>
</head>
<style type="text/css">

body {
    font: normal 11px auto verdana,arial,sans-serif;
    color: #333333;
    background: #ffffff;
}

#mytable {
    width: 1200px;
    padding: 0;
    margin: 0;
}

caption {
    padding: 0 0 5px 0;
    width: 1200px;
    font: 20px verdana,arial,sans-serif;
    font-weight: bold;
    text-align: center;
}

th {
    font: bold 11px verdana,arial,sans-serif;
    color: #333333;
    border-right: 1px solid #EAEAEA;
    border-bottom: 1px solid #EAEAEA;
    border-top: 1px solid #EAEAEA;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 6px 6px 6px 12px;
    background: #F5F5F5;
    text-align: center;
}

th.nobg {
    border-top: 0;
    border-left: 0;
    border-right: 1px solid #EAEAEA;
    background: none;
}

td {
    border-right: 1px solid #EAEAEA;
    border-bottom: 1px solid #EAEAEA;
    background: #fff;
    font-size:11px;
    padding: 6px 6px 6px 12px;
    color: #333333;
    text-align: center;
}
</style>


<body>
<table id="mytable" cellspacing="0">
<caption>????新开放端口</caption>
  <tr>
    <th scope="col">业务</th>
    <th scope="col">IP</th>
    <th scope="col">端口</th>
    <th scope="col">服务</th>
    <th scope="col">协议</th>
    <th scope="col">版本</th>
    <th scope="col">产品</th>
    <th scopt="col">其他</th>
  </tr>
'''

    for report in report_list:
        report = json.loads(report)
        content += '<tr> \
                <td>{0}</td> \
                <td>{1}</td> \
                <td>{2}</td> \
                <td>{3}</td> \
                <td>{4}</td> \
                <td>{5}</td> \
                <td>{6}</td> \
                <td>{7}</td> \
                </tr>'.format(report['business'], report['address'], report['port'], report['service'], report['protocol'], report['version'], report['product'], report['extrainfo'])

    content += '''
</table>
</body>
</html>
'''


    sender = 'scan@example.com'
    mailto = ['a@example.com', 'b@example.com']
    subject = '端口扫描报表'
    msg = MIMEText(content, 'html', 'utf-8')
    msg['from'] = 'scan@example.com'
    msg['to'] = ','.join(mailto)
    msg['subject'] = subject

    try:
        smtpobj = smtplib.SMTP('mail.example.com')
        smtpobj.sendmail(sender, mailto, msg.as_string())
        smtpobj.quit
        print '-'*60 + '\n' + '邮件发送成功'
    except Exception,e:
        print e


# 60秒检测一次标志位，如果标志位为0则将报表推送到另一个redis，并将标志位置1，同时发送对比结果邮件
if __name__ == '__main__':
    while 1:
        sign = redis_data.get('nmap_sign')
        if int(sign) == 0:
            get_open_port()
            for report in today_reports:
                redis_data.rpush('nmap_report', report)
            # 报表只保留最近两天的
            redis_data.delete('scan_report_{}'.format(b_yesterday))
            # 发送当天新增端口的邮件
            send_mail()
            # 标志位置1
            redis_data.set('nmap_sign', 1)
            break
        else:
            time.sleep(60)
