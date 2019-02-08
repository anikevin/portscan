# 扫描流程
准备至少两台服务器，一台作为客户端，安装redis。一台作为服务端，用于扫描，服务端可扩展
1. nmap -sP扫描存活IP
2. 存活主机IP以32每份（可设置）进行分割，每份相当于1个扫描任务。将任务根据服务端数量平均分配，同时设置下发的总任务数为标志位，写入redis 
3. 服务端监听在某个端口上，当收到客户端下发的存活主机IP地址后，并行扫描存活主机TCP全端口 
4. 服务端扫描完成后，将结果传回客户端redis里，同时将标志位减1
5. 当所有扫描任务完成后，标志位变为0，客户端监控脚本发送对比结果邮件


# 文件说明
* client.py:  获取存活IP，分割IP下发任务
* server.py:  监听是否有任务，对存活主机进行全端口扫描，回传扫描结果
* monitor.py: 判断标志位，发送端口对比邮件


# 使用方法
* 客户端运行 <br />
nohup python client.py &
nohup python monitor.py &
* 服务端运行 <br />
nohup python server.py -t 5 -ht 500m &


# 第三方库
* pip install -r requirements.txt
