#!/bin/bash
echo "安徽三实捕影Linux安全检查与应急响应工具"
echo "Version:1.3"
echo "Author:飞鸟"
echo "Mail:liuquyong112@gmail.com"
echo "Date:2019-02-19"

cat <<EOF
*********************************************
Linux主机安全检查:
	1.首先采集原始信息保存到/tmp/buying_${ipadd}_${date}/check_file/文件夹下
	2.将系统日志、应用日志打包并保存到/tmp/buying_${ipadd}_${date}/log/目录下
	3.在检查过程中若发现存在问题则直接输出到/tmp/buying_${ipadd}_${date}/danger_file.txt文件中
	4.有些未检查可能存在问题的需要人工分析原始文件
	5.脚本编写环境Centos7,在实际使用过程中若发现问题可以邮件联系:liuquyong112@gmail.com
	6.使用过程中若在windows下修改再同步到Linux下，请使用dos2unix工具进行格式转换,不然可能会报错
	7.在使用过程中必须使用root账号,不然可能导致某些项无法分析

如何使用:
	1.本脚本可以单独运行,单独运行中只需要将本脚本上传到相应的服务器中,然后sh buying_linuxcheck.sh即可
	2.另外本脚本可以作为多台服务器全面检查的安全检查模板,本脚本不需要手工运行,只需要将相应服务器的IP、账号、密码写到hosts.txt文件中，然后sh login.sh即可

功能设计:
	1.V1.0主要功能用来采集信息
	2.V1.1主要功能将原始数据进行分析,并找出存在可疑或危险项
	3.V1.2增加基线检查的功能
	4.V1.3可以进行相关危险项或可疑项的自动处理


检查内容
	0.IP及版本
		0.1 IP地址
		0.2 版本信息
			0.2.1 系统内核版本
			0.2.2 系统发行版本
		0.3 ARP
			0.3.1 ARP表
			0.3.2 ARP攻击
	1.端口情况
		1.1 开放端口
			1.1.1 TCP开放端口
			1.1.2 UDP开放端口
		1.2 TCP高危端口
		1.3 UDP高危端口
	2.网络连接
	3.网卡模式
	4.自启动项
		4.1 用户自定义启动项
		4.2 系统自启动项
	5.定时任务
		5.1 系统定时任务
			5.1.1 时间看系统定时任务
			5.1.2 分析可疑系统定时任务
		5.2 用户定时任务
			5.2.1 时间看用户定时任务
			5.2.2 分析可疑用户定时任务
	6.路由与路由转发
	7.进程分析
		7.1 系统进程
		7.2 守护进程
	8.关键文件检查
		8.1 DNS文件
		8.2 hosts文件
		8.3 公钥文件
		8.4 私钥文件
	9.运行服务
	10.登录情况
	11.用户与用户组
		11.1 超级用户
		11.2 克隆用户
		11.3 可登录用户
		11.4 非系统用户
		11.5 shadow文件
		11.6 空口令用户
		11.7 空口令且可登录
		11.8 口令未加密
		11.9 用户组分析
			11.9.1 用户组情况
			11.9.2 特权用户
			11.9.3 相同UID用户组
			11.9.4 相同用户组名
		11.10 文件权限
			11.10.1 etc文件权限
			11.10.2 shadow文件权限
			11.10.3 passwd文件权限
			11.10.4 group文件权限
			11.10.5 securetty文件权限
			11.10.6 services文件权限
			11.10.7 grub.conf文件权限
			11.10.8 xinetd.conf文件权限
			11.10.9 lilo.conf文件权限
			11.10.10 limits.conf文件权限
	12.历史命令
		12.1 系统历史命令
			12.1.1 系统操作历史命令
			12.1.2 是否下载过脚本文件
			12.1.3 是否增加过账号
			12.1.4 是否删除过账号
			12.1.5 历史可疑命令
			12.1.6 本地下载文件
		12.2 数据库历史命令
	13.策略与配置
		13.1 防火墙策略
		13.2 远程访问策略
			13.2.1 远程允许策略
			13.2.2 远程拒绝策略
		13.3 账号与密码策略
			13.3.1 密码有效期策略
			13.3.2 密码复杂度策略
			13.3.3 密码已过期用户
			13.3.4 账号超时锁定策略
			13.3.5 grub密码策略检查
			13.3.6 lilo密码策略检查
		13.4 selinux策略
		13.5 sshd配置
			13.5.1 sshd配置
			13.5.2 空口令登录
			13.5.3 root远程登录
			13.5.4 ssh协议版本
		13.6 NIS配置
		13.7 Nginx配置
			13.7.1 原始配置
			13.7.2 可疑配置
		13.8 SNMP配置检查
	14.可疑文件
		14.1 脚本文件
		14.2 恶意文件
		14.3 最近变动的文件
		14.4 文件属性
			14.4.1 passwd文件属性
			14.4.2 shadow文件属性
			14.4.3 gshadow文件属性
			14.4.4 group文件属性
	15.系统文件完整性
	16.系统日志分析
		16.1 日志配置与打包
			16.1.1 查看日志配置
			16.1.2日志是否存在
			16.1.3 日志审核是否开启
			16.1.4 自动打包日志
		16.2 secure日志分析
			16.2.1 成功登录
			16.2.2 登录失败
			16.2.3 图形登录情况
			16.2.4 新建用户与用户组
		16.3 message日志分析
			16.3.1 传输文件
			16.3.2 历史使用DNS
		16.4 cron日志分析
			16.4.1 定时下载
			16.4.2 定时执行脚本
		16.5 yum日志分析
			16.5.1 下载软件情况
			16.5.2 卸载软件情况
			16.5.3 可疑软件
		16.6 dmesg日志分析
			16.6.1 内核自检分析
		16.7 btmp日志分析
			16.7.1 错误登录分析
		16.8 lastlog日志分析
			16.8.1 所有用户最后一次登录分析
		16.9 wtmp 日志分析
			16.9.1 所有用户登录分析
	17.内核检查
		17.1 内核信息
		17.2 异常内核
	18.安装软件
		18.1 安装软件
		18.2 可疑软件
	19.环境变量
	20.性能分析
		20.1 磁盘使用
			20.1.1 磁盘使用情况
			20.1.2 磁盘使用过大
		20.2 CPU
			20.2.1 CPU情况
			20.2.2 占用CPU前五进程
			20.2.3 占用CPU较多资源进程
		20.3 内存
			20.3.1 内存情况
			20.3.2 占用内存前五进程
			20.3.3 占用内存占多进程
		20.4 网络连接
			20.4.1 并发连接
		20.5 其他
			20.5.1 运行时间及负载情况
	21.共享情况


*********************************************
EOF

dos2unix buying.sh
date=$(date +%Y%m%d)

ipadd=$(ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}')

check_file="/tmp/buying_${ipadd}_${date}/check_file/"
danger_file="/tmp/buying_${ipadd}_${date}/danger_file.txt"
log_file="/tmp/buying_${ipadd}_${date}/log/"
rm -rf $check_file
rm -rf $danger_file
rm -rf log_file
mkdir /tmp/buying_${ipadd}_${date}/
echo "检查发现危险项,请注意:" > ${danger_file}
mkdir $check_file
echo "" >> $danger_file
mkdir $log_file
cd $check_file

if [ $(whoami) != "root" ];then
	echo "安全检查必须使用root账号,否则某些项无法检查"
	exit 1
fi


saveresult="tee -a checkresult.txt"
echo "[0.1]正在检查IP地址....." && "$saveresult"

echo -------------0.IP及版本-------------------
echo -------------0.1IP地址-------------------
echo "[0.1]正在检查IP地址....." | $saveresult
ip=$(ifconfig -a | grep -w inet | awk '{print $2}')
if [ -n "$ip" ];then
	(echo "[*]本机IP地址信息:" && echo "$ip")  | $saveresult
else
	echo "[!!!]本机未配置IP地址" | $saveresult
fi
printf "\n" | $saveresult

echo -------------0.2版本信息------------------
echo "[0.2.1]正在检查系统内核版本....." | $saveresult
corever=$(uname -a)
if [ -n "$corever" ];then
	(echo "[*]系统内核版本信息:" && echo "$corever") | $saveresult
else
	echo "[!!!]未发现内核版本信息" | $saveresult
fi
printf "\n" | $saveresult

echo "[0.2.2]正在检查系统发行版本....." | $saveresult
systemver=$(cat /etc/redhat-release)
if [ -n "$systemver" ];then
	(echo "[*]系统发行版本:" && echo "$systemver") | $saveresult
else
	echo "[!!!]未发现发行版本信息" | $saveresult
fi
printf "\n" | $saveresult

echo -------------0.3 ARP------------------
echo -------------0.3.1 ARP表项-------------
echo "[0.3.1]正在查看ARP表项....." | $saveresult
arp=$(arp -a -n)
if [ -n "$arp" ];then
	(echo "[*]ARP表项如下:" && echo "$arp") | $saveresult
else
	echo "[未发现arp表]" | $saveresult
fi
printf "\n" | $saveresult

echo -------------0.3.2 ARP攻击-------------
echo "[0.3.2]正在检测是否存在ARP攻击....." | $saveresult
arpattack=$(arp -a -n | awk '{++S[$4]} END {for(a in S) {if($2>1) print $2,a,S[a]}}')
if [ -n "$arpattack" ];then
	(echo "[!!!]发现存在ARP攻击:" && echo "$arpattack") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现ARP攻击" | $saveresult
fi
printf "\n" | $saveresult

echo ------------1.查看端口情况-----------------
echo -------------1.1 查看开放端口--------------
echo -------------1.1.1 查看TCP开放端口--------------
#TCP或UDP端口绑定在0.0.0.0、127.0.0.1、192.168.1.1这种IP上只表示这些端口开放
#只有绑定在0.0.0.0上局域网才可以访问
echo "[1.1.1]正在检查TCP开放端口....." | $saveresult
listenport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$listenport" ];then
	(echo "[*]该服务器开放TCP端口以及对应的服务:" && echo "$listenport") | $saveresult
else
	echo "[!!!]系统未开放TCP端口" | $saveresult
fi
printf "\n" | $saveresult

accessport=$(netstat -anltp | grep LISTEN | awk  '{print $4,$7}' | egrep "(0.0.0.0|:::)" | sed 's/:/ /g' | awk '{print $(NF-1),$NF}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$accessport" ];then
	(echo "[!!!]以下TCP端口面向局域网或互联网开放,请注意！" && echo "$accessport") | $saveresult
else
	echo "[*]端口未面向局域网或互联网开放" | $saveresult
fi
printf "\n" | $saveresult

echo -------------1.1.2 查看UDP开放端口--------------
echo "[1.1.2]正在检查UDP开放端口....." | $saveresult
udpopen=$(netstat -anlup | awk  '{print $4,$NF}' | grep : | sed 's/:/ /g' | awk '{print $2,$3}' | sed 's/\// /g' | awk '{printf "%-20s%-10s\n",$1,$NF}' | sort -n | uniq)
if [ -n "$udpopen" ];then
	(echo "[*]该服务器开放UDP端口以及对应的服务:" && echo "$udpopen") | $saveresult
else
	echo "[!!!]系统未开放UDP端口" | $saveresult
fi
printf "\n" | $saveresult

udpports=$(netstat -anlup | awk '{print $4}' | egrep "(0.0.0.0|:::)" | awk -F: '{print $NF}' | sort -n | uniq)
if [ -n "$udpports" ];then
	echo "[*]以下UDP端口面向局域网或互联网开放:" | $saveresult
	for port in $udpports
	do
		nc -uz 127.0.0.1 $port
		if [ $? -eq 0 ];then
			echo $port  | $saveresult
		fi
	done
else 
	echo "[*]未发现在UDP端口面向局域网或互联网开放." | $saveresult
fi
printf "\n" | $saveresult

echo -------------1.2 TCP高危端口--------------
echo "[1.2]正在检查TCP高危端口....." | $saveresult
tcpport=`netstat -anlpt | awk '{print $4}' | awk -F: '{print $NF}' | sort | uniq | grep '[0-9].*'`
count=0
if [ -n "$tcpport" ];then
	for port in $tcpport
	do
		for i in `cat /tmp/dangerstcpports.dat`
		do
			tcpport=`echo $i | awk -F "[:]" '{print $1}'`
			desc=`echo $i | awk -F "[:]" '{print $2}'`
			process=`echo $i | awk -F "[:]" '{print $3}'`
			if [ $tcpport == $port ];then
				echo "$tcpport,$desc,$process" | tee -a $danger_file | $saveresult
				count=count+1
			fi
		done
	done
fi
if [ $count = 0 ];then
	echo "[*]未发现TCP危险端口" | $saveresult
else
	echo "[!!!]请人工对TCP危险端口进行关联分析与确认" | $saveresult
fi
printf "\n" | $saveresult

echo -------------1.3 UDP高危端口--------------
echo "[1.3]正在检查UDP高危端口....."
udpport=`netstat -anlpu | awk '{print $4}' | awk -F: '{print $NF}' | sort | uniq | grep '[0-9].*'`
count=0
if [ -n "$udpport" ];then
	for port in $udpport
	do
		for i in `cat /tmp/dangersudpports.dat`
		do
			udpport=`echo $i | awk -F "[:]" '{print $1}'`
			desc=`echo $i | awk -F "[:]" '{print $2}'`
			process=`echo $i | awk -F "[:]" '{print $3}'`
			if [ $udpport == $port ];then
				echo "$udpport,$desc,$process" | tee -a $danger_file | $saveresult
				count=count+1
			fi
		done
	done
fi
if [ $count = 0 ];then
	echo "[*]未发现UDP危险端口" | $saveresult
else
	echo "[!!!]请人工对UDP危险端口进行关联分析与确认"
fi
printf "\n" | $saveresult

echo ------------2.网络连接---------------------
echo "[2.1]正在检查网络连接情况....." | $saveresult
netstat=$(netstat -anlp | grep ESTABLISHED)
netstatnum=$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
if [ -n "$netstat" ];then
	(echo "[*]网络连接情况:" && echo "$netstat") | $saveresult
	if [ -n "$netstatnum" ];then
		(echo "[*]各个状态的数量如下:" && echo "$netstatnum") | $saveresult
	fi
else
	echo "[*]未发现网络连接" | $saveresult
fi
printf "\n" | $saveresult

echo -------------3.网卡模式---------------------
echo "[3.1]正在检查网卡模式....." | $saveresult
ifconfigmode=$(ifconfig -a | grep flags | awk -F '[: = < >]' '{print "网卡:",$1,"模式:",$5}')
if [ -n "$ifconfigmode" ];then
	(echo "网卡工作模式如下:" && echo "$ifconfigmode") | $saveresult
else
	echo "[*]未找到网卡模式相关信息,请人工分析" | $saveresult
fi
printf "\n" | $saveresult

echo "[3.2]正在分析是否有网卡处于混杂模式....." | $saveresult
Promisc=`ifconfig | grep PROMISC | gawk -F: '{ print $1}'`
if [ -n "$Promisc" ];then
	(echo "[!!!]网卡处于混杂模式:" && echo "$Promisc") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现网卡处于混杂模式" | $saveresult
fi
printf "\n" | $saveresult

echo "[3.3]正在分析是否有网卡处于监听模式....." | $saveresult
Monitor=`ifconfig | grep -E "Mode:Monitor" | gawk -F: '{ print $1}'`
if [ -n "$Monitor" ];then
	(echo "[!!!]网卡处于监听模式:" && echo "$Monitor") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现网卡处于监听模式" | $saveresult
fi
printf "\n" | $saveresult

echo -------------4.启动项-----------------------
echo -------------4.1 用户自定义启动项-----------------------
echo "[4.1]正在检查用户自定义启动项....." | $saveresult
chkconfig=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}')
if [ -n "$chkconfig" ];then
	(echo "[*]用户自定义启动项:" && echo "$chkconfig") | $saveresult
else
	echo "[!!!]未发现用户自定义启动项" | $saveresult
fi
printf "\n" | $saveresult

echo -------------4.2 系统自启动项-----------------------
echo "[4.2]正在检查系统自启动项....." | $saveresult
systemchkconfig=$(systemctl list-unit-files | grep enabled | awk '{print $1}')
if [ -n "$systemchkconfig" ];then
	(echo "[*]系统自启动项如下:" && echo "$systemchkconfig")  | $saveresult
else
	echo "[*]未发现系统自启动项" | $saveresult
fi
printf "\n" | $saveresult

echo -------------4.3 危险启动项-----------------------
echo "[4.3]正在检查危险启动项....." | $saveresult
dangerstarup=$(chkconfig --list | grep -E ":on|启用" | awk '{print $1}' | grep -E "\.(sh|per|py)$")
if [ -n "$dangerstarup" ];then
	(echo "[!!!]发现危险启动项:" && echo "$dangerstarup") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现危险启动项" | $saveresult
fi
printf "\n" | $saveresult

echo ------------5.查看定时任务-------------------
echo ------------5.1系统定时任务分析-------------------
echo ------------5.1.1查看系统定时任务-------------------
echo "[5.1.1]正在分析系统定时任务....." | $saveresult
syscrontab=$(more /etc/crontab | grep -v "# run-parts" | grep run-parts)
if [ -n "$syscrontab" ];then
	(echo "[!!!]发现存在系统定时任务:" && more /etc/crontab ) | tee -a $danger_file | $saveresult
else
	echo "[*]未发现系统定时任务" | $saveresult
fi
printf "\n" | $saveresult

# if [ $? -eq 0 ]表示上面命令执行成功;执行成功输出的是0；失败非0
#ifconfig  echo $? 返回0，表示执行成功
# if [ $? != 0 ]表示上面命令执行失败

echo ------------5.1.2分析系统可疑定时任务-------------------
echo "[5.1.2]正在分析系统可疑任务....." | $saveresult
dangersyscron=$(egrep "((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)$))"  /etc/cron*/* /var/spool/cron/*)
if [ $? -eq 0 ];then
	(echo "[!!!]发现下面的定时任务可疑,请注意！！！" && echo "$dangersyscron") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑系统定时任务" | $saveresult
fi
printf "\n" | $saveresult

echo ------------5.2分析用户定时任务-------------------
echo ------------5.2.1查看用户定时任务-------------------
echo "[5.2.1]正在查看用户定时任务....." | $saveresult
crontab=$(crontab -l)
if [ $? -eq 0 ];then
	(echo "[!!!]发现用户定时任务如下:" && echo "$crontab") | $saveresult
else
	echo "[*]未发现用户定时任务"  | $saveresult
fi
printf "\n" | $saveresult

echo ------------5.2.2查看可疑用户定时任务-------------------
echo "[5.2.2]正在分析可疑用户定时任务....." | $saveresult
danger_crontab=$(crontab -l | egrep "((chmod|useradd|groupadd|chattr)|((wget|curl).*\.(sh|pl|py)))")
if [ $? -eq 0 ];then
	(echo "[!!!]发现可疑定时任务,请注意！！！" && echo "$danger_crontab") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑定时任务" | $saveresult
fi
printf "\n" | $saveresult

echo -------------6.路由与路由转发----------------
echo "[6.1]正在检查路由表....." | $saveresult
route=$(route -n)
if [ -n "$route" ];then
	(echo "[*]路由表如下:" && echo "$route") | $saveresult
else
	echo "[*]未发现路由器表" | $saveresult
fi
printf "\n" | $saveresult

echo "[6.2]正在分析是否开启转发功能....." | $saveresult
#数值分析
#1:开启路由转发
#0:未开启路由转发
ip_forward=`more /proc/sys/net/ipv4/ip_forward | gawk -F: '{if ($1==1) print "1"}'`
if [ -n "$ip_forward" ];then
	echo "[!!!]该服务器开启路由转发,请注意！" | tee -a $danger_file  | $saveresult
else
	echo "[*]该服务器未开启路由转发" | $saveresult
fi
printf "\n" | $saveresult

echo ------------7.进程分析--------------------
echo ------------7.1系统进程--------------------
echo "[7.1]正在检查进程....." | $saveresult
ps=$(ps -aux)
if [ -n "$ps" ];then
	(echo "[*]系统进程如下:" && echo "$ps") | $saveresult
else
	echo "[*]未发现系统进程" | $saveresult
fi
printf "\n" | $saveresult

echo "[7.2]正在检查守护进程....." | $saveresult
if [ -e /etc/xinetd.d/rsync ];then
	(echo "[*]系统守护进程:" && more /etc/xinetd.d/rsync | grep -v "^#") | $saveresult
else
	echo "[*]未发现守护进程" | $saveresult
fi
printf "\n" | $saveresult

echo ------------8.关键文件检查-----------------
echo ------------8.1DNS文件检查-----------------
echo "[8.1]正在检查DNS文件....." | $saveresult
resolv=$(more /etc/resolv.conf | grep ^nameserver | awk '{print $NF}') 
if [ -n "$resolv" ];then
	(echo "[*]该服务器使用以下DNS服务器:" && echo "$resolv") | $saveresult
else
	echo "[*]未发现DNS服务器" | $saveresult
fi
printf "\n" | $saveresult

echo ------------8.2hosts文件检查-----------------
echo "[8.2]正在检查hosts文件....." | $saveresult
hosts=$(more /etc/hosts)
if [ -n "$hosts" ];then
	(echo "[*]hosts文件如下:" && echo "$hosts") | $saveresult
else
	echo "[*]未发现hosts文件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------8.3公钥文件检查-----------------
echo "[8.3]正在检查公钥文件....." | $saveresult
if [  -e /root/.ssh/*.pub ];then
	echo "[!!!]发现公钥文件,请注意！"  | tee -a $danger_file | $saveresult
else
	echo "[*]未发现公钥文件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------8.4私钥文件检查-----------------
echo "[8.4]正在检查私钥文件....." | $saveresult
if [ -e /root/.ssh/id_rsa ];then
	echo "[!!!]发现私钥文件,请注意！" | tee -a $danger_file | $saveresult
else
	echo "[*]未发现私钥文件" | $saveresult
fi
printf "\n" | $saveresult


echo ------------9.运行服务----------------------
echo "[9.1]正在检查运行服务....." | $saveresult
services=$(systemctl | grep -E "\.service.*running" | awk -F. '{print $1}')
if [ -n "$services" ];then
	(echo "[*]以下服务正在运行：" && echo "$services") | $saveresult
else
	echo "[!!!]未发现正在运行的服务！" | $saveresult
fi
printf "\n" | $saveresult

echo ------------10.查看登录用户------------------
echo "[10.1]正在检查正在登录的用户....." | $saveresult
(echo "[*]系统登录用户:" && who ) | $saveresult
printf "\n" | $saveresult

echo ------------11.查看用户信息------------------
echo "[11]正在查看用户信息....." | $saveresult
echo "[*]用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录Shell" | $saveresult
more /etc/passwd  | $saveresult
printf "\n" | $saveresult

echo ------------11.1超级用户---------------------
#UID=0的为超级用户,系统默认root的UID为0
echo "[11.1]正在检查是否存在超级用户....." | $saveresult
Superuser=`more /etc/passwd | egrep -v '^root|^#|^(\+:\*)?:0:0:::' | awk -F: '{if($3==0) print $1}'`
if [ -n "$Superuser" ];then
	echo "[!!!]除root外发现超级用户:" | tee -a $danger_file | $saveresult
	for user in $Superuser
	do
		echo $user | $saveresult
		if [ "${user}" = "toor" ];then
			echo "[!!!]BSD系统默认安装toor用户,其他系统默认未安装toor用户,若非BSD系统建议删除该账号" | $saveresult
		fi
	done
else
	echo "[*]未发现超级用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.2克隆用户---------------------
#相同的UID为克隆用户
echo "[11.2]正在检查是否存在克隆用户....." | $saveresult
uid=`awk -F: '{a[$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd`
if [ -n "$uid" ];then
	echo "[!!!]发现下面用户的UID相同:" | tee -a $danger_file | $saveresult
	(more /etc/passwd | grep $uid | awk -F: '{print $1}') | tee -a $danger_file | $saveresult
else
	echo "[*]未发现相同UID的用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.3可登录用户-------------------
echo "[11.3]正在检查可登录的用户......" | $saveresult
loginuser=`cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}'`
if [ -n "$loginuser" ];then
	echo "[!!!]以下用户可以登录：" | tee -a $danger_file | $saveresult
	for user in $loginuser
	do
		echo $user | tee -a $danger_file | $saveresult
	done
else
	echo "[*]未发现可以登录的用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.4非系统用户-----------------
echo "[11.4]正在检查非系统本身自带用户" | $saveresult
if [ -f /etc/login.defs ];then
	uid=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
	(echo "系统最小UID为"$uid) | $saveresult
	nosystemuser=`gawk -F: '{if ($3>='$uid' && $3!=65534) {print $1}}' /etc/passwd`
	if [ -n "$nosystemuser" ];then
		(echo "以下用户为非系统本身自带用户:" && echo "$nosystemuser") | tee -a $danger_file | $saveresult
	else
		echo "[*]未发现除系统本身外的其他用户" | $saveresult
	fi
fi
printf "\n" | $saveresult

echo ------------11.5shadow文件-----------------
echo "[11.5]正在检查shadow文件....." | $saveresult
(echo "[*]shadow文件" && more /etc/shadow ) | $saveresult
printf "\n" | $saveresult

echo ------------11.6空口令用户-----------------
echo "[11.6]正在检查空口令用户....." | $saveresult
nopasswd=`gawk -F: '($2=="") {print $1}' /etc/shadow`
if [ -n "$nopasswd" ];then
	(echo "[!!!]以下用户口令为空：" && echo "$nopasswd") | $saveresult
else
	echo "[*]未发现空口令用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.7空口令且可登录-----------------
echo "[11.7]正在检查空口令且可登录的用户....." | $saveresult
#允许空口令用户登录方法
#1.passwd -d username
#2.echo "PermitEmptyPasswords yes" >>/etc/ssh/sshd_config
#3.service sshd restart
aa=$(cat /etc/passwd  | grep -E "/bin/bash$" | awk -F: '{print $1}')
bb=$(gawk -F: '($2=="") {print $1}' /etc/shadow)
cc=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
flag=""
for a in $aa
do
    for b in $bb
    do
        if [ "$a" = "$b" ] && [ -n "$cc" ];then
            echo "[!!!]发现空口令且可登录用户:"$a | $saveresult
            flag=1
        fi
    done
done
if [ -n "$flag" ];then
	echo "请人工分析配置和账号" | $saveresult
else
	echo "[*]未发现空口令且可登录用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.8口令未加密----------------
echo "[11.8]正在检查口令加密用户....." | $saveresult
noenypasswd=$(awk -F: '{if($2!="x") {print $1}}' /etc/passwd)
if [ -n "$noenypasswd" ];then
	(echo "[!!!]以下用户口令未加密:" && echo "$noenypasswd") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现口令未加密的用户"  | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.9用户组分析-----------------------
echo ------------11.9.1 用户组信息------------ ----
echo "[11.9.1]正在检查用户组信息....." | $saveresult
echo "[*]用户组信息如下:"
(more /etc/group | grep -v "^#") | $saveresult
printf "\n" | $saveresult

echo ------------11.9.2 特权用户--------------------
echo "[11.9.2]正在检查特权用户....." | $saveresult
roots=$(more /etc/group | grep -v '^#' | gawk -F: '{if ($1!="root"&&$3==0) print $1}')
if [ -n "$roots" ];then
	echo "[!!!]除root用户外root组还有以下用户:" | tee -a $danger_file | $saveresult
	for user in $roots
	do
		echo $user | tee -a $danger_file | $saveresult
	done
else 
	echo "[*]除root用户外root组未发现其他用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.9.3 相同GID用户组--------------------
echo "[11.9.3]正在检查相应GID用户组....." | $saveresult
groupuid=$(more /etc/group | grep -v "^$" | awk -F: '{print $3}' | uniq -d)
if [ -n "$groupuid" ];then
	(echo "[!!!]发现相同GID用户组:" && echo "$groupuid") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现相同GID的用户组" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.9.4 相同用户组名--------------------
echo "[11.9.4]正在检查相同用户组名....." | $saveresult
groupname=$(more /etc/group | grep -v "^$" | awk -F: '{print $1}' | uniq -d)
if [ -n "$groupname" ];then
	(echo "[!!!]发现相同用户组名:" && echo "$groupname") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现相同用户组名" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10 文件权限--------------------
echo ------------11.10.1 etc文件权限--------------------
echo "[11.10.1]正在检查etc文件权限....." | $saveresult
etc=$(ls -l / | grep etc | awk '{print $1}')
if [ "${etc:1:9}" = "rwxr-x---" ]; then
    echo "[*]/etc/权限为750,权限正常" | $saveresult
else
    echo "[!!!]/etc/文件权限为:""${etc:1:9}","权限不符合规划,权限应改为750" | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.2 shadow文件权限--------------------
echo "[11.10.2]正在检查shadow文件权限....." | $saveresult
shadow=$(ls -l /etc/shadow | awk '{print $1}')
if [ "${shadow:1:9}" = "rw-------" ]; then
    echo "[*]/etc/shadow文件权限为600,权限符合规范" | $saveresult
else
    echo "[!!!]/etc/shadow文件权限为:""${shadow:1:9}"",不符合规范,权限应改为600" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.3 passwd文件权限--------------------
echo "[11.10.3]正在检查passwd文件权限....." | $saveresult
passwd=$(ls -l /etc/passwd | awk '{print $1}')
if [ "${passwd:1:9}" = "rw-r--r--" ]; then
    echo "[*]/etc/passwd文件权限为644,符合规范" | $saveresult
else
    echo "[!!!]/etc/passwd文件权限为:""${passwd:1:9}"",权限不符合规范,建议改为644" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.4 group文件权限--------------------
echo "[11.10.4]正在检查group文件权限....." | $saveresult
group=$(ls -l /etc/group | awk '{print $1}')
if [ "${group:1:9}" = "rw-r--r--" ]; then
    echo "[*]/etc/group文件权限为644,符合规范" | $saveresult
else
    echo "[!!!]/etc/goup文件权限为""${group:1:9}","不符合规范,权限应改为644" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.5 securetty文件权限--------------------
echo "[11.10.5]正在检查securetty文件权限....." | $saveresult
securetty=$(ls -l /etc/securetty | awk '{print $1}')
if [ "${securetty:1:9}" = "-rw-------" ]; then
    echo "[*]/etc/securetty文件权限为600,符合规范" | $saveresult
else
    echo "[!!!]/etc/securetty文件权限为""${securetty:1:9}","不符合规范,权限应改为600" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.6 services文件权限--------------------
echo "[11.10.6]正在检查services文件权限....." | $saveresult
services=$(ls -l /etc/services | awk '{print $1}')
if [ "${services:1:9}" = "-rw-r--r--" ]; then
    echo "[*]/etc/services文件权限为644,符合规范" | $saveresult
else
    echo "[!!!]/etc/services文件权限为""$services:1:9}","不符合规范,权限应改为644" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.7 grub.conf文件权限--------------------
echo "[11.10.7]正在检查grub.conf文件权限....." | $saveresult
grubconf=$(ls -l /etc/grub.conf | awk '{print $1}')
if [ "${grubconf:1:9}" = "-rw-------" ]; then
    echo "[*]/etc/grub.conf文件权限为600,符合规范" | $saveresult
else
    echo "[!!!]/etc/grub.conf文件权限为""${grubconf:1:9}","不符合规范,权限应改为600" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.8 xinetd.conf文件权限--------------------
echo "[11.10.8]正在检查xinetd.conf文件权限....." | $saveresult
xinetdconf=$(ls -l /etc/xinetd.conf | awk '{print $1}')
if [ "${xinetdconf:1:9}" = "-rw-------" ]; then
    echo "[*]/etc/xinetd.conf文件权限为600,符合规范" | $saveresult
else
    echo "[!!!]/etc/xinetd.conf文件权限为""${xinetdconf:1:9}","不符合规范,权限应改为600" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------11.10.9 lilo.conf文件权限--------------------
echo "[11.10.9]正在检查lilo.conf文件权限....." | $saveresult
if [ -f /etc/lilo.conf ];then
liloconf=$(ls -l /etc/lilo.conf | awk '{print $1}')
	if [ "${liloconf:1:9}" = "-rw-------" ];then
		echo "/etc/lilo.conf文件权限为600,符合要求" | $saveresult
	else
		echo "/etc/lilo.conf文件权限不为600,不符合要求,建议设置权限为600" | $saveresult
	fi
else
	echo "/etc/lilo.conf文件夹不存在,不检查,符合要求"
fi
printf "\n" | $saveresult

echo ------------11.10.10 limits.conf文件权限--------------------
echo "[11.10.10]正在检查limits.conf文件权限....." | $saveresult
cat /etc/security/limits.conf | grep -v ^# | grep core
if [ $? -eq 0 ];then
	soft=`cat /etc/security/limits.conf | grep -v ^# | grep core | awk -F ' ' '{print $2}'`
	for i in $soft
	do
		if [ $i = "soft" ];then
			echo "* soft core 0 已经设置,符合要求" | $saveresult
		fi
		if [ $i = "hard" ];then
			echo "* hard core 0 已经设置,符合要求" | $saveresult
		fi
	done
else 
	echo "没有设置core,建议在/etc/security/limits.conf中添加* soft core 0和* hard core 0"  | $saveresult
fi

echo ------------11.11其他--------------------
###############################################
#Access:访问时间,每次访问文件时都会更新这个时间,如使用more、cat
#Modify:修改时间,文件内容改变会导致该时间更新
#Change:改变时间,文件属性变化会导致该时间更新,当文件修改时也会导致该时间更新;但是改变文件的属性,如读写权限时只会导致该时间更新，不会导致修改时间更新
###############################################
echo "[11.11]正在检查useradd时间属性....." | $saveresult
echo "[*]useradd时间属性:" | $saveresult
stat /usr/sbin/useradd | egrep "Access|Modify|Change" | grep -v '(' | $saveresult
printf "\n" | $saveresult

echo "[11.11]正在检查userdel时间属性....." | $saveresult
echo "[*]userdel时间属性:" | $saveresult
stat /usr/sbin/userdel | egrep "Access|Modify|Change" | grep -v '(' | $saveresult
printf "\n" | $saveresult

echo ------------12历史命令--------------------------
echo ------------12.1系统操作历史命令---------------
echo ------------12.1.1系统操作历史命令---------------
echo "[12.1.1]正在检查操作系统历史命令....." | $saveresult
history=$(more /root/.bash_history)
if [ -n "$history" ];then
	(echo "[*]操作系统历史命令如下:" && echo "$history") | $saveresult
else
	echo "[!!!]未发现历史命令,请检查是否记录及已被清除" | $saveresult
fi
printf "\n" | $saveresult

echo ------------12.1.2是否下载过脚本文件---------------
echo "[12.1.2]正在检查是否下载过脚本文件....." | $saveresult
scripts=$(more /root/.bash_history | grep -E "((wget|curl).*\.(sh|pl|py)$)" | grep -v grep)
if [ -n "$scripts" ];then
	(echo "[!!!]该服务器下载过脚本以下脚本：" && echo "$scripts") | tee -a $danger_file | $saveresult
else
	echo "[*]该服务器未下载过脚本文件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------12.1.3是否增加过账号---------------
echo "[12.1.3]正在检查是否增加过账号....." | $saveresult
addusers=$(history | egrep "(useradd|groupadd)" | grep -v grep)
if [ -n "$addusers" ];then
	(echo "[!!!]该服务器增加过以下账号:" && echo "$addusers") | tee -a $danger_file | $saveresult
else
	echo "[*]该服务器未增加过账号" | $saveresult
fi
printf "\n" | $saveresult

echo ------------12.1.4是否删除过账号--------------
echo "[12.1.4]正在检查是否删除过账号....." | $saveresult
delusers=$(history | egrep "(userdel|groupdel)" | grep -v grep)
if [ -n "$delusers" ];then
	(echo "[!!!]该服务器删除过以下账号:" && echo "$delusers") | tee -a $danger_file | $saveresult
else
	echo "[*]该服务器未删除过账号" | $saveresult
fi
printf "\n" | $saveresult

echo ------------12.1.5可疑历史命令--------------
echo "[12.1.5]正在检查历史可疑命令....." | $saveresult
danger_histroy=$(history | grep -E "(whois|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)" | grep -v grep)
if [ -n "$danger_histroy" ];then
	(echo "[!!!]发现可疑历史命令" && echo "$danger_histroy") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑历史命令" | $saveresult
fi
printf "\n" | $saveresult

echo ------------12.1.6本地下载文件--------------
echo "[12.1.6]正在检查历史日志中本地下载文件记录....." | $saveresult
uploadfiles=$(history | grep sz | grep -v grep | awk '{print $3}')
if [ -n "$uploadfiles" ];then
	(echo "[!!!]通过历史日志发现本地主机下载过以下文件:" && echo "$uploadfiles") | $saveresult
else
	echo "[*]通过历史日志未发现本地主机下载过文件" | $saveresult
fi
printf "\n" | $saveresult


echo ------------12.2数据库操作历史命令---------------
echo "[12.2]正在检查数据库操作历史命令....." | $saveresult
mysql_history=$(more /root/.mysql_history)
if [ -n "$mysql_history" ];then
	(echo "[*]数据库操作历史命令如下:" && echo "$mysql_history") | $saveresult
else
	echo "[*]未发现数据库历史命令" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.策略情况---------------------
echo ------------13.1防火墙策略-------------------
echo "[13.1]正在检查防火墙策略....." | $saveresult
firewalledstatus=$(systemctl status firewalld | grep "active (running)")
firewalledpolicy=$(iptables -L | grep "\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}")
if [ -n "$firewalledstatus" ];then
	echo "[*]该服务器防火墙已打开"
	if [ -n "$firewalledpolicy" ];then
		(echo "[*]防火墙策略如下" && echo "$firewalledpolicy") | $saveresult
	else
		echo "[!!!]防火墙策略未配置,建议配置防火墙策略!" | tee -a $danger_file | $saveresult
	fi
else
	echo "[！！！]防火墙未开启,建议开启防火墙" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.2远程访问策略-----------------
echo ------------13.2.1远程允许策略-----------------
echo "[13.2.1]正在检查远程允许策略....." | $saveresult
hostsallow=$(more /etc/hosts.allow | grep -v '#')
if [ -n "$hostsallow" ];then
	(echo "[!!!]允许以下IP远程访问:" && echo "$hostsallow") | tee -a $danger_file | $saveresult
else
	echo "[*]hosts.allow文件未发现允许远程访问地址" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.2.2远程拒绝策略-----------------
echo "[13.2.2]正在检查远程拒绝策略....." | $saveresult
hostsdeny=$(more /etc/hosts.deny | grep -v '#')
if [ -n "$hostsdeny" ];then
	(echo "[!!!]拒绝以下IP远程访问:" && echo "$hostsdeny") | $saveresult
else
	echo "[*]hosts.deny文件未发现拒绝远程访问地址" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.3密码策略------------------------
echo ------------13.3.1密码有效期策略------------------------
echo "[13.3.1]正在检查密码有效期策略....." | $saveresult
(echo "[*]密码有效期策略如下:" && more /etc/login.defs | grep -v "#" | grep PASS ) | $saveresult
printf "\n" | $saveresult

echo "[*]正在进行具体项的基线检查......" | $saveresult
passmax=$(cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}')
if [ $passmax -le 90 -a $passmax -gt 0 ];then
	echo "[*]口令生存周期为${passmax}天,符合要求" | $saveresult
else
	echo "[!!!]口令生存周期为${passmax}天,不符合要求,建议设置为0-90天" | $saveresult
fi

passmin=$(cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}')
if [ $passmin -ge 6 ];then
	echo "[*]口令更改最小时间间隔为${passmin}天,符合要求" | $saveresult
else
	echo "[!!!]口令更改最小时间间隔为${passmin}天,不符合要求,建议设置不小于6天" | $saveresult
fi

passlen=$(cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}')
if [ $passlen -ge 8 ];then
	echo "[*]口令最小长度为${passlen},符合要求" | $saveresult
else
	echo "[!!!]口令最小长度为${passlen},不符合要求,建议设置最小长度大于等于8" | $saveresult
fi

passage=$(cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}')
if [ $passage -ge 30 -a $passage -lt $passmax ];then
	echo "[*]口令过期警告时间天数为${passage},符合要求" | $saveresult
else
	echo "[!!!]口令过期警告时间天数为${passage},不符合要求,建议设置大于等于30并小于口令生存周期" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.3.2密码复杂度策略------------------------
echo "[13.3.1]正在检查密码复杂度策略....." | $saveresult
(echo "[*]密码复杂度策略如下:" && more /etc/pam.d/system-auth | grep -v "#") | $saveresult
printf "\n" | $saveresult

echo ------------13.3.3 密码已过期用户---------------------------
echo "[13.3.3]正在检查密码已过期用户....." | $saveresult
NOW=$(date "+%s")
day=$((${NOW}/86400))
passwdexpired=$(grep -v ":[\!\*x]([\*\!])?:" /etc/shadow | awk -v today=${day} -F: '{ if (($5!="") && (today>$3+$5)) { print $1 }}')
if [ -n "$passwdexpired" ];then
	(echo "[*]以下用户的密码已过期:" && echo "$passwdexpired")  | $saveresult
else
	echo "[*]未发现密码已过期用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.3.4 账号超时锁定策略---------------------------
echo "[13.3.4]正在检查账号超时锁定策略....." | $saveresult
account_timeout=`cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}'` 
if [ "$account_timeout" != ""  ];then
	TMOUT=`cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}'`
	if [ $TMOUT -le 600 -a $TMOUT -ge 10 ];then
		echo "[*]账号超时时间为${TMOUT}秒,符合要求" | $saveresult
	else
		echo "[!!!]账号超时时间为${TMOUT}秒,不符合要求,建议设置小于600秒" | $saveresult
fi
else
	echo "[!!!]账号超时未锁定,不符合要求,建议设置小于600秒" | $saveresult 
fi
printf "\n" | $saveresult

echo ------------13.3.5 grub密码策略检查---------------------------
echo "[13.3.5]正在检查grub密码策略....." | $saveresult
grubpass=$(cat /etc/grub.conf | grep password)
if [ $? -eq 0 ];then
	echo "[*]已设置grub密码,符合要求" | $saveresult 
else
	echo "[!!!]未设置grub密码,不符合要求,建议设置grub密码" | $saveresult 
fi
printf "\n" | $saveresult


echo ------------13.3.6 lilo密码策略检查---------------------------
echo "[13.3.6]正在检查lilo密码策略....." | $saveresult
if [ -f  /etc/lilo.conf ];then
	lilopass=$(cat /etc/lilo.conf | grep password 2> /dev/null)
	if [ $? -eq 0 ];then
		echo "[*]已设置lilo密码,符合要求" | $saveresult
	else
		echo "[!!!]未设置lilo密码,不符合要求,建议设置lilo密码" | $saveresult
	fi
else
	echo "[*]未发现/etc/lilo.conf文件" | $saveresult
fi


echo ------------13.4selinux策略----------------------
echo "[13.4]正在检查selinux策略....." | $saveresult
(echo "selinux策略如下:" && egrep -v '#|^$' /etc/sysconfig/selinux ) | $saveresult
printf "\n" | $saveresult

echo ------------13.5sshd配置文件--------------------
echo ------------13.5.1sshd配置----------------------
echo "[13.5.1]正在检查sshd配置....." | $saveresult
sshdconfig=$(more /etc/ssh/sshd_config | egrep -v "#|^$")
if [ -n "$sshdconfig" ];then
	(echo "[*]sshd配置文件如下:" && echo "$sshdconfig") | $saveresult
else
	echo "[！]未发现sshd配置文件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.5.2空口令登录检查--------------------
echo "[13.5.2]正在检查是否允许空口令登录....." | $saveresult
emptypasswd=$(cat /etc/ssh/sshd_config | grep -w "^PermitEmptyPasswords yes")
nopasswd=`gawk -F: '($2=="") {print $1}' /etc/shadow`
if [ -n "$emptypasswd" ];then
	echo "[!!!]允许空口令登录,请注意！！！"
	if [ -n "$nopasswd" ];then
		(echo "[!!!]以下用户空口令:" && echo "$nopasswd") | tee -a $danger_file | $saveresult
	else
		echo "[*]但未发现空口令用户" | $saveresult
	fi
else
	echo "[*]不允许空口令用户登录" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.5.3 root远程登录--------------------
echo "[13.5.3]正在检查是否允许root远程登录....." | $saveresult
cat /etc/ssh/sshd_config | grep -v ^# |grep "PermitRootLogin no"
if [ $? -eq 0 ];then
	echo "[*]root不允许登陆,符合要求" | $saveresult
else
	echo "[!!!]允许root远程登陆,不符合要求,建议/etc/ssh/sshd_config添加PermitRootLogin no" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.5.4 ssh协议版本--------------------
echo "[13.5.4]正在检查ssh协议版本....." | $saveresult
protocolver=$(more /etc/ssh/sshd_config | grep -v ^$ | grep Protocol | awk '{print $2}')
if [ "$protocolver" -eq "2" ];then
	echo "[*]openssh使用ssh2协议,符合要求" 
else
	echo "[!!!]openssh未ssh2协议,不符合要求"
fi

echo ------------13.6 NIS 配置文件--------------------
echo "[13.6]正在检查nis配置....." | $saveresult
nisconfig=$(more /etc/nsswitch.conf | egrep -v '#|^$')
if [ -n "$nisconfig" ];then
	(echo "[*]NIS服务配置如下:" && echo "$nisconfig") | $saveresult
else
	echo "[*]未发现NIS服务配置" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.7 Nginx配置----------------------
echo ------------13.7.1 Nginx配置---------------------
echo "[13.7.1]正在检查Nginx配置文件......" | $saveresult
nginx=$(whereis nginx | awk -F: '{print $2}')
if [ -n "$nginx" ];then
	(echo "[*]Nginx配置文件如下:" && more $nginx/conf/nginx.conf) | $saveresult
else
	echo "[*]未发现Nginx服务" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.7.2 Nginx端口转发分析-------------
echo "[13.7.2]正在检查Nginx端口转发配置......" | $saveresult
nginx=$(whereis nginx | awk -F: '{print $2}')
nginxportconf=$(more $nginx/conf/nginx.conf | egrep "listen|server |server_name |upstream|proxy_pass|location"| grep -v \#)
if [ -n "$nginxportconf" ];then
	(echo "[*]可能存在端口转发的情况,请人工分析:" && echo "$nginxportconf") | $saveresult
else
	echo "[*]未发现端口转发配置" | $saveresult
fi
printf "\n" | $saveresult

echo ------------13.8 SNMP配置检查-------------
echo "[13.8]正在检查SNMP配置......" | $saveresult
if [ -f /etc/snmp/snmpd.conf ];then
	public=$(cat /etc/snmp/snmpd.conf | grep public | grep -v ^# | awk '{print $4}')
	private=$(cat /etc/snmp/snmpd.conf | grep private | grep -v ^# | awk '{print $4}')
	if [ "$public" -eq "public" ];then
		echo "发现snmp服务存在默认团体名public,不符合要求" | $saveresult
	fi
	if [ "$private" -eq "private" ];then
		echo "发现snmp服务存在默认团体名private,不符合要求" | $saveresult
	fi
else
	echo "snmp服务配置文件不存在,可能没有运行snmp服务" | $saveresult
fi
printf "\n" | $saveresult

echo ------------14. 可疑文件-------------------------
echo ------------14.1 脚本文件------------------------
#下面脚本不查找/usr目录和/etc目录,检查时可以根据需求来调整
echo "[14.1]正在检查脚本文件....." | $saveresult
scripts=$(find / *.* | egrep "\.(py|sh|per|pl)$" | egrep -v "/usr|/etc|/var")
if [ -n "scripts" ];then
	(echo "[!!!]发现以下脚本文件,请注意！！！" && echo "$scripts") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现脚本文件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------14.2 恶意文件---------------------
#webshell这一块因为技术难度相对较高,并且已有专业的工具，目前这一块建议使用专门的安全检查工具来实现
#系统层的恶意文件建议使用rootkit专杀工具来查杀,如rkhunter,下载地址:http://rkhunter.sourceforge.net

echo ------------14.3 最近24小时内变动的文件---------------------
#查看最近24小时内有改变的文件
(find / -mtime 0 | grep -E "\.(py|sh|per|pl|php|asp|jsp)$") | tee -a $danger_file | $saveresult
printf "\n" | $saveresult


echo ------------14.4 文件属性---------------------
echo ------------14.4.1 passwd文件属性---------------------
echo "[14.4.1]正在检查passwd文件属性......" | $saveresult
flag=0
for ((x=1;x<=15;x++))
do
	apend=`lsattr /etc/passwd | cut -c $x`
	if [ $apend = "i" ];then
		echo "/etc/passwd文件存在i安全属性,符合要求" | $saveresult
		flag=1
	fi
	if [ $apend = "a" ];then
		echo "/etc/passwd文件存在a安全属性" | $saveresult
		flag=1
	fi
done

if [ $flag = 0 ];then
	echo "/etc/passwd文件不存在相关安全属性,建议使用chattr +i或chattr +a防止/etc/passwd被删除或修改" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------14.4.2 shadow文件属性---------------------
echo "[14.4.2]正在检查shadow文件属性......" | $saveresult
flag=0
for ((x=1;x<=15;x++))
do
	apend=`lsattr /etc/shadow | cut -c $x`
	if [ $apend = "i" ];then
		echo "/etc/shadow文件存在i安全属性,符合要求" | $saveresult
		flag=1
	fi
	if [ $apend = "a" ];then
		echo "/etc/shadow文件存在a安全属性" | $saveresult
		flag=1
	fi
done
if [ $flag = 0 ];then
	echo "/etc/shadow文件不存在相关安全属性,建议使用chattr +i或chattr +a防止/etc/shadow被删除或修改" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------14.4.3 gshadow文件属性---------------------
echo "[14.4.3]正在检查gshadow文件属性......" | $saveresult
flag=0
for ((x=1;x<=15;x++))
do
	apend=`lsattr /etc/gshadow | cut -c $x`
	if [ $apend = "i" ];then
		echo "/etc/gshadow文件存在i安全属性,符合要求" | $saveresult
		flag=1
	fi
	if [ $apend = "a" ];then
		echo "/etc/gshadow文件存在a安全属性" | $saveresult
		flag=1
	fi
done
if [ $flag = 0 ];then
	echo "/etc/gshadow文件不存在相关安全属性,建议使用chattr +i或chattr +a防止/etc/gshadow被删除或修改" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult


echo ------------14.4.4 group文件属性---------------------
echo "[14.4.4]正在检查group文件属性......" | $saveresult
flag=0
for ((x=1;x<=15;x++))
do
	apend=`lsattr /etc/group | cut -c $x`
	if [ $apend = "i" ];then
		echo "/etc/group文件存在i安全属性,符合要求" | $saveresult
		flag=1
	fi
	if [ $apend = "a" ];then
		echo "/etc/group文件存在a安全属性" | $saveresult
		flag=1
	fi
done
if [ $flag = 0 ];then
	echo "/etc/group文件不存在相关安全属性,建议使用chattr +i或chattr +a防止/etc/group被删除或修改" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult


echo ------------15 文件完整性----------------------
echo ------------15.1 系统文件完整性----------------------
#通过取出系统关键文件的MD5值,一方面可以直接将这些关键文件的MD5值通过威胁情报平台进行查询
#另一方面,使用该软件进行多次检查时会将相应的MD5值进行对比,若和上次不一样,则会进行提示

echo "[15.1]正在采集系统关键文件MD5....."
file="/tmp/buying_${ipadd}_${date}/sysfile_md5.txt"
if [ -e "$file" ]; then 
	md5sum -c "$file" 2>&1; 
else
	md5sum /usr/bin/awk >> $file
	md5sum /usr/bin/basename >> $file
	md5sum /usr/bin/bash >> $file
	md5sum /usr/bin/cat >> $file
	md5sum /usr/bin/chattr >> $file
	md5sum /usr/bin/chmod >> $file
	md5sum /usr/bin/chown >> $file
	md5sum /usr/bin/cp >> $file
	md5sum /usr/bin/csh >> $file
	md5sum /usr/bin/curl >> $file
	md5sum /usr/bin/cut >> $file
	md5sum /usr/bin/date >> $file
	md5sum /usr/bin/df >> $file
	md5sum /usr/bin/diff >> $file
	md5sum /usr/bin/dirname >> $file
	md5sum /usr/bin/dmesg >> $file
	md5sum /usr/bin/du >> $file
	md5sum /usr/bin/echo >> $file
	md5sum /usr/bin/ed >> $file
	md5sum /usr/bin/egrep >> $file
	md5sum /usr/bin/env >> $file
	md5sum /usr/bin/fgrep >> $file
	md5sum /usr/bin/file >> $file
	md5sum /usr/bin/find >> $file
	md5sum /usr/bin/gawk >> $file
	md5sum /usr/bin/GET >> $file
	md5sum /usr/bin/grep >> $file
	md5sum /usr/bin/groups >> $file
	md5sum /usr/bin/head >> $file
	md5sum /usr/bin/id >> $file
	md5sum /usr/bin/ipcs >> $file
	md5sum /usr/bin/kill >> $file
	md5sum /usr/bin/killall >> $file
	md5sum /usr/bin/kmod >> $file
	md5sum /usr/bin/last >> $file
	md5sum /usr/bin/lastlog >> $file
	md5sum /usr/bin/ldd >> $file
	md5sum /usr/bin/less >> $file
	md5sum /usr/bin/locate >> $file
	md5sum /usr/bin/logger >> $file
	md5sum /usr/bin/login >> $file
	md5sum /usr/bin/ls >> $file
	md5sum /usr/bin/lsattr >> $file
	md5sum /usr/bin/lynx >> $file
	md5sum /usr/bin/mail >> $file
	md5sum /usr/bin/mailx >> $file
	md5sum /usr/bin/md5sum >> $file
	md5sum /usr/bin/mktemp >> $file
	md5sum /usr/bin/more >> $file
	md5sum /usr/bin/mount >> $file
	md5sum /usr/bin/mv >> $file
	md5sum /usr/bin/netstat >> $file
	md5sum /usr/bin/newgrp >> $file
	md5sum /usr/bin/numfmt >> $file
	md5sum /usr/bin/passwd >> $file
	md5sum /usr/bin/perl >> $file
	md5sum /usr/bin/pgrep >> $file
	md5sum /usr/bin/ping >> $file
	md5sum /usr/bin/pkill >> $file
	md5sum /usr/bin/ps >> $file
	md5sum /usr/bin/pstree >> $file
	md5sum /usr/bin/pwd >> $file
	md5sum /usr/bin/readlink >> $file
	md5sum /usr/bin/rpm >> $file
	md5sum /usr/bin/runcon >> $file
	md5sum /usr/bin/sed >> $file
	md5sum /usr/bin/sh >> $file
	md5sum /usr/bin/sha1sum >> $file
	md5sum /usr/bin/sha224sum >> $file
	md5sum /usr/bin/sha256sum >> $file
	md5sum /usr/bin/sha384sum >> $file
	md5sum /usr/bin/sha512sum >> $file
	md5sum /usr/bin/size >> $file
	md5sum /usr/bin/sort >> $file
	md5sum /usr/bin/ssh >> $file
	md5sum /usr/bin/stat >> $file
	md5sum /usr/bin/strace >> $file
	md5sum /usr/bin/strings >> $file
	md5sum /usr/bin/su >> $file
	md5sum /usr/bin/sudo >> $file
	md5sum /usr/bin/systemctl >> $file
	md5sum /usr/bin/tail >> $file
	md5sum /usr/bin/tcsh >> $file
	md5sum /usr/bin/telnet >> $file
	md5sum /usr/bin/test >> $file
	md5sum /usr/bin/top >> $file
	md5sum /usr/bin/touch >> $file
	md5sum /usr/bin/tr >> $file
	md5sum /usr/bin/uname >> $file
	md5sum /usr/bin/uniq >> $file
	md5sum /usr/bin/users >> $file
	md5sum /usr/bin/vmstat >> $file
	md5sum /usr/bin/w >> $file
	md5sum /usr/bin/watch >> $file
	md5sum /usr/bin/wc >> $file
	md5sum /usr/bin/wget >> $file
	md5sum /usr/bin/whatis >> $file
	md5sum /usr/bin/whereis >> $file
	md5sum /usr/bin/which >> $file
	md5sum /usr/bin/who >> $file
	md5sum /usr/bin/whoami >> $file
	md5sum /usr/lib/systemd/s >> $file
	md5sum /usr/local/bin/rkh >> $file
	md5sum /usr/sbin/adduser >> $file
	md5sum /usr/sbin/chkconfi >> $file
	md5sum /usr/sbin/chroot >> $file
	md5sum /usr/sbin/depmod >> $file
	md5sum /usr/sbin/fsck >> $file
	md5sum /usr/sbin/fuser >> $file
	md5sum /usr/sbin/groupadd >> $file
	md5sum /usr/sbin/groupdel >> $file
	md5sum /usr/sbin/groupmod >> $file
	md5sum /usr/sbin/grpck >> $file
	md5sum /usr/sbin/ifconfig >> $file
	md5sum /usr/sbin/ifdown >> $file
	md5sum /usr/sbin/ifup >> $file
	md5sum /usr/sbin/init >> $file
	md5sum /usr/sbin/insmod >> $file
	md5sum /usr/sbin/ip >> $file
	md5sum /usr/sbin/lsmod >> $file
	md5sum /usr/sbin/lsof >> $file
	md5sum /usr/sbin/modinfo >> $file
	md5sum /usr/sbin/modprobe >> $file
	md5sum /usr/sbin/nologin >> $file
	md5sum /usr/sbin/pwck >> $file
	md5sum /usr/sbin/rmmod >> $file
	md5sum /usr/sbin/route >> $file
	md5sum /usr/sbin/rsyslogd >> $file
	md5sum /usr/sbin/runlevel >> $file
	md5sum /usr/sbin/sestatus >> $file
	md5sum /usr/sbin/sshd >> $file
	md5sum /usr/sbin/sulogin >> $file
	md5sum /usr/sbin/sysctl >> $file
	md5sum /usr/sbin/tcpd >> $file
	md5sum /usr/sbin/useradd >> $file
	md5sum /usr/sbin/userdel >> $file
	md5sum /usr/sbin/usermod >> $file
	md5sum /usr/sbin/vipw >> $file
fi
printf "\n" | $saveresult


echo ------------16 日志分析------------------------------
echo ------------16.1 查看日志配置与打包-------------------
echo ------------16.1.1 查看日志配置----------------------
echo "[16.1.1]正在查看日志配置....." | $saveresult
logconf=$(more /etc/rsyslog.conf | egrep -v "#|^$")
if [ -n "$logconf" ];then
	(echo "[*]日志配置如下:" && echo "$logconf") | $saveresult
else
	echo "[!!!]未发现日志配置文件" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.1.2日志是否存在---------------
echo "[16.1.2]正在分析日志文件是否存在....." | $saveresult
logs=$(ls -l /var/log/)
if [ -n "$logs" ];then
	echo "[*]日志文件存在" | $saveresult
else
	echo "[!!!]日志文件不存在,请分析是否被清除！" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.1.3 日志审核是否开启---------------
echo "[16.1.3]正在分析日志审核是否开启....." | $saveresult
service auditd status | grep running
if [ $? -eq 0 ];then
	echo "[*]系统日志审核功能已开启,符合要求" | $saveresult
else
	echo "[!!!]系统日志审核功能已关闭,不符合要求,建议开启日志审核。可使用以下命令开启:service auditd start" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.1.4 打包日志---------------
echo "[16.1.4]正在打包日志......" | $saveresult
zip -r ${log_file}system_log.zip /var/log/
if [ $? -eq 0 ];then
	echo "[*]日志打包成功" | $saveresult
else
	echo "[!!!]日志打包失败,请工人导出日志" | tee -a $danger_file | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.2secure日志分析---------------
echo ------------16.2.1成功登录--------------------
echo "[16.2.1]正在检查日志中成功登录的情况....." | $saveresult
loginsuccess=$(more /var/log/secure* | grep "Accepted password" | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginsuccess" ];then
	(echo "[*]日志中分析到以下用户成功登录:" && echo "$loginsuccess")  | $saveresult
	(echo "[*]登录成功的IP及次数如下：" && grep "Accepted " /var/log/secure* | awk '{print $11}' | sort -nr | uniq -c )  | $saveresult
	(echo "[*]登录成功的用户及次数如下:" && grep "Accepted" /var/log/secure* | awk '{print $9}' | sort -nr | uniq -c )  | $saveresult
else
	echo "[*]日志中未发现成功登录的情况" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.2.2登录失败--------------------
echo "[16.2.2]存在检查日志中登录失败的情况....." | $saveresult
loginfailed=$(more /var/log/secure* | grep "Failed password" | awk '{print $1,$2,$3,$9,$11}')
if [ -n "$loginfailed" ];then
	(echo "[!!!]日志中发现以下登录失败的情况:" && echo "$loginfailed") |  tee -a $danger_file  | $saveresult
	(echo "[!!!]登录失败的IP及次数如下:" && grep "Failed password" /var/log/secure* | awk '{print $11}' | sort -nr | uniq -c)  | $saveresult
	(echo "[!!!]登录失败的用户及次数如下:" && grep "Failed password" /var/log/secure* | awk '{print $9}' | sort -nr | uniq -c)  | $saveresult
else
	echo "[*]日志中未发现登录失败的情况" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.2.3本机登录情况-----------------
echo "[16.2.4]正在检查图本机登录情况....." | $saveresult
systemlogin=$(more /var/log/secure* | grep -E "sshd:session.*session opened" | awk '{print $1,$2,$3,$11}')
if [ -n "$systemlogin" ];then
	(echo "[*]本机登录情况:" && echo "$systemlogin") | $saveresult
	(echo "[*]本机登录账号及次数如下:" && more /var/log/secure* | grep -E "sshd:session.*session opened" | awk '{print $11}' | sort -nr | uniq -c) | $saveresult
else
	echo "[!!!]未发现在本机登录退出情况,请注意！！！" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.2.4新增用户-------------------
echo "[16.2.4]正在检查新增用户....." | $saveresult
newusers=$(more /var/log/secure* | grep "new user"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -n "$newusers" ];then
	(echo "[!!!]日志中发现新增用户:" && echo "$newusers") | tee -a $danger_file | $saveresult
	(echo "[*]新增用户账号及次数如下:" && more /var/log/secure* | grep "new user" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $saveresult
else
	echo "[*]日志中未发现新增加用户" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.2.5新增用户组-----------------
echo "[16.2.5]正在检查新增用户组....." | $saveresult
newgoup=$(more /var/log/secure* | grep "new group"  | awk -F '[=,]' '{print $1,$2}' | awk '{print $1,$2,$3,$9}')
if [ -n "$newgoup" ];then
	(echo "[!!!]日志中发现新增用户组:" && echo "$newgoup") | tee -a $danger_file | $saveresult
	(echo "[*]新增用户组及次数如下:" && more /var/log/secure* | grep "new group" | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c) | $saveresult
else
	echo "[*]日志中未发现新增加用户组" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.3message日志分析---------------
echo ------------16.3.1传输文件--------------------
#下面命令仅显示传输的文件名,并会将相同文件名的去重
#more /var/log/message* | grep "ZMODEM:.*BPS" | awk -F '[]/]' '{print $0}' | sort | uniq
echo "[16.3.1]正在检查传输文件....." | $saveresult
zmodem=$(more /var/log/message* | grep "ZMODEM:.*BPS")
if [ -n "$zmodem" ];then
	(echo "[!!!]传输文件情况:" && echo "$zmodem") | tee -a $danger_file | $saveresult
else
	echo "[*]日志中未发现传输文件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.3.2历史使用DNS服务器------------
echo "[16.3.2]正在检查日志中使用DNS服务器的情况....." | $saveresult
dns_history=$(more /var/log/messages* | grep "using nameserver" | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq)
if [ -n "$dns_history" ];then
	(echo "[!!!]该服务器曾经使用以下DNS:" && echo "$dns_history") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现使用DNS服务器" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.4cron日志分析---------------
echo ------------16.4.1定时下载-----------------
echo "[16.4.1]正在分析定时下载....." | $saveresult
cron_download=$(more /var/log/cron* | grep "wget|curl")
if [ -n "$cron_download" ];then
	(echo "[!!!]定时下载情况:" && echo "$cron_download") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现定时下载情况" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.4.2定时执行脚本-----------------
echo "[16.4.2]正在分析定时执行脚本....." | $saveresult
cron_shell=$(more /var/log/cron* | grep -E "\.py$|\.sh$|\.pl$") 
if [ -n "$cron_shell" ];then
	(echo "[!!!]发现定时执行脚本:" && echo "$cron_download") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现定时下载脚本" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.5yum日志分析----------------------
echo ------------16.5.1下载软件情况-------------------
echo "[16.5.1]正在分析使用yum下载软件情况....." | $saveresult
yum_install=$(more /var/log/yum* | grep Installed | awk '{print $NF}' | sort | uniq)
if [ -n "$yum_install" ];then
	(echo "[*]曾使用yum下载以下软件:"  && echo "$yum_install") | $saveresult
else
	echo "[*]未使用yum下载过软件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.5.2下载脚本文件-------------------
echo "[16.5.2]正在分析使用yum下载脚本文件....." | $saveresult
yum_installscripts=$(more /var/log/yum* | grep Installed | grep -E "(\.sh$\.py$|\.pl$)" | awk '{print $NF}' | sort | uniq)
if [ -n "$yum_installscripts" ];then
	(echo "[*]曾使用yum下载以下脚本文件:"  && echo "$yum_installscripts") | $saveresult
else
	echo "[*]未使用yum下载过脚本文件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.5.3卸载软件情况-------------------
echo "[16.5.3]正在检查使用yum卸载软件情况....." | $saveresult
yum_erased=$(more /var/log/yum* | grep Erased)
if [ -n "$yum_erased" ];then
	(echo "[*]使用yum曾卸载以下软件:" && echo "$yum_erased")  | $saveresult
else
	echo "[*]未使用yum卸载过软件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.5.4可疑工具-----------------
echo "[16.5.4]正在检查使用yum安装的可疑工具....." | $saveresult
hacker_tools=$(more /var/log/yum* | awk -F: '{print $NF}' | awk -F '[-]' '{print $1}' | sort | uniq | grep -E "(^nc|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)")
if [ -n "$hacker_tools" ];then
	(echo "[!!!]发现使用yum下载过以下可疑软件:" && echo "$hacker_tools") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现使用yum下载过可疑软件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.6 dmesg日志分析----------------------
echo ------------16.6.1 内核自检日志---------------------
echo "[16.6.1]正在查看内核自检日志....." | $saveresult
dmesg=$(dmesg)
if [ $? -eq 0 ];then
	(echo "[*]日志自检日志如下：" && "$dmesg" ) | $saveresult
else
	echo "[*]未发现内核自检日志" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.7 btmp日志分析----------------------
echo ------------16.7.1 错误登录日志分析-----------------
echo "[16.7.1]正在分析错误登录日志....." | $saveresult
lastb=$(lastb)
if [ -n "$lastb" ];then
	(echo "[*]错误登录日志如下:" && echo "$lastb") | $saveresult
else
	echo "[*]未发现错误登录日志" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.8 lastlog日志分析----------------------
echo ------------16.8.1 所有用户最后一次登录日志分析-----------------
echo "[16.8.1]正在分析所有用户最后一次登录日志....." | $saveresult
lastlog=$(lastlog)
if [ -n "$lastlog" ];then
	(echo "[*]所有用户最后一次登录日志如下:" && echo "$lastlog") | $saveresult
else
	echo "[*]未发现所有用户最后一次登录日志" | $saveresult
fi
printf "\n" | $saveresult

echo ------------16.9 wtmp日志分析---------------
echo ------------16.9.1所有登录用户分析-------
echo "[16.9.1]正在检查历史上登录到本机的用户:" | $saveresult
lasts=$(last | grep pts | grep -vw :0)
if [ -n "$lasts" ];then
	(echo "[*]历史上登录到本机的用户如下:" && echo "$lasts") | $saveresult
else
	echo "[*]未发现历史上登录到本机的用户信息" | $saveresult
fi
printf "\n" | $saveresult

echo ------------17 内核检查-------------------
echo ------------17.1 内核情况-----------------
echo "[17.1]正在检查内核信息......" | $saveresult
lsmod=$(lsmod)
if [ -n "$lsmod" ];then
	(echo "[*]内核信息如下:" && echo "$lsmod") | $saveresult
else
	echo "[*]未发现内核信息" | $saveresult
fi
printf "\n" | $saveresult

echo ------------17.2 可疑内核检查-----------------
echo "[17.2]正在检查可疑内核....." | $saveresult
danger_lsmod=$(lsmod | grep -Ev "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state")
if [ -n "$danger_lsmod" ];then
	(echo "[!!!]发现可疑内核模块:" && echo "$danger_lsmod") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现可疑内核模块" | $saveresult
fi
printf "\n" | $saveresult

echo ------------18 安装软件-------------------
echo ------------18.1 安装软件及版本-----------------
echo "[18.1]正在检查安装软件及版本情况....." | $saveresult
software=$(rpm -qa | awk -F- '{print $1,$2}' | sort -nr -k2 | uniq)
if [ -n "$software" ];then
	(echo "[*]系统安装与版本如下:" && echo "$software") | $saveresult
else
	echo "[*]系统未安装软件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------18.2可疑软件-----------------
echo "[18.2]正在检查安装的可疑软件....." | $saveresult
danger_soft=$(rpm -qa  | awk -F- '{print $1}' | sort | uniq | grep -E "^(ncat|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)$")
if [ -n "$danger_soft" ];then
	(echo "[!!!]以下安装的软件可疑,需要人工分析:"  && echo "$danger_soft") | tee -a $danger_file | $saveresult
else
	echo "[*]未发现安装可疑软件" | $saveresult
fi
printf "\n" | $saveresult

echo ------------19环境变量-----------------
echo "[18]正在检查环境变量....." | $saveresult
env=$(env)
if [ -n "$env" ];then
	(echo "[*]环境变量:" && echo "$env") | $saveresult
else
	echo "[*]未发现环境变量" | $saveresult
fi
printf "\n" | $saveresult

echo ------------20性能分析-----------------
echo ------------20.1磁盘分析-----------------
echo ------------20.1.1磁盘使用-----------------
echo "[20.1.1]正在检查磁盘使用....." | $saveresult
echo "[*]磁盘使用情况如下:" && df -h  | $saveresult
printf "\n" | $saveresult

echo ------------20.1.2检查磁盘使用过大-----------------
echo "[20.1.2]正在检查磁盘使用是否过大....." | $saveresult
#使用超过70%告警
df=$(df -h | awk 'NR!=1{print $1,$5}' | awk -F% '{print $1}' | awk '{if ($2>70) print $1,$2}')
if [ -n "$df" ];then
	(echo "[!!!]硬盘空间使用过高，请注意！！！" && echo "$df" ) | tee -a $danger_file | $saveresult
else
	echo "[*]硬盘空间足够" | $saveresult
fi
printf "\n" | $saveresult

echo ------------20.2CPU分析-----------------
echo ------------20.2.1CPU情况-----------------
echo "[20.2.1]正在检查CPU相关信息....." | $saveresult
(echo "CPU硬件信息如下:" && more /proc/cpuinfo ) | $saveresult
(echo "CPU使用情况如下:" && ps -aux | sort -nr -k 3 | awk  '{print $1,$2,$3,$NF}') | $saveresult
printf "\n" | $saveresult

echo ------------20.2.2占用CPU前5进程-----------------
echo "[20.2.2]正在检查占用CPU前5资源的进程....." | $saveresult
(echo "占用CPU资源前5进程：" && ps -aux | sort -nr -k 3 | head -5)  | $saveresult
printf "\n" | $saveresult

echo ------------20.2.3占用CPU较大进程-----------------
echo "[20.2.3]正在检查占用CPU较大的进程....." | $saveresult
pscpu=$(ps -aux | sort -nr -k 3 | head -5 | awk '{if($3>=20) print $0}')
if [ -n "$pscpu" ];then
	echo "[!!!]以下进程占用的CPU超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD" 
	echo "$pscpu" | tee -a 20.2.3_pscpu.txt | tee -a $danger_file | $saveresult
else
	echo "[*]未发现进程占用资源超过20%" | $saveresult
fi
printf "\n" | $saveresult

echo ------------20.3 内存分析-----------------
echo ------------20.3.1 内存情况-----------------
echo "[20.3.1]正在检查内存相关信息....." | $saveresult
(echo "[*]内存信息如下:" && more /proc/meminfo) | $saveresult
(echo "[*]内存使用情况如下:" && free -m) | $saveresult
printf "\n" | $saveresult

echo ------------20.3.2占用内存前5进程-----------------
echo "[20.2.2]正在检查占用内存前5资源的进程....." | $saveresult
(echo "[*]占用内存资源前5进程：" && ps -aux | sort -nr -k 4 | head -5) | $saveresult
printf "\n" | $saveresult

echo ------------20.3.3占用内存较多进程-----------------
echo "[20.3.3]正在检查占用内存较多的进程....." | $saveresult
psmem=$(ps -aux | sort -nr -k 4 | head -5 | awk '{if($4>=2) print $0}')
if [ -n "$psmem" ];then
	echo "[!!!]以下进程占用的内存超过20%:" && echo "UID         PID   PPID  C STIME TTY          TIME CMD"
	echo "$psmem" | tee -a $danger_file | $saveresult
else
	echo "[*]未发现进程占用内存资源超过20%" | $saveresult
fi
printf "\n" | $saveresult

echo ------------20.4网络连接-----------------
echo "[20.4]正在检查网络连接情况......" | $saveresult
netstat=$(netstat -anlp | grep ESTABLISHED)
netstatnum=$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
if [ -n "$netstat" ];then
	(echo "[*]网络连接情况:" && echo "$netstat") | $saveresult
	if [ -n "$netstatnum" ];then
		(echo "[*]各个状态的数量如下:" && echo "$netstatnum")  | $saveresult
	fi
else
	echo "[*]未发现网络连接" | $saveresult
fi
printf "\n" | $saveresult

echo ------------20.5 其他----------------------
echo ------------20.5.1 运行时间及负载-----------------
echo "[20.5.1]正在检查系统运行时间及负载情况......" | $saveresult
(echo "[*]系统运行时间如下:" && uptime) | $saveresult
printf "\n" | $saveresult


echo ------------21 共享情况----------------------
echo "[21]正在检查共享情况......" | $saveresult
share=$(exportfs)
if [ -n "$share" ];then
	(echo "[!!!]网络共享情况如下:" && echo "$share") | $saveresult
else
	echo "[*]未发现网络共享" | $saveresult
fi
printf "\n" | $saveresult


echo "[*]正在将检查文件压缩到/tmp/目录下......"
zip -r /tmp/buying_${ipadd}_${date}.zip /tmp/buying_${ipadd}_${date}/*

echo "检查结束！！！"
echo "安徽三实捕影Linux安全检查与应急响应工具"
echo "Version:1.2"
echo "Author:飞鸟"
echo "若有问题请联系Mail:liuquyong112@gmail.com"
echo "Date:2019-02-19"
