#!/bin/bash
echo "安徽三实捕影Linux安全检查与应急响应工具"
echo "Version:1.2"
echo "Author:飞鸟"
echo "Mail:liuquyong112@gmail.com"
echo "Date:2019-02-19"

cat <<EOF
*************************************************************************************
功能与使用说明:
	1.此脚本主要功能用来实现一键对远程服务器进行安全检查
	2.使用时只需要将远程服务器的IP、账号、密码放到hosts.txt文本中,运行sh login.sh或chmod +x login.sh;./login.sh即可自动进行安全检查
	3.有的Linux系统不允许使用root账号直接登录,因此前期需要测试或与用户沟通是否允许root直接登录
		3.1 如果允许使用root直接登录,可以将root账号密码直接写到hosts.txt文本中
		3.2 如果不允许使用root账号直接登录,需要增加一个可以登录的账号到hosts.txt文件中,此账号需要有对/tmp目录的读写权限，具体格式参考hosts.txt文本的说明                                   
	4.远程服务器的检查内容均放在/tmp/buying_${ipadd}_${date}目录下
	5.检查结束后会将远程服务器的检查结果打包放到本地的/tmp目录下,同时会删除远程服务器上的检查脚本与结果
*************************************************************************************
EOF
for i in `cat hosts.txt`
do
  #远程IP地址
  ipadd=`echo $i | awk -F "[:]" '{print $1}'`
  #远程服务器SSH端口
  port=`echo $i | awk -F "[:]" '{print $2}'`
  #普通用户,如果root允许登录,这里面可以是root账号
  username=`echo $i | awk -F "[:]" '{print $3}'`
  #普通用户密码，如果root允许登录,这里面可以是root密码
  userpasswd=`echo $i | awk -F "[:]" '{print $4}'`
  #root用户密码
  rootpasswd=`echo $i | awk -F "[:]" '{print $5}'`
  #上传检查脚本buying_linuxcheck.sh
  expect put.exp $ipadd $port $username $userpasswd 
  #登陆执行检查脚本buying_linuxcheck.sh
  expect sh.exp $ipadd $port $username $userpasswd $rootpasswd 
  #从远程拿取结果
  expect get.exp $ipadd $port $username $userpasswd 
  #删除远程服务器的检查结果和检查脚本
  expect del.exp $ipadd $port $username $userpasswd $rootpasswd
done 
