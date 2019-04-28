#!/bin/bash
EOF
for i in `cat hosts.txt`
do
  #远程IP地址
  ipadd=`echo $i | awk -F "[:]" '{print $1}'`
  #普通用户,如果root允许登录,这里面可以是root账号
  username=`echo $i | awk -F "[:]" '{print $2}'`
  #普通用户密码，如果root允许登录,这里面可以是root密码
  userpasswd=`echo $i | awk -F "[:]" '{print $3}'`
  #root用户密码
  rootpasswd=`echo $i | awk -F "[:]" '{print $4}'`
  #上传检查脚本buying_linuxcheck.sh
  expect put.exp $ipadd $username $userpasswd 
  #登陆执行检查脚本buying_linuxcheck.sh
  expect sh.exp $ipadd $username $userpasswd $rootpasswd 
  #从远程拿取结果
  expect get.exp $ipadd $username $userpasswd 
  #删除远程服务器的检查结果和检查脚本
  expect del.exp $ipadd $username $userpasswd $rootpasswd
done
