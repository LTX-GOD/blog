---
title: 关于HTB-THM连不上
published: 2025-04-28
pinned: false
description: 如何解决HTB和THM的openvpn连接问题
tags: ['HTB', 'THM']
category: 环境配置
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-28
pubDate: 2025-04-28
---


## 主要问题

### 梯子配置
这里是mac系统，linux应该是类似的，win自己挂到linux虚拟机或者是梯子开局域网模式即可  
`clash`or`v2rayN`都会有一个端口开放，我是直接暴露出去的，记得开系统代理即可

### .ovpn文件
tcp一般都能连上，但是只有htb的有，而且htb的联机模式还不是tcp  

udp的问题一般在于连不上或者是机场不支持，机场不支持换一个就好了  
连不上的话在.ovpn文件加入一句`socks-proxy 127.0.0.1 port`，端口就是梯子的端口

## 其他问题
全搞好了还不行？  

1. mac推荐用orbstack，win推荐用wsl2，都直接走本机的环境，不用额外配置，缺点是没有ui
2. 非要虚拟机的话，里面下个梯子重复上面的操作，一般都不会有问题
3. 实在解决不了直接重装一个虚拟机得了xd，说不定是你以前把环境玩坏了