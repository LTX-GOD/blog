---
title: 关于靶场网络配置
published: 2025-04-23
pinned: false
description: A simple example of a Markdown blog post.
tags: ['HTB','THM']
category: 环境配置
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-23
pubDate: 2025-04-23
---


## 前言
闲的无聊，看群友遇到这种问题，想到以后学弟学妹有可能也有这种问题，那就写一下吧～

## 本机配置
我这里本地是mac，代理挂黑猫
1. 黑猫挂上系统代理，把端口记录下来，开局域网连接
2. 把这个端口露出去
3. 在htb&thm下载`.ovpn`文件，这里只说`udp`文件的配置
4. vim添加进去`socks-proxy 127.0.0.1 port`

## 虚拟机配置

### orbstack&wsl
我目前使用orbstack的，可以直接吃到本地配置，朋友用的wsl2也可以，所以不用额外配置的xd，还是太全面了

### pd&vm
虚拟机我一般开的`桥接`，要么虚拟机里面下个黑猫重复上面的操作，要么去吃本机代理  

这里更推荐吃本机  
设置里面直接去配置代理，把本机的ip和代理端口加进去，然后ping一下google什么的，能通就行了  
虚拟机里面下个`.ovpn`运行一下，这个时候应该是可以通的

## 本地靶机相关
推荐virtualbox去当靶机容器，原因是好用  
网络记得开桥接，攻击机也开桥接，但是有的时候弹shell不成功，一般是虚拟机容器的问题，这个时候我一般弹本机上，可以去解决这个问题

## 靶场相关
在线的推荐htb,thm
离线推荐vulnhub,hmv
