---
title: wsl2 + arch + sagemath
published: 2024-12-12
pinned: false
description: wsl2  arch  sagemath 环境配置
tags: ['wsl2','sagemath']
category: 环境配置
licenseName: "MIT"
author: zsm
draft: false
date: 2024-12-12
pubDate: 2024-12-12
---


## 前言
为什么要这样搞呢，主要是自己太闲了（被打），还是因为win环境下的sagemath版本低，bug多，而且还不能pwn交互，虽然在vm里面可以搞，但是我又嫌打开虚拟机麻烦，所以就wsl2了。

<br>

## 安装wsl+arch
在此推荐这个[视频教学](https://www.bilibili.com/video/BV1Ae411v798?vd_source=4b59b7952acd90b154bddabab8cfb111 "视频教学")，主要的步骤就是以下几步（我是win11）
1.控制面板&rarr;程序&rarr;启用或关闭Windows功能&rarr;打开适用于Linux的Windows子系统&rarr;重启。
`tips:如果没有成功，可以去看看是否开了管理员权限`
2.打开powershell&rarr;输入：wsl --install --no-distribution&rarr;wsl --update
`tips:--no-distribution作用是安装wsl时不安装linux发行版，如果不加的话会默认安装乌班图`
3.打开c盘&rarr;用户&rarr;个人文件夹&rarr;创建文本文件（不要加后缀）&rarr;命名.wslconfig&rarr;编辑输入
```
[experimental]
autoMemoryReclaim=gradual
networkingMode=mirrored
dnsTunneling=true
firewall=true
autoProxy=true
```
4.下载archlinux，[链接](https://github.com/yuk7/ArchWSL/releases/tag/24.4.28.0 "链接")，下载zip文件，压缩到本地，记住压缩到新建文件夹里面，我命名为arch
5.直接双击arch.exe
6.进行身份注册，现在默认是root，输入passwd设置密码
7.设置个常用账户输入
```
echo "%wheel ALL=(ALL)ALL"/etc/sudoers.d/wheel
useradd -m-G wheel-s /bin/bash fusername
Arch.exe config --default-user fusername
```
退出之后重进
8.配置
```
sudo pacman-key --init
sudo pacman-key --populate
sudo pacman -Syy archlinux-keyring
```
9.换源，推荐清华源
```
sudo nano /etc/pacman.d/mirrorlist
```
在最前面直接加上
```
Server = https://mirrors.tuna.tsinghua.edu.cn/archlinux/$repo/os/$arch
```
然后ctrl+s，ctrl+x退出

<br>

## 安装以及调用sagemath
### 安装
输入 sudo pacman -Sy sagemath
安装之后sage调用，看看能不能出来，可以的话就成功了
安装第三方库的命令是 pacman -S python-xyz
<br>
### 调用
推荐方法vscode
vscode左下角有个蓝色方块，点击后连接wsl，如果要下载插件直接下就行了，调出终端，输入 mkdir sage，去新建一个文件夹，进入这个文件夹后新建一个文件，例如1.ipynb（后缀只能是这个），然后会下载插件，全部下载完后右上角选择内核，输入sage的代码看看能不能用，能用就行
