---
title: 关于vscode的配置
published: 2025-09-22
pubDate: 2025-09-22
description: ''
pinned: false
tags: ['vscode']
author: zsm
category: 环境配置
draft: false 
licenseName: "MIT"
lang: 'zh_CN'
---

## 前言

你知道的，大学老师喜欢推荐vs，作为vs的黑子，不允许这样。这里推荐vscode给新生，nvim的话还是老登玩玩吧

注：如果以前有安装vs并且配置了cpp，推荐把vs卸载干净。

## cpp环境

### msys2&mingw配置

在去年其实写过一个配置文章，但是我感觉有点落伍了。

+ 安装[msys2](https://www.msys2.org)，安装记得改个目录，c盘内存还是挺宝贵的
+ 配置镜像源
  + 打开msys2的终端，输入
    > vim /etc/pacman.d/mirrorlist.mingw
  + 先按`i`，在第一行加入
    > Server = https://mirrors.tuna.tsinghua.edu.cn/msys2/mingw/$repo/
  + 接下来按`esc键`->输入`:wq!`
+ 终端内输入`pacman -S --needed base-devel mingw-w64-ucrt-x86_64-toolchain`

### windows内环境变量配置

+ 按下Win + R，输入sysdm.cpl并回车
+ 切换到"高级"选项卡，点击"环境变量"
+ 在"系统变量"中找到Path，点击"编辑"
+ 点击"新建"，添加C:\msys64\ucrt64\bin（根据实际安装路径调整）
+ 点击"确定"保存所有对话框
+ Win + R输入cmd，然后输入

```
g++ --version
gdb --version
```
+ 若显示版本信息，则安装成功

### 只配置mingw 

哎，只想配置mingw怎么办呢，有的xd有的。

直接去官网下载[mingw](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/seh/),然后压缩包解压出来，比如在D盘，像刚才一样把`D:\mingw64\bin`添加到环境变量即可

## python配置

### 安装python

+ 先去[官网](https://www.python.org/downloads/)下载，这里推荐3.12版本的，稳定且不老
+ 安装可以直接选择第二个，可以全部勾选上，记得勾选下面的加入环境变
+ 第二波选项可以不改动
+ `cmd`里面输入`python`，有反应就代表安装对了

注：这里为什么没有说不要安装在C盘，因为python路径在win上面挺奇妙的(主要是我也忘了)

### 进阶安装

其实这是后话，这里简单的题一下。

因为python的特性，版本之间差异较大，所以延伸出来了`虚拟环境`这个词汇，这里推荐几个

+ venv
+ uv
+ pyenv
+ conda

注：推荐熟练了之后再去搞这种东西

### 库下载

python的核心是库，比如`gmpy2`,`pwn`什么的，这里需要用`pip`

先更新一下

> python -m pip install -U pip

临时换源可以类似

> pip install -i https://mirrors.aliyun.com/pypi/simple/ package_name

永久换源需要在`%APPDATA%\pip\pip.ini`中修改，如果没有就创建

```
[global]
index-url = https://mirrors.aliyun.com/pypi/simple/
```

## vscode配置

### 初始化

其实就是去[官网](https://code.visualstudio.com)下载安装，也是别安装到c盘就行。记得选上添加到路径。

### 相关插件

这里就简单的推荐几个

1. Chinese 汉化插件
2. C/C++ 微软官方插件
3. code runner 直接运行代码的插件，缺点是不能交互输入
4. python 官方插件
5. pylance 规范化插件

### vsc内环境

+ 按`ctrl+shift+p`，然后输入`Python: Select Interpreter`可以选择你的python解释路径，

+ 按`ctrl+shift+p`，输入`C/C++`有个编辑配置
  + `编译器路径输入gcc.exe的路径`，把自己mingw的bin目录下面的gcc填进去 
  + `IntelliSense模式`选自己电脑系统的
  + `C++标准`选c++17，`C标准`选c99

## 末尾

因为本人长时间没用win，可能有些问题和遗漏，大家体谅一下，缺的部分可以在群里问问，也可以在网上搜搜。
