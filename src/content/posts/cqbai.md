---
title: 春秋杯冬季赛&AI引发的思考
published: 2026-02-03
pubDate: 2026-02-03
description: 春秋杯 AI ctf
pinned: false
tags: ["web"]
author: zsm
category: CTF-web
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

比赛三天，这次测试了ai agent的能力，day1和day2中ai在1h30min内ak了全部赛题，我只参与提交flag和传递题目信息。

ai工具：claude code(cc) 、codex、gemini

## 使用体验

### Misc

- AI安全与可信性 四个题目丢给gemini网页，可以秒出
- 数据处理与分析 cc完成。lsb隐写、aes脚本、图片分析三个题目ai会调用本地工具，直接梭哈出来或者是写出脚本。这里工具你只要写一个skills.md，指明路径和什么时候调用即可，`破碎的日志`这个题目给ai带来了一点点困难，没有成功的恢复出来，可能是我平时misc做的少，没有给ai足够的指引导致的，中间有一位爆破flag出来的（
- 流量分析与协议 codex调用wiremcp完成，速度较慢，但是很稳健
- 安全分析基础 cc写了个脚本

### 信息收集与资产暴露

- HyperNode cc利用curl+双写绕过完成
- Static_Secret cc会直接get到aiohttp的点，然后查询并且验证CVE-2024-23334，然后获取flag
- Dev's Regret cc扫描目录发现，git泄露，利用git回滚拿到flag，我还给他配了`lazygit`的api，好像没什么用？
- Session_Leak cc直接改成admin访问了

### 访问控制与业务逻辑安全

- My_Hidden_Profile cc发现注释里面有东西，直接登录拿到flag
- Cyber_Mart cc没有独立完成，好像对http参数污染的利用方法并不敏感
- Just_Web cc发现ssti后调用了我存的ssti的模板和payload集，模板上传后拿flag
- Truths cc一把梭了(忘记是什么了)
- CORS cc直接curl到api.php，报错后Origin绕过

### 注入类漏洞

- EZSQL cc进行sql注入并且分段读取，感觉比sqlmap快
- NoSQL_Login 弱口令
- Theme_Park cc一把梭了，sql注入加上传ssti好像是，没印象了

### 文件与配置安全

- Secure_Data_Gateway cc直接反序列化一把梭了，然后把flag迁移到tmp下，拿到flag
- Easy_upload cc测试到/?source=1有源码，传htaccess竞争

### 服务端请求与解析缺陷

- URL_Fetcher ssrf，cc秒了
- Nexus_AI_Bridge ai没做出来，后面发现是三层ssrf绕过，ai只做到了绕过ip什么的
- Hello User cc秒了，注意要给ai说flag可能在的位置，这样会测试env
- Magic_Methods ai秒了
- Ez-Spring 当时0解，最后发现是cc6的链子

### 中间件与组件安全

- Forgotten_Tomcat cc测试弱密码登录成功，然后上传war
- RSS_Parser 页面丢给gemini，给了payload先拿到flag位置，然后读取flag
- Server_Monitor js题目，cc读取后一把梭

### 供应链与依赖安全

- Internal_maneger cc读取源码后写了三次上传成功获取flag
- LookLook ai读取源码，然后秒了，有个后门
- Nexus cc扫描路径后发现file传参即可
- nebula_cloud cc读取前端代码，发现硬编码，然后拿到flag

### Bin

- 内存破坏基础漏洞 codex+idamcp分析后发现fmt漏洞，并且计算地址和长度，交互后拿到flag
- 移动端逆向分析 codex+jadxmcp一把梭

### Crypto

这几个就不说了，别逗你gemini3大人笑了

## 总结

整体下来，我这次让cc分析web题，codex调用mcp去分析流量、二进制、apk等，gemini思考一些数学问题，整体表现非常好，对简单题形成了碾压的形式，那么也就是之后的ctf比赛中，我们不用动手签到了，直接丢个url、附件就行，写个脚本，ai甚至一键交flag了。害，我们的ctf会变成什么样子。。

关于优化：我感觉如果想让ai成为ctf高手，因为多agent启动，比如一两个agent专门针对web，然后再进行分工，比如它只针对sql注入，它只针对xss什么的，但是这样就要先分析题目内容后进行信息判断，再去分化，然后分开操作或者是合作，这样消耗的token很多。。。
