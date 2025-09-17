---
title: Study nodejs 「5」
published: 2025-04-09
pinned: false
description: 学习nodejs的一些笔记
tags: ['nodejs']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-09
pubDate: 2025-04-09
---


## nodejs实现定时任务

用`node-schedule`这个模组去实现定时任务
然后这边实现自动登录校园网的(，首先先bp抓个包，发现里面东西有点多，就写了一堆配置文件，然后包成docker去定时发送

config.js
```js
const config = {
    loginUrl: 'http://ip/eportal/InterFace.do?method=login',
    userId: '',
    password: '',
    service: '中国移动',
    headers: {
        'User-Agent': '',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Origin': '',
        'Referer': 'http://ip/eportal/index.jsp',
        'Cookie': 'EPORTAL_USER_GROUP=; EPORTAL_COOKIE_PASSWORD=; EPORTAL_COOKIE_DOMAIN=false; EPORTAL_COOKIE_USERNAME=; EPORTAL_COOKIE_SERVER=; EPORTAL_COOKIE_SERVER_NAME=; EPORTAL_COOKIE_SAVEPASSWORD=true; EPORTAL_COOKIE_OPERATORPWD='
    }
};

export default config;
```

index.js
```js
import schedule from 'node-schedule';
import axios from 'axios';
import qs from 'qs';
import config from './config.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const logDir = path.join(__dirname, 'logs');

// 确保日志目录存在
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// 日志函数
function log(message, isError = false) {
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0];
    const timeStr = now.toLocaleString();
    const logMessage = `${timeStr} - ${message}\n`;

    // 控制台输出
    console.log(logMessage);

    // 写入文件
    const logFile = path.join(logDir, `${dateStr}.log`);
    fs.appendFileSync(logFile, logMessage);

    // 如果是错误，也写入错误日志
    if (isError) {
        const errorFile = path.join(logDir, `${dateStr}-error.log`);
        fs.appendFileSync(errorFile, logMessage);
    }
}

async function login() {
    try {
        const data = {
            userId: config.userId,
            password: config.password,
            service: config.service,
            queryString: qs.stringify({
                wlanuserip: '',
                wlanacname: '',
                ssid: '',
                nasip: '',
                snmpagentip: '',
                mac: '',
                t: '',
                url: '',
                apmac: '',
                nasid: '',
                vid: '',
                port: '',
                nasportid: ''
            }),
            operatorPwd: '',
            operatorUserId: '',
            validcode: '',
            passwordEncrypt: false
        };

        const response = await axios({
            method: 'post',
            url: config.loginUrl,
            headers: config.headers,
            data: qs.stringify(data)
        });

        log(`登录结果: ${JSON.stringify(response.data)}`);
    } catch (error) {
        log(`登录失败: ${error.message}`, true);
    }
}

// 每天早上7点执行登录
schedule.scheduleJob('0 7 * * *', login);

log('定时任务已启动，将在每天早上7点自动登录');

// 立即执行一次登录，测试配置是否正确
login();
```
感觉学校这边有点怪，甚至会判定是学生还是老师登录，这玩意还分的？网速不一样呗bro

dockerfile
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

CMD ["node", "index.js"] 
```

docker-compose.yml
```yaml
version: '3'

services:
  campus-login:
    build: .
    container_name: campus-login
    restart: always
    environment:
      - TZ=Asia/Shanghai
    volumes:
      - ./config.js:/app/config.js
      - ./logs:/app/logs
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

然后就好了，只得一提的是Cron表达式，和linux的是一样的
```
*    *    *    *    *    *
┬    ┬    ┬    ┬    ┬    ┬
│    │    │    │    │    │
│    │    │    │    │    └── 星期（0 - 6，0表示星期日）
│    │    │    │    └───── 月份（1 - 12）
│    │    │    └────────── 日（1 - 31）
│    │    └─────────────── 小时（0 - 23）
│    └──────────────────── 分钟（0 - 59）
└───────────────────────── 秒（0 - 59）

```

## 文件上传

这个问题其实很简单，就是前端向后端发送一个文件，后端接收到文件后，保存到指定位置，然后返回给前端一个状态码，表示上传成功或者失败。
但是当文件很大时就会有一个问题，如果我网络突然崩了，再整体重新上传，那不就炸了吗？所以我们可以分段上传，比如一个文件被分成了十份，我在上传到最后一点时寄了，重新上传时只需上传最后一份即可

### 前端部分
```html
<input id="file" type="file"> <!--用来上传文件-->
```
定义chunks去切片
文件切片 file 接受文件对象，注意file的底层是继承于blob的因此他可以调用blob的方法，slice进行切片，size就是每个切片的大小
```js
const file = document.getElementById('file')
file.addEventListener('change', (event) => {
    const file = event.target.files[0] //获取文件信息
    const chunks = chunkFun(file)
    uploadFile(chunks)
})

const chunkFun = (file, size = 1024 * 1024 * 4) => {
    const chunks = []
    for (let i = 0; i < file.size; i += size) {
        chunks.push(file.slice(i, i + size))
    }
    return chunks
}

```

循环调用接口上传，并且存储一些信息，当前分片的索引，注意file必须写在最后一个，因为nodejs端的multer 会按照顺序去读的，不然读不到参数, 最后通过promise.all 并发发送请求，等待所有请求发送完成，通知后端合并切片
```js
 const upload = (chunks) => {
            const list = []
            for (let i = 0; i < chunks.length; i++) {
                const formData = new FormData()
                formData.append('index', i)
                formData.append('filename', zsm)
                formData.append('flie', chunks[i])
                list.push(fetch('http://localhost:3000/upload', {
                    method: 'POST',
                    body: formData
                }))
            }
            Promise.all(list).then(res => {
                fetch('http://localhost:3000/merge', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        filename: zsm
                    })

                })
                console.log('上传成功')
            })
        }
```

### node端
比较值得注意的问题是上传时是分块的，所以我们需要合并，将分块的存入`uploads`，然后读取出来排序后再合并即可，严谨一点加点判断什么的
```js
import express from 'express'
import multer from 'multer'
import cors from 'cors'
import fs from 'fs/promises'
import { existsSync, mkdirSync } from 'fs'
import path from 'path'

// 确保上传目录和视频目录存在
const uploadDir = path.join(process.cwd(), 'uploads')
const videoDir = path.join(process.cwd(), 'video')
    ;[uploadDir, videoDir].forEach(dir => {
        if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true })
        }
    })

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename(req, file, cb) {
        cb(null, `${req.body.index}-${req.body.filename}`)
    }
})

// 添加文件过滤器
const fileFilter = (req, file, cb) => {
    // 记录文件信息
    console.log('上传文件信息:', {
        fieldname: file.fieldname,
        originalname: file.originalname,
        mimetype: file.mimetype,
        size: file.size
    })
    // 接受所有文件类型
    cb(null, true)
}

const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: 500 * 1024 * 1024, // 增加文件大小限制到500MB
    }
})

const app = express()
app.use(cors())
app.use(express.json())

// 错误处理中间件
const errorHandler = (err, req, res, next) => {
    console.error(err)
    res.status(500).json({ error: err.message || '服务器内部错误' })
}

app.post('/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: '没有接收到文件' })
        }
        res.json({ message: '文件上传成功' })
    } catch (error) {
        next(error)
    }
})

app.post('/merge', async (req, res, next) => {
    try {
        if (!req.body.filename) {
            return res.status(400).json({ error: '未提供文件名' })
        }

        const files = await fs.readdir(uploadDir)
        if (files.length === 0) {
            return res.status(400).json({ error: '没有找到需要合并的文件' })
        }

        // 排序
        files.sort((a, b) => parseInt(a.split('-')[0]) - parseInt(b.split('-')[0]))

        // 使用原始文件扩展名
        const fileExtension = path.extname(req.body.filename) || ''
        const outputPath = path.join(videoDir, `${req.body.filename}${fileExtension}`)

        // 使用 Promise.all 并行读取所有文件
        const fileContents = await Promise.all(
            files.map(file => fs.readFile(path.join(uploadDir, file)))
        )

        // 合并文件
        await fs.writeFile(outputPath, Buffer.concat(fileContents))

        // 清理临时文件
        await Promise.all(
            files.map(file => fs.unlink(path.join(uploadDir, file)))
        )

        res.json({
            message: '文件合并成功',
            path: outputPath,
            size: fileContents.reduce((acc, curr) => acc + curr.length, 0)
        })
    } catch (error) {
        next(error)
    }
})

app.use(errorHandler)

app.listen(3000, () => {
    console.log('server is running on port 3000')
})
```

## 文件流下载

文件流下载是一种通过将文件内容以流的形式发送给客户端，实现文件下载的方法。它适用于处理大型文件或需要实时生成文件内容的情况。

### 前端实现
```html
<body>
    <button id="btn">下载文件</button>
    <script>
        const btn = document.getElementById('btn');
        btn.addEventListener('click', async () => {
            try {
                const response = await fetch('http://localhost:3000/download', {
                    method: 'POST',
                    body: JSON.stringify({
                        fileName: 'test.txt'
                    }),
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || '下载失败');
                }

                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'test.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } catch (error) {
                console.error('下载出错:', error);
                alert(error.message);
            }
        });
    </script>
</body>
```

前端核心逻辑就是接受的返回值是流的方式arrayBuffer,转成blob，生成下载链接，模拟a标签点击下载

### node端

主要的地方在于响应头
1. Content-Type 指定下载文件的 MIME 类型

+ application/octet-stream（二进制流数据）
+ application/pdf：Adobe PDF 文件。
+ application/json：JSON 数据文件
+ image/jpeg：JPEG 图像文件

2. Content-Disposition 指定服务器返回的内容在浏览器中的处理方式。它可以用于控制文件下载、内联显示或其他处理方式

+ attachment：指示浏览器将响应内容作为附件下载。通常与 filename 参数一起使用，用于指定下载文件的名称
+ inline：指示浏览器直接在浏览器窗口中打开响应内容，如果内容是可识别的文件类型（例如图片或 PDF），则在浏览器中内联显示

```js
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";

const app = express();
app.use(cors());
app.use(express.json())

app.post('/download', (req, res) => {
  try {
    const fileName = req.body.fileName;
    if (!fileName) {
      return res.status(400).json({ error: '文件名不能为空' });
    }

    const filepath = path.join(process.cwd(), 'static', fileName);

    // 检查文件是否存在
    if (!fs.existsSync(filepath)) {
      return res.status(404).json({ error: '文件不存在' });
    }

    const content = fs.readFileSync(filepath);

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
    res.send(content);
  } catch (error) {
    console.error('下载文件时出错:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
```