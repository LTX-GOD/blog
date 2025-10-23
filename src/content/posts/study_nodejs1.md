---
title: Study Nodejs「1」
published: 2025-03-31
pinned: false
description: 学习nodejs的一些笔记
tags: ['nodejs']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-31
pubDate: 2025-03-31
---


## 为什么学nodejs
可能是后面要接手一些项目，或者是些javaspring烦了，学学nodejs玩，目前感觉nodejs的生态还是不错的

## npm的生命周期

第一开始也没想到这个还有生命周期的，就记录一下
```
"predev": "node prev.js",
"dev": "node index.js",
"postdev": "node post.js"
```
执行 `npm run dev` 命令的时候 `predev` 会自动执行 他的生命周期是在`dev`之前执行，然后执行`dev`命令，再然后执行`postdev`，也就是`dev`之后执行
运用场景例如`npm run build` 可以在打包之后删除`dist`目录等等
post例如你编写完一个工具发布`npm`，那就可以在之后写一个ci脚本顺便帮你推送到git等等

## npx

个人理解`npx`的作用是在命令行中运行`node`包中的可执行文件，而不需要全局安装这些包。哎，这样就不会全局包乱飞和包版本冲突了，就行`python`的虚拟环境隔离一样，但是又感觉和`pipx`有异曲同工之妙？

## express

目前体验是很爽的，把原生`nodejs`的`http`服务封装了，方便使用
(下面代码的风格都是`module`)

### 基本使用方法

 + http服务

比较好玩的地方在于`express`是一个函数，同时监听端口的时候也不用像原生的一样了
```nodejs
//原生
const http = require('http');
const url = require('url');
const fs = require('fs');

http.createServer((req, res) => {

}).listen(3000,()=>{

});
```

```nodejs
import express from 'express';

const app = express()

app.listen(3000, () => console.log('Listening on port 3000'))
```

 + 接口编写

编写get post 接口
```nodejs
app.get('/', (req, res) => {
    res.send('get')
})

app.post('/create', (req, res) => {
    res.send('post')
})
```

 + 接受前端的参数
他是无法直接接手`json`参数的，所以要用中间件
```nodejs
app.use(express.json())

app.get('/', (req, res) => {
    console.log(req.query) //get 用query
    res.send('get')
})

app.post('/create', (req, res) => {
    console.log(req.body) //post用body
    res.send('post')
})

//如果是动态参数用 params
app.get('/:id', (req, res) => {
    console.log(req.params)
    res.send('get id')
})
```

### 模块化
全部东西写依托很难看和维护，`express`允许将路由处理程序拆分为多个模块，每个模块负责处理特定的路由。通过将路由处理程序拆分为模块，可以使代码逻辑更清晰，易于维护和扩展

例如文件结构
```
src
 --user.js
 --list.js
app.js
```

src/user.js
```nodejs
import express from 'express';

const router = express.Router();

router.post('/login', (req, res) => {
    res.json({
        code: 200,
        msg: '登录成功'
    })
});

router.post('/register', (req, res) => {
    res.json({
        code: 200,
        msg: '注册成功'
    })
});

export default router;
```

src/list.js
```nodejs
import express from 'express';

const router = express.Router();

router.get('/getall', (req, res) => {
    res.json({
        code: 200,
        msg: '获取成功',
        data: [{ id: 1 }]
    })
});

export default router;
```

app.js
```nodejs
import express from 'express';
import User from './src/user.js'
const app = express()
app.use(express.json())
app.use('/user', User)
app.get('/', (req, res) => {
    console.log(req.query)
    res.send('get')
})

app.get('/:id', (req, res) => {
    console.log(req.params)
    res.send('get id')
})

app.post('/create', (req, res) => {
    console.log(req.body)
    res.send('post')
})


app.listen(3000, () => console.log('Listening on port 3000'))
```

### 中间件
中间件是一个关键概念。中间件是处理HTTP请求和响应的函数，它位于请求和最终路由处理函数之间，可以对请求和响应进行修改、执行额外的逻辑或者执行其他任务。

中间件函数接收三个参数：`req`（请求对象）、`res`（响应对象）和`next`（下一个中间件函数）。通过调用`next()`方法，中间件可以将控制权传递给下一个中间件函数。如果中间件不调用`next()`方法，请求将被中止，不会继续传递给下一个中间件或路由处理函数

拿`log4js`举例子

middleware/logger.js
```nodejs
import log4js from 'log4js';

// 配置 log4js
log4js.configure({
  appenders: {
    out: {
      type: 'stdout', // 输出到控制台
      layout: {
        type: 'colored' // 使用带颜色的布局
      }
    },
    file: {
      type: 'file', // 输出到文件
      filename: './logs/server.log', // 指定日志文件路径和名称
    }
  },
  categories: {
    default: {
      appenders: ['out', 'file'], // 使用 out 和 file 输出器
      level: 'debug' // 设置日志级别为 debug
    }
  }
});

// 获取 logger
const logger = log4js.getLogger('default');

// 日志中间件
const loggerMiddleware = (req, res, next) => {
  logger.debug(`${req.method} ${req.url}`); // 记录请求方法和URL
  next();
};

export default loggerMiddleware;
```

app.js
```nodejs
import express from 'express';
import User from './src/user.js'
import loggerMiddleware from './middleware/logger.js';
const app = express()
app.use(loggerMiddleware)
```

### 防盗链
防盗链一般主要就是验证`host` 或者 `referer`，手动添加一个白名单
```nodejs
import express from 'express';

const app = express();

const whiteList = ['localhost']

const preventHotLingking = (req, res, next) => {
    const referer = req.get('referer')
    if (referer) {
        const { hostname } = new URL(referer)
        if (!whiteList.includes(hostname)) {
            res.status(403).send('403 Forbidden')
            return
        }
    }
    console.log(referer)
    next();
}

app.use(express.static('static'))

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
```

##  跨域问题
跨域资源共享（Cross-Origin Resource Sharing，CORS）是一种机制，用于在浏览器中实现跨域请求访问资源的权限控制。当一个网页通过 XMLHttpRequest 或 Fetch API 发起跨域请求时，浏览器会根据同源策略（Same-Origin Policy）进行限制。同源策略要求请求的源（协议、域名和端口）必须与资源的源相同，否则请求会被浏览器拒绝，所以我们在做前后端分离的项目的时候百分百遇到

### 一般解决方法
举个小例子
发送请求
```nodejs
fetch('http://localhost:3000/info').then(res=>{
    return res.json()
}).then(res=>{
    console.log(res)
})
```

写个普通的get接口
```nodejs
import express from 'express'
const app = express()
app.get('/info', (req, res) => {
    res.json({
        code: 200
    })
})
app.listen(3000, () => {
    console.log('http://localhost:3000')
})

```
这个时候就会报错，因为跨域了，解决方法就是设置响应头(我这里是5500端口)
```nodejs
app.use('*',(req,res,next)=>{
    res.setHeader('Access-Control-Allow-Origin','http://localhost:5500')
    next()
})
```

### 请求头

 1. Accept：指定客户端能够处理的内容类型。
2. Accept-Language：指定客户端偏好的自然语言。
3. Content-Language：指定请求或响应实体的自然语言。
4. Content-Type：指定请求或响应实体的媒体类型。
5. DNT (Do Not Track)：指示客户端不希望被跟踪。
6. Origin：指示请求的源（协议、域名和端口）。
7. User-Agent：包含发起请求的用户代理的信息。
8. Referer：指示当前请求的源 URL。
9. Content-type: application/x-www-form-urlencoded | multipart/form-data |  text/plain

那么我们需要支持的时候就写
>'Access-Control-Allow-Headers','Content-Type'

### 请求方法支持
默认情况下，`CORS` 仅允许 `GET`、`POST`、`HEAD`和`OPTIONS` 方法。如果需要支持其他方法，需要设置 `Access-Control-Allow-Methods` 头。
比如需要支持`patch`
>'Access-Control-Allow-Methods','POST,GET,OPTIONS,DELETE,PATCH'

### 自定义响应头
自定义响应头是指在响应中添加自定义的 HTTP 头。自定义响应头可以用于传递额外的信息，例如自定义的错误码、自定义的响应消息等。

```nodejs
app.get('/info', (req, res) => {
    res.set('zsm', '1')
    res.json({
        code: 200
    })
})
```
那么前端接收的方法也很简单
```nodejs
 fetch('http://localhost:3000/info').then(res=>{
    const headers = res.headers 
    console.log(headers.get('zsm'))
    return res.json()
}).then(res=>{
    console.log(res)
})

```
我们只需要去接收读取就行了，但是发现是null 这是因为后端没有抛出该响应头所以后端需要增加抛出的一个字段
```nodejs
app.get('/info', (req, res) => {
    res.set('zsm', '1')
    res.setHeader('Access-Control-Expose-Headers', 'zsm')
    res.json({
        code: 200
    })
})

```

