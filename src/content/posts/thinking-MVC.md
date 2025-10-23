---
title: 关于MVC的小笔记or总结
published: 2025-06-06
pinned: false
description: 关于MVC的小笔记or总结
tags: ['nodejs']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-06-06
pubDate: 2025-06-06
---


## 前言
前面的nodejs「3」其实写过，但是很潦草且不深刻，这个稍微深刻一点

## 什么是MVC
三个字母对应三个单词，对应三个层次  

+ M->`Model`
+ V->`View`
+ C->`Control`

在我浅薄的理解下，`Model`层是对于数据库去建立sql模型，以及增删查改等操作。`Control`去作为M和V之间的中间件，去衔接贯通，并且在我的理解里面，这个不应该含有web层面的业务逻辑(下单，支付等操作)。而`View`就是与前端进行交互，得到or发送状态/数据等信息。  
那么web层面的逻辑就应该交给`Services`层去完成，衍生出来的`DTO`层，用于C->S时的数据处理以及规范，有趣的是他只是一个结构体，不能处理复杂的逻辑，比如权限管理，增加waf等，我第一开始真的想过在这里去加waf保证安全(如xss，sql注入等)  

## MVC&传统思想的不同
画图好像可以表现的更加直接
![wMVC](/images/wu.png)
![MVC](/images/1.png)
在我的理解里，传统思想的处理方式就是一个任务对应一个文件，比如用户创建个人信息时我需要一个文件，更新个人信息时需要另一个文件去处理，那么这样的坏处是什么呢，在进行类似操作时，我需要在不同的文件里面写入相同的函数，比如`upload`操作，而我在日后维护时，需要自己去一个一个修改，这就是缺点了  
而MVC就在处理这种情况。  
这里用nodejs+express举例吧(真对java不熟xd)，这里前后端分离的，C层就不写了  

```db.config.js
import mongoose from "mongoose";

mongoose.connect("mongodb://127.0.0.1:27017/company-system", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const db = mongoose.connection;

db.on("error", (err) => {
    console.error("❌ MongoDB connection error:", err);
});

db.once("open", () => {
    console.log("✅ MongoDB connected successfully!");
});

export default db;
```

```UserController.js
import UserService from '../../services/admin/UserService.js'
    getList: async (req, res) => {
        const result = await UserService.getList(req.params)
        res.send({
            ActionType: "OK",
            data: result
        })
    }
```

C层就会去调用S层

```UserService.js
import UserModel from "../../models/UserModel.js"
    getList: async ({ id }) => {
        return id ? UserModel.find({ _id: id }, ["username", "role", "avatar", "introduction", "gender"])
            : UserModel.find({}, ["username", "role", "avatar", "introduction", "gender"])
    }
```

S层会去调用M层

```UserModel.js
import mongoose from 'mongoose'

const { Schema } = mongoose

const UserSchema = new Schema({
    username: String,
    password: String,
    gender: Number,        // 0-未知，1-男，2-女
    introduction: String,  // 简介
    avatar: String,        // 头像地址
    role: Number           // 1-管理员，2-编辑
})

// 注册并导出模型
const UserModel = mongoose.model("user", UserSchema)
export default UserModel
```

这里去调用数据模型，整体流程可以明显感觉到我把一个函数拆成了三个文件里面的三个函数，并且依次调用，这样的好处是，如果日后需要修改某个逻辑，比如数据库的，我可以直接去完善模型，业务的直接去修改S层，修改一处，其他地方引用的同步有效，更加轻松方便。但是如果项目很大，初次编写的时候会很麻烦

## MVC&MVT
`MVT`是`Django`采用的框架模式，T是Template，负责封装构造要返回的html。对于`MVC`进行了拆分，主要点在于把C层拆分，有一个url分发器，它的作用是将一个个URL的页面请求分发给不同的view处理，view再调用相应的Model和Template。好处是解耦 URL 与业务逻辑
```urls.py
path('blog/<int:id>/', views.blog_detail)
```
把路由合并在一处去管理，并且和逻辑分开(这样看nodejs也有这种风格)。其他的好处就是`Django`自己强大的Form 系统，从V到T一条龙服务。  
总体来说MVT不是没有C层，而是让你感觉没有C层，写起来更加自然

## MVC+RESTful
`RESTful`是一种书写规范，虽然我很不规范，但是还是学一下  
RESTful就是对自己写的接口进行规范化，使用RESTful架构可以充分的发挥GET、POST、PUT、DELETE 四种请求方式的意义,简单的来说url地址中只包含名词表示资源，使用http的动词(GET | POST | PUT | DELTE)表示要进行的动作进行操作资源  
错误的编写方式
```
//添加用户
router.post('/user/addUser',(req,res)=>{
  //...
})
//更新用户信息
router.put('/user/updateUser',(req,res)=>{
  //...
})
//删除用户
router.delete('/user/delUser',(req,res)=>{
  //...
})
//获取用户信息
router.get('/user/getUser',(req,res)=>{
  //...
})
```
| 问题点                            | 原因说明喵                            |
| ------------------------------ | -------------------------------- |
| 🚫 接口中出现了动词（addUser / getUser） | URL 应该是名词，动词重复了 HTTP 方法的语义       |
| 🚫 可读性低                        | `/user/addUser` 到底是创建还是更新，看起来不直观 |
| 🚫 统一性差                        | 接口没有统一风格，扩展性差，维护困难               |
| 🚫 难以自动化文档生成                   | Swagger、Postman 无法统一识别 REST 动作   |


正确的编写方式
```
//添加用户
router.post('/user',(req,res)=>{
  //...
})
//更新用户信息
router.put('/user/:id',(req,res)=>{
  //...
})
//删除用户
router.delete('/user/:id',(req,res)=>{
  //...
})
//获取用户信息
router.get('/user',(req,res)=>{
  //...
})
```
| 优点           | 说明喵                                     |
| ----------------- | --------------------------------------- |
| ✅ **语义清晰，动词统一**   | `/user` 是资源名，POST 就是新增，GET 就是查询，PUT 是更新 |
| ✅ **URL 简洁明了**    | 看 URL 就知道是哪个资源、对谁进行什么操作                 |
| ✅ **自动文档更友好**     | Swagger/OpenAPI 识别接口更智能                 |
| ✅ **前后端协作更标准化**   | 不再需要靠接口注释来理解用途                          |
| ✅ **更符合 REST 标准** | 易于团队协作、代码规范化                            |
| ✅ **利于权限控制/缓存机制** | 因为语义明确，可对不同方法做精细控制                      |

RESTful 路由标准示例总结
| 操作     | 方法     | URL 示例       | 说明 |
| ------ | ------ | ------------ | -- |
| 获取所有用户 | GET    | `/users`     | 列表 |
| 获取单个用户 | GET    | `/users/:id` | 详情 |
| 新增用户   | POST   | `/users`     | 创建 |
| 更新用户   | PUT    | `/users/:id` | 修改 |
| 删除用户   | DELETE | `/users/:id` | 删除 |

用人话说这就是让前后端的沟通更加简单自然

## 总结
MVC是一个思想，不是一个固定的东西，适合自己/团队的就是最好的xd