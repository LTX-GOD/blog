---
title: 五一长假vue3+nodejs全栈项目复盘
published: 2025-05-04
pinned: false
description: 一个小项目
tags: ['nodejs']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-05-04
pubDate: 2025-05-04
---



## 前言
五一闲来无事，也不是特别想打ctf，啧，最近感觉打ctf的体验越来越不对了，热爱好像变质了？搓个项目玩吧。在这里复盘一下

## 整体框架
前端`vue3`，好久没搓vue了，还挺怀念去年暑假学vue的。  
后端`nodejs+expres`，本来想用`fastify`，但是掌握度不高，还是稳一点吧，别给自己写恶心了。  
项目挺老套的，新闻+产品管理/发布项目，两套前端(admin&web)，一个后端(server)。管理又分为管理员和编辑员。

### 前端
#### 初期配置
`vue create admin`创建后台管理项目，在8080端口运行  
`vue create web`创建企业门户页面，在8081端口运行  
因为用的一套后端在3000端口，上来直接配置`vue.config.js`，利用反向代理和后端通讯
```js
const { defineConfig } = require('@vue/cli-service')
module.exports = defineConfig({
  transpileDependencies: true,
  devServer: {
    proxy: {
      "api阿巴阿巴": {
        target: "http://localhost:3000",
        changeOrigin: true
      }
    }
  }
})
```
不过让我最好奇的他这个居然不是es6写法

#### 模板组件
为了前端不那么丑，我大量使用了`element-plus`的组件，使用方法照抄官网的就行，值得注意的是参数调整和自己灵活应用组件

#### 关于时间处理
时间规范化处理可以使用`moment`，可以参考他们的官方文档，一般常用的方法是
```js
import moment from 'moment'
moment.locale("zh-cn");

const formatTime = {
    getTime: (data) => {
        return moment(data).format('YYYY/MM/DD')
    }
}

export default formatTime
```

#### 关于文件上传
因为传新闻和产品的时候总会用到的，虽然写好一个复制粘贴过去就行，但是又长又臭非常的影响我心情，这种时候可以利用封装的思想，把这个单独封装成一个组件去使用  

#### 关于路由配置
路由配置又麻烦又简单的，创建的时候就有一个`router/index.js`，因为`admin`项目的左侧栏会放很多的子选项，就会加一堆路由，用子路由实现是合理的，但是就会有一些问题，比如权限性问题，我又不想在后端实现，所以我专门写了个`router/config.js`去实现动态路由，并在里面实现权限管理`requireAdmin`，感觉比较简陋，就是对编辑员隐藏这个路由  

#### 关于拦截器
这里直接使用`axios`，直接把官网的拉过来用了，写了个`util/axios.config.js`，去实现拦截器

#### 关于富文本编辑器
现在用的还是`wangeditor`的v4，为什么呢？因为很简单，可以直接导入，不像v5需要自己再重新配置，但是还是过时了，后面再换成v5或者是其他的markdown编辑器吧，咕咕咕

#### 关于样式
经典常用`<style lang="scss" scoped>` ，但是如果Element Plus 的子组件，它的 DOM 结构并不在当前组件的模板中，我就不能加效果了，那么就可以用`::v-deep`去穿透，比如
```
.avatar-uploader .el-upload { ... }
编译后
.avatar-uploader .el-upload[data-v-xxxxxx] { ... }

::v-deep .avatar-uploader .el-upload { ... }
编译后
[data-v-xxxxxx] .avatar-uploader .el-upload { ... }
```
这样就可以作用进去了

### 后端
#### 初期配置
`express`默认创建时commonjs模式，不喜欢，先全部重构成es6，再规划一下  
经典的nodejs+MVC.routes路由是纯接口==>controllers数据处理=>models层数据操作==>数据库==>返回数据

#### 数据库
这里用的`mongo`，nodejs里面用`mongoose`去创建模型，可视化用的是vsc的插件`Database Client`

#### 关于token
这里使用`jsonwebtoken`去实现，方便好用放心，同时结合前端的身份区分去进行完善，因为是自己写的小项目，key也就随便输入了一个常用的，例如
```js
import jsonwebtoken from 'jsonwebtoken'
const secret = 'abab'
export class JWT {
    generate(value, expries) {
        return jsonwebtoken.sign(value, secret, { expiresIn: expries })
    }
    verify(token) {
        try {
            return jsonwebtoken.verify(token, secret)
        } catch (error) {
            return false
        }
    }
}

//验证token
app.use((req, res, next) => {
  //如果token有效，next(),如果无效，返回401给前端
  if (req.url === '/adminapi/user/login') {
    next()
    return;
  }
  const token = req.headers["authorization"].split(" ")[1]
  if (token) {
    const payload = jwt.verify(token)
    if (payload) {
      const newToken = jwt.generate({
        _id: payload._id,
        username: payload.username
      }, '1d')
      res.header("Authorization", newToken)
      next()
    } else {
      res.status(401).send({
        errCode: "-1",
        errorInfo: "token过期"
      })
    }
  }
})
```

#### 关于MVC&数据库
nodejs的MVC是要自己手动实现的，就像上面所写的一样，需要创建三个文件夹，分别去实现不同的功能，这点就没springboot好。  
同时创建之后，再在下面创建admin和web文件夹，分别去处理管理页面和门户页面，以免写的api太乱。  
关于数据库本地docker去搭mango并且关联到`db`这个文件夹，同时一套模型对应两套前端，方便调用，也没有同步的问题，比如
```js
import mongoose from 'mongoose'

const { Schema } = mongoose

const NewsSchema = new Schema({
    title: String,
    content: String,
    category: Number,        // 123
    cover: String,  // 封面
    isPublish: Number,        // 发布状态
    editTime: Date,          // 编辑时间
})

// 注册并导出模型
const NewsModel = mongoose.model("news", NewsSchema)
export default NewsModel
```
config文件里面去写关于数据库的东西
```js
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
那么该如何使用呢，`server`文件夹下的直接对数据库模型进行调用，在`XXserver.js`里面写入api，比如
```js
import NewsModel from '../../models/NewsModel.js'
const NewsService = {
    add: async ({ title, content, category, isPublish, cover, editTime }) => {
        return NewsModel.create({
            title, content, category, isPublish, cover, editTime
        })
    },
    getList: async ({ _id }) => {
        return _id ? NewsModel.find({ _id }) : NewsModel.find({})
    },
    publish: async ({ _id, isPublish, editTime }) => {
        return NewsModel.updateOne({
            _id
        }, {
            isPublish,
            editTime
        })
    },
    delList: async ({ _id }) => {
        return NewsModel.deleteOne(
            {
                _id
            }
        )
    },
    updateList: async ({ _id, title, content, category, isPublish, cover, editTime }) => {
        if (cover) {
            return NewsModel.updateOne({ _id }, {
                title, content, category, isPublish, cover, editTime
            })
        } else {
            return NewsModel.updateOne({ _id }, {
                title, content, category, isPublish, editTime
            })
        }
    }
}

export default NewsService
```
然后Controller文件再去调用server文件，最后合并到路由里面，这样就算是封装好了

## 个人感受
这个项目很简单，主要就是练手的，前后端交互和调试占了好多时间，还是写的太少了，和其他的对比的话，和spring不同，nodejs让我感觉更加组件化，个人写的更加舒服和享受。但是现在写进去的东西太少了，比如前面`study`系列的单点登录，orm等知识点都没用，并且小项目也凸显不出nodejs最大的优势，后面可能会改善这个，把这个复杂化，技术化，或者是直接去写一个更大的(或者是咕咕咕)