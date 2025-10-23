---
title: Study nodejs「2」
published: 2025-04-01
pinned: false
description: 学习nodejs的一些笔记
tags: ['nodejs']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-01
pubDate: 2025-04-01
---


## nodejs&mysql
现在学mysql和sqlserver(学校老师强制要求的)比较多，就先拿这些举例子了

### mysql2
一个把`nodejs&mysql&express`连接的包，顺便使用`js-yaml`去写配置
>npm install mysql2 express js-yaml

db.config.yaml
```yaml
db:
    user:root
    password:'root'
    host:127.0.0.1
    port:3306
    database:test
```
主要把ip端口和账号密码以及库的名称写入进去

index.js
```node
import express from 'express';
import mysql2 from 'mysql2/promise';
import fs from 'fs';
import jsyaml from 'js-yaml';

const yaml = fs.readFileSync('./db.config.yaml', 'utf8')
    const config = jsyaml.load(yaml)
console.log(config)
const sql = await mysql2.createConnection({
    ...config.db
})

const app = express();
app.use(express.json())
app.get('/', async (res, req) => {
    const [data] = await sql.query('SELECT * FROM users')
    res.send(data)
})

app.get('/user/:id', async (res, req) => {
    const [row] = await sql.query('SELECT * FROM users WHERE id = ?', [req.params.id])
    res.send(row)
})

app.use('/create', async (req, res) => {
    const { name, age, hobby } = req.body
    await sql.query('INSERT INTO users (name,age,hobby) VALUES (?,?,?)', [name, age, hobby])
    res.send('ok')
})

app.use('/update', async (req, res) => {
    const { id, name, age, hobby } = req.body
    await sql.query('UPDATE users SET name = ?, age = ?, hobby = ? WHERE id = ?', [name, age, hobby, id])
    res.send('ok')
})

app.post('/delete',async (req,res)=>{
    await sql.query(`delete from user where id = ?`,[req.body.id])
    res.send({ok:1})
})

const port = 3000;

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
```

通过上面的接口实现增删改查，然后测试的话用的是vsc的`REST Client`插件

```
# 查询全部
 GET http://localhost:3000/ HTTP/1.1

# 单个查询
GET http://localhost:3000/user/2 HTTP/1.1

# 添加数据
POST http://localhost:3000/create HTTP/1.1
Content-Type: application/json

{
    "name":"张三",
    "age":18
}

# 更新数据
POST http://localhost:3000/update HTTP/1.1
Content-Type: application/json

{
    "name":"法外狂徒",
    "age":20,
    "id":23
}


#删除
# POST http://localhost:3000/delete HTTP/1.1
# Content-Type: application/json

# {
#     "id":24
# }

```

### prisma
一个现代的orm框架，使用起来比较方便，流行的数据库也都支持。

### 安装以及初始化
```
//安装
npm install prisma
//初始化
prisma init --datasource-provider mysql
//连接mysql
修改.env文件 [DATABASE_URL="mysql://账号:密码@主机:端口/库名"]
```

### 创建数据库

prisma/schema.prisma
```
model Post {
  id       Int     @id @default(autoincrement()) //id 整数 自增
  title    String  //title字符串类型
  publish  Boolean @default(false) //发布 布尔值默认false
  author   User   @relation(fields: [authorId], references: [id]) //作者 关联用户表 关联关系 authorId 关联user表的id
  authorId Int
}

model User {
  id    Int    @id @default(autoincrement())
  name  String
  email String @unique
  posts Post[]
}
```
执行命令
>prisma migrate dev

或者是直接全部写入
```
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

model Post {
  id       Int     @id @default(autoincrement()) //id 整数 自增
  title    String  //title字符串类型
  publish  Boolean @default(false) //发布 布尔值默认false
  author   User   @relation(fields: [authorId], references: [id]) //作者 关联用户表 关联关系 authorId 关联user表的id
  authorId Int
}

model User {
  id    Int    @id @default(autoincrement())
  name  String
  email String @unique
  posts Post[]
}

```

他会自动帮你创建一个`.sql`文件
```sql
-- CreateTable
CREATE TABLE `Post` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `title` VARCHAR(191) NOT NULL,
    `publish` BOOLEAN NOT NULL DEFAULT false,
    `authorId` INTEGER NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `User` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `User_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Post` ADD CONSTRAINT `Post_authorId_fkey` FOREIGN KEY (`authorId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

```

### 使用
其实这个东西和`ts`联动是最强的，所以下面就写`ts`了

```ts
import express from 'express'
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
const app = express()
const port: number = 3000

app.use(express.json())

//关联查找
app.get('/', async (req, res) => {
    const data = await prisma.user.findMany({
        include: {
            posts: true
        }
    })
    res.send(data)
})

//单个查找
app.get('/user/:id', async (req, res) => {
    const row = await prisma.user.findMany({
        where: {
            id: Number(req.prisma.id)
        }
    })
    res.send(row)
})

//新增
app.post('/create', async (req, res) => {
    const { name, email } = req.body
    const data = await prisma.user.create({
        data: {
            name,
            email,
            posts: {
                create: {
                    title: '标题',
                    publish: true
                },
            }
        }
    })
    res.send(data)
})

//更新
app.post('/update',async (req, res) => {
    const {id,name,email}=req.body
    const data=await prisma.user.update({
        where:{
            id:Number(id)
        },
        data:{
            name,
            email
        }
    })
    req.send(data)
})

//删除
app.post('/delete', async (req, res) => {
    const { id } = req.body
    await prisma.post.deleteMany({
        where: {
            authorId: Number(id)
        }
    })
    const data = await prisma.user.delete({
        where: {
            id: Number(id),
        },
    })
    res.send(data)
})


app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
```

