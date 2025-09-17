---
title: Study nodejs「3」
published: 2025-04-06
pinned: false
description: 学习nodejs的一些笔记
tags: ['nodejs']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-04-06
pubDate: 2025-04-06
---


## MVC

这真的很java吧（）

### 安装依赖

>npm install inversify reflect-metadata express inversify-express-util prisma class-validator class-transformer

(数据库的东西用的还是上次的，懒得搞了，然后有个版本问题，npm install inversify-express-utils要求inversify@6.0.3express@4.21.1 )

### 封装方法
main.tx
```ts
import { InversifyExpressServer } from 'inversify-express-utils'
import { Container } from 'inversify'

const container = new Container()

const server = new InversifyExpressServer(container)
const app = server.build()

app.listen(3000, () => {
    console.log('server started')
})
```
这是最简单的封装，把`express`封装成一个`server`

`src` 下面创建亮个文件夹，一个`user`,一个`db`
```
db
     --index.ts
user
     --server.ts
     --user.dto.ts
     --controller.ts
```

### 正式写入
main.ts
```ts
import 'reflect-metadata'
import { InversifyExpressServer } from 'inversify-express-utils'
import { Container } from 'inversify'
import { UserController } from './src/user/controller'
import { UserService } from './src/user/service'
import express from 'express'
import { PrismaClient } from '@prisma/client'
import { PrismaDB } from './src/db'
const container = new Container() //Ioc搞个容器
/**
 * prisma依赖注入
 */
 //注入工厂封装db
container.bind<PrismaClient>('PrismaClient').toFactory(()=>{
    return () => {
        return new PrismaClient()
    }
})
container.bind(PrismaDB).toSelf()
/**
 * user模块
 */
container.bind(UserService).to(UserService) //添加到容器
container.bind(UserController).to(UserController) //添加到容器
/**
 * post模块
 */
const server = new InversifyExpressServer(container) //返回server
//中间件编写在这儿
server.setConfig(app => {
    app.use(express.json()) //接受json
})
const app = server.build() //app就是express

app.listen(3000, () => {
    console.log('http://localhost:3000')
})
```

user/controller.ts
```ts
import { controller, httpGet as GetMapping, httpPost as PostMapping } from 'inversify-express-utils'
import { inject } from 'inversify'
import { UserService } from './service'
import type { Request, Response } from 'express'
@controller('/user') //路由
export class UserController {

    constructor(
        @inject(UserService) private readonly userService: UserService, //依赖注入
    ) { }

    @GetMapping('/index') //get请求
    public async getIndex(req: Request, res: Response) {
        console.log(req?.user.id)
        const info = await this.userService.getUserInfo()
        res.send(info)
    }

    @PostMapping('/create') //post请求
    public async createUser(req: Request, res: Response) {
        const user = await this.userService.createUser(req.body)
        res.send(user)
    }
}
```
user/service.ts
```ts
import { injectable, inject } from 'inversify'
import { UserDto } from './user.dto'
import { plainToClass } from 'class-transformer' //dto验证
import { validate } from 'class-validator' //dto验证
import { PrismaDB } from '../db'
@injectable()
export class UserService {

    constructor(
        @inject(PrismaDB) private readonly PrismaDB: PrismaDB //依赖注入
    ) {

    }

    public async getUserInfo() {
        return await this.PrismaDB.prisma.user.findMany()
    }

    public async createUser(data: UserDto) {
        const user = plainToClass(UserDto, data)
        const errors = await validate(user)
        const dto = []
        if (errors.length) {
            errors.forEach(error => {
                Object.keys(error.constraints).forEach(key => {
                    dto.push({
                        [error.property]: error.constraints[key]
                    })
                })
            })
            return dto
        } else {
            const userInfo =  await this.PrismaDB.prisma.user.create({ data: user })
            return userInfo
        }
    }
}
```
user/user.dto.ts
```ts
import { IsNotEmpty, IsEmail } from 'class-validator'
import { Transform } from 'class-transformer'
export class UserDto {
    @IsNotEmpty({ message: '用户名必填' })
    @Transform(user => user.value.trim())
    name: string

    @IsNotEmpty({ message: '邮箱必填' })
    @IsEmail({},{message: '邮箱格式不正确'})
    @Transform(user => user.value.trim())
    email: string
}
```
db/index.ts
```ts
import { injectable, inject } from 'inversify'
import { PrismaClient } from '@prisma/client'

@injectable()
export class PrismaDB {
    prisma: PrismaClient
    constructor(@inject('PrismaClient') PrismaClient: () => PrismaClient) {
       this.prisma = PrismaClient()
    }
}
```
总体思想是去把不同的部分去分别封装，然后通过`inversify`去注入，这样子就实现了一个简单的MVC框架，有点类似java了，但是更加手动，dto验证可以去限制文件内容，类似`python`的`re`。

## JWT

### 安装依赖
>npm install jsonwebtoken passport passport-jwt

### 实现
我们在`src`中新建一个文件夹`jwt`，新建一个`index.ts`

jwt/index.ts
```ts
import { injectable} from 'inversify'
import passport from 'passport'
import jsonwebtoken from 'jsonwebtoken'
import {Strategy,ExtractJwt} from 'passport-jwt'

@injectable()
export class JWT {
    private secret:string='awfbkuahfbakjhfbafuwhjbeawhjfn'
    private jwtOptions={
        jwtFromRequest:ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey:this.secret
    }
    constructor(){
        this.strategy()
    }
    public strategy(){
        let str=new Strategy(this.jwtOptions,(payload,done)=>{
            done(null,payload)
        })
        passport.use(str)//激活插件
    }

    static middleware(){
        return passport.authenticate('jwt',{session:false})
    }//经过jwt认证后才能进入到下一个
    //生成token
    public createToken(data:Object) {
          jsonwebtoken.sign(data,this.secret,{expiresIN:'1h'})
    }
    //关联express
    public init(){
        return passport.initialize()
    }
}
```
需要注意的是我们要去激活插件，并且要关联express

main.ts
```ts
import 'reflect-metadata'
import { InversifyExpressServer } from 'inversify-express-utils'
import { Container } from 'inversify'
import { User } from './src/user/controller'
import { UserService } from './src/user/services'
import express from 'express'
import { PrismaClient } from '@prisma/client'
import { PrismaDB } from './src/db'
import { JWT } from './src/jwt'
const container = new Container()
/**
 * user模块
 */
container.bind(User).to(User)
container.bind(UserService).to(UserService)
/**
 *  封装PrismaClient
 */
container.bind<PrismaClient>('PrismaClient').toFactory(() => {
    return () => {
        return new PrismaClient()
    }
})
container.bind(PrismaDB).to(PrismaDB)
/**
 * jwt模块
 */
container.bind(JWT).to(JWT) //主要代码


const server = new InversifyExpressServer(container)
server.setConfig((app) => {
    app.use(express.json())
    app.use(container.get(JWT).init()) //主要代码
})
const app = server.build()

app.listen(3000, () => {
    console.log('Listening on port 3000')
})

```
user/controller.ts
```ts
import { controller, httpGet as GetMapping, httpPost as PostMapping } from 'inversify-express-utils'
import { UserService } from './services'
import { inject } from 'inversify'
import type { Request, Response } from 'express'
import { JWT } from '../jwt'
const {middleware}  = new JWT()
@controller('/user')
export class User {
    constructor(@inject(UserService) private readonly UserService: UserService) {

    }
    @GetMapping('/index',middleware()) //主要代码
    public async getIndex(req: Request, res: Response) {
        let result = await this.UserService.getList()
        res.send(result)
    }

    @PostMapping('/create')
    public async createUser(req: Request, res: Response) {
        let result = await this.UserService.createUser(req.body)
        res.send(result)
    }
}

```

user/services.ts
```ts
import { injectable, inject } from 'inversify'
import { PrismaDB } from '../db'
import { UserDto } from './user.dto'
import { plainToClass } from 'class-transformer'
import { validate } from 'class-validator'
import { JWT } from '../jwt'
@injectable()
export class UserService {
    constructor(
        @inject(PrismaDB) private readonly PrismaDB: PrismaDB,
        @inject(JWT) private readonly jwt: JWT //依赖注入
    ) {

    }
    public async getList() {
        return await this.PrismaDB.prisma.user.findMany()
    }

    public async createUser(user: UserDto) {
        let userDto = plainToClass(UserDto, user)
        const errors = await validate(userDto)
        if (errors.length) {
            return errors
        } else {
            const result = await this.PrismaDB.prisma.user.create({
                data: user
            })
            return {
                ...result,
                token: this.jwt.createToken(result) //生成token
            }
        }

    }
}

```
然后会发现接收信息存在类型问题，我们在`main.ts`加入
```ts
declare global {
    namespace Express {
        interface Request {
            id: number
            name: string
            email: string
        }
    }
}
```

## 最后结构
```
├── main.ts                 # 应用入口文件
├── src/
    ├── db/                 # 数据库相关
    │   └── index.ts       
    ├── jwt/               # JWT认证相关
    │   └── index.ts
    └── user/              # 用户模块
        ├── controller.ts  # 控制器
        ├── service.ts     # 服务层
        └── user.dto.ts    # 数据传输对象
```