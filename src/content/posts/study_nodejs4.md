---
title: Study nodejs 「4」
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


## Redis

### docker部署
本地是mac，加上初学不想污染环境，就用docker试试

```
docker pull redis
docker run -p 6379:6379 -d - redis-server --appendonly yes
docker rename funny_buck redis
docker exec -it redis redis-cli
//vsc中Database Client可以可视化
```

### 字符串命令
```
SET key value [NX|XX] [EX seconds] [PX milliseconds] [GET]
```
`key`：要设置的键名。
`value`：要设置的值。
`NX`：可选参数，表示只在键不存在时才设置值。
`XX`：可选参数，表示只在键已经存在时才设置值。
`EX seconds`：可选参数，将键的过期时间设置为指定的秒数。
`PX milliseconds`：可选参数，将键的过期时间设置为指定的毫秒数。
`GET`：可选参数，返回键的旧值。

比如
>SET name zsm NX EX 60

就是在键名`name`不存在时，设置键名为`name`的值为`zsm`，并且设置键名的过期时间为60秒。

>SET score 5 XX

在键名`score`已经存在时，设置键名为`score`的值为`5`。

>DEL name

删除键名为`name`的键值对。

### 集合命令

```
SADD fruits "apple"
SADD fruits "banana"
SADD fruits "orange"
```
`SADD`命令用于向集合中添加元素。

`SADD`命令的语法为：`SADD key member [member ...]`，其中`key`为集合的名称，`member`为要添加的元素。

```
SMEMBERS fruits
```
`SMEMBERS`命令用于获取集合中的所有元素。

```
SISMEMBER fruits "apple"
```
`SISMEMBER`命令用于判断一个元素是否在集合中。

```
SREM fruits "banana"
```
`SREM`命令用于从集合中删除一个或多个元素。

```
SCARD fruits
```
`SCARD`命令用于获取集合中的元素个数。

```
SRANDMEMBER fruits
```
`SRANDMEMBER`命令用于从集合中随机获取一个元素。

```
SUNION fruits vegetables
```
`SUNION`命令用于将多个集合进行并集操作。

```
SINTER fruits vegetables
```
`SINTER`命令用于将多个集合进行交集操作。

```
SDIFF fruits vegetables
```
`SDIFF`命令用于将多个集合进行差集操作。

### 哈希表命令

```
HSET obj name "John"
HSET obj age 25
HSET obj email "john@example.com"
```
`HSET`命令用于向哈希表中添加键值对。

`HSET`命令的语法为：`HSET key field value [field value ...]`，其中`key`为哈希表的名称，`field`为键名，`value`为键值。

```
HGET obj name
```
`HGET`命令用于获取哈希表中指定键的值。

```
HMSET obj name "John" age 25 email "john@example.com"
```
`HMSET`命令用于向哈希表中添加多个键值对。

```
HMGET obj name age email
```
`HMGET`命令用于获取哈希表中指定键的值。

```
HGETALL obj
```
`HGETALL`命令用于获取哈希表中的所有键值对。

```
HDEL obj age email
```
`HDEL`命令用于删除哈希表中的指定键。

```
HEXISTS obj name
```
`HEXISTS`命令用于判断哈希表中是否存在指定键。

```
HKEYS obj
```
`HKEYS`命令用于获取哈希表中的所有键。

```
HVALS obj
```
`HVALS`命令用于获取哈希表中的所有值。

```
HLEN obj
```
`HLEN`命令用于获取哈希表中的键值对个数。

### 列表命令

```
RPUSH key element1 element2 element3
LPUSH key element1 element2 element3
```

`RPUSH`命令用于将元素从右侧插入列表。
`LPUSH`命令用于将元素从左侧插入列表。
`RPUSH`&`LPUSH`命令的语法为：`RPUSH key element [element ...]`，其中`key`为列表的名称，`element`为要插入的元素。

```
LINDEX key index
LRANGE key start stop
```
`LINDEX`命令用于获取列表中指定索引位置的元素。
`LRANGE`命令用于获取列表中指定范围内的元素。

```
LSET key index newValue
```
`LSET`命令用于修改列表中指定索引位置的元素的值。

```
LPOP key
RPOP key
LREM key count value
```
`LPOP`命令用于从列表的左侧移除并返回第一个元素。
`RPOP`命令用于从列表的右侧移除并返回最后一个元素。
`LREM`命令用于从列表中删除指定数量的指定值元素。

```
LLEN key
```
`LLEN`命令用于获取列表的长度。

### 持久化

1. RDB（Redis Database）持久化：RDB是一种快照的形式，它会将内存中的数据定期保存到磁盘上。可以通过配置Redis服务器，设置自动触发RDB快照的条件，比如在指定的时间间隔内，或者在指定的写操作次数达到一定阈值时进行快照保存。RDB持久化生成的快照文件是一个二进制文件，包含了Redis数据的完整状态。在恢复数据时，可以通过加载快照文件将数据重新加载到内存中。

2. AOF（Append-Only File）持久化：AOF持久化记录了Redis服务器执行的所有写操作命令，在文件中以追加的方式保存。当Redis需要重启时，可以重新执行AOF文件中保存的命令，以重新构建数据集。相比于RDB持久化，AOF持久化提供了更好的数据恢复保证，因为它记录了每个写操作，而不是快照的形式。然而，AOF文件相对于RDB文件更大，恢复数据的速度可能会比较慢。

启动docker的时候- redis-server --appendonly yes就是打开了rdb
```
docker exec -it redis bash
root@4f92f5f4b595:/data# ls
appendonlydir  dump.rdb
```

如果想通过配置文件修改，可以通过下载tar包或者是编写dockerfile

### 订阅&事务
#### 订阅
监听命令
subscribe

推送命令
publish

整体效果
```
127.0.0.1:6379> subscribe zsm
1) "subscribe"
2) "zsm"
3) (integer) 1
1) "message"
2) "zsm"
3) "200"

127.0.0.1:6379> publish zsm 200
(integer) 1
```

其实就是redis多个实例之间进行通讯，但是不能持久化

#### 事务
不能回滚，保证原子的一致性

打开
multi
关闭
discard

```
127.0.0.1:6379> set A 100
OK
127.0.0.1:6379> set B 100
OK
127.0.0.1:6379> multi
OK
127.0.0.1:6379(TX)> set A 0
QUEUED
127.0.0.1:6379(TX)> set B 200
QUEUED
127.0.0.1:6379(TX)> exec
1) OK
2) OK
```

有点类似于队列，可以写入一堆东西，然后一块执行，那如果可以定时，就是理想的使用方法了

### 主从复制
docker实现也不算麻烦

主
```
mkdir -p /home/docker/redis6379/conf
mkdir -p /home/docker/redis6379/data
vi /home/docker/redis6379/conf/redis.conf

# 服务端口 默认6379
port 6379
# 关闭保护模式，允许远程连接
protected-mode no
# 密码
requirepass 123456

```
从
```
mkdir -p /home/docker/redis6380/conf
mkdir -p /home/docker/redis6380/data 
vi /home/docker/redis6380/conf/redis.conf

# 服务端口 默认6379
port 6380
# 关闭保护模式，允许远程连接
protected-mode no
# 密码
requirepass 123456
# 主节点密码
masterauth 123456
# 主从复制
replicaof 172.16.8.186 6379

```

启动
主
```
docker run -d \
-p 6379:6379 \
--name redis6379 \
--restart always \
--privileged=true \
-v /home/docker/redis6379/conf/redis.conf:/etc/redis/redis.conf \
-v /home/docker/redis6379/data:/data \
redis:latest \
redis-server /etc/redis/redis.conf

```
从
```
docker run -d \
-p 6381:6381 \
--name redis6381 \
--restart always \
--privileged=true \
-v /home/docker/redis6381/conf/redis.conf:/etc/redis/redis.conf \
-v /home/docker/redis6381/data:/data \
redis:latest \
redis-server /etc/redis/redis.conf

```

### redis&nodejs联动
>npm i ioredis

```
import Redis from "ioredis";
//命令行=>面向对象
const redis = new Redis({
    host: "127.0.0.1",
    port: 6379,
})

// redis.set("name", "zhangsan")
// redis.get("name").then((res) => {
//     console.log(res)
// })

//redis.setex("age",5, 18)//设置过期时间

//redis.sadd("set", "a", "b", "c")
// redis.smembers("set").then((res) => {
//     console.log(res)
// })

// redis.srem("set", "a", "b", "c")

// redis.hset("hash", "name", "zhangsan", "age", 18)

//redis.hdel("hash", "name")
redis.hgetall("hash").then((res) => {
    console.log(res)
})
```

和数据库的`prisma`那边不一样，这边感觉就是吧命令直接变成代码了

## lua&redis&nodejs

实现一个简单的限流阀，就是比如腾讯游戏抽奖每次只能在有限时间点有限次数的那种

index.html
```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>

<body>
    <button id="btn">抽奖</button>
    <script>
        const btn = document.getElementById('btn');
        btn.onclick = function () {
            fetch('http://localhost:3000/lottery').then(res => {
                return res.text()
            }).then(data => {
                console.log(data)
                alert(data)
            })
        }
    </script>
</body>

</html>
```
index.js
```js
import express from 'express';
import Redis from 'ioredis';
import fs from 'node:fs';

const lua = fs.readFileSync('./index.lua', 'utf-8');
const redis = new Redis();
const app = express();

//限流阀
const KEY = 'lottery';
const TIME = 30
const LIMIT = 5

// 设置 CORS
app.all('*', (req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

app.get('/lottery', (req, res) => {
    redis.eval(lua, 1, KEY, TIME, LIMIT, (err, result) => {
        if (err) {
            console.log(err)
            return res.status(500).json({ error: err.message });
        }
        if (result == 1) {
            res.send('抽奖成功')
        } else {
            res.send('请稍后再试')
        }
    })
})

app.listen(3000, () => {
    console.log('Server is running on port 3000');
})
```
index.lua
```lua
local key = KEYS[1]
local inerval = tonumber(ARGV[1])
local count = tonumber(ARGV[2])

local limit = tonumber(redis.call("get", key) or "0")

if limit + 1 >= count then
    return 0
else
    redis.call("incr", key)
    redis.call("expire", key, inerval)
    return 1
end
```
只得注意的问题在于跨域处理，感觉lua的语法还是比较简单的，注意和js的交互处理