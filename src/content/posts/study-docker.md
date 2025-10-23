---
title: Study Docker
published: 2025-06-09
pinned: false
description: 学习docker的一些笔记
tags: ['docker']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-06-09
pubDate: 2025-06-09
---


## 中文文档
https://yeasy.gitbook.io/docker_practice

## 关于部署
mac可以用docker-desktop，或者是orbstack(这个真的好用xd)，linux就直接指令操作吧。win不推荐，推荐wsl里面搞docker然后映射出来

## 基本知识
```
docker search nginx 寻找镜像 有ok的是官方的
docker pull nginx 直接下载
docker images 查看镜像
docker hub 镜像仓库
docker rmi删除镜像

docker run 运行
docker run [OPTIONS] IMAGE [COMMAND] [ARG...]
-d: 后台运行容器，并返回容器ID。
-i: 以交互模式运行容器，通常与 -t 一起使用。
-t: 分配一个伪终端。
-p HOST_PORT:CONTAINER_PORT: 将主机的端口映射到容器的端口。
-v HOST_DIR:CONTAINER_DIR: 将主机目录挂载到容器中。
--name NAME: 为容器指定一个名称。
-e KEY=VALUE: 设置环境变量。
示例
运行带有交互终端的 Ubuntu 容器：
docker run -it ubuntu
在后台运行 Nginx 容器并映射端口：
docker run -d -p 8080:80 nginx
挂载本地目录到容器中：
docker run -v /local/path:/container/path my-image


docker ps 查看容器
docker ps -a 查看所有容器（包括停止的）

docker stop 停止容器
docker rm 删除容器
docker start 启动容器
docker stats 查看容器状态
docker logs 查看容器日志
docker exec 进入容器

docker commit 创建镜像
docker save 保存
docker load 加载

docker inspect zsm_2 查看容器信息(主要是ip)

docker network create 创建网络
--driver 指定网络驱动(默认是bridge)
--subnet 指定子网
--gateway 指定网关
--ip-range 指定ip范围
--attachable 是否允许容器加入网络

docker network rm my_custom_network  删除网络
docker run -d --name my_container --network my_custom_network nginx 启动容器时指定网络
docker network connect my_custom_network my_container  将运行的容器加入网络

```

## compose.yaml编写
### 顶级元素
```
name # 容器组名称
services # 容器组,服务
networks # 网络
volumes: # 卷
configs: # 配置
secrets: # 密钥
```

## dockerfile编写
```
FROM #指定镜像基础环境
RUN #运行自定义命令
CMD #容器启动命令或者是参数
LABEL #标签
EXPOSE #暴露端口
ENV #环境变量
ADD #添加文件到镜像
COPY #复制文件到镜像
ENTRYPOINT #容器固定启动命令
WORKDIR #工作目录
USER #用户
VOLUME #挂载目录
ARG #参数

```

## 动态端口实现
在ctf题目里面，总有一些题的环境打开后发现端口是不定的，就是这样实现的。想gzctf平台上面是已经自动实现了，自己练习的时候可以用以下方式实现
### 动态端口映射
```
version: "3"
services:
  server:
    build: .
    restart: always
    ports:
      - "2222-2232:2222"  # 这里定义了一个端口范围
```

### 环境变量配置端口
```
version: "3"
services:
  server:
    build: .
    restart: always
    environment:
      SERVICE_PORT: 2222  # 容器内服务监听的端口
    ports:
      - "${HOST_PORT:-2222}:2222"  # 外部端口可以通过环境变量 HOST_PORT 设置
```

## 注意事项
在用docker打包一个项目时，可以利用`.dockerignore`文件，把不需要直接打包的文件除去，比如`nodejs`项目的`node_modules`文件夹等。  

这样的好处是，在docker中去配置环境，避免冲突，也避免了打包时因为内存太大而造成的速度影响

## 未完结
咕咕咕