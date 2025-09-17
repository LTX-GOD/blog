---
title: Study K8s
published: 2025-06-09
pinned: false
description: 学习k8s的一些笔记
tags: ['k8s']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-06-09
pubDate: 2025-06-09
---


## 关于安装
mac的话可以直接orb一把梭了，里面直接启动即可，如果不想的话，就直接去看[官方安装方法](https://minikube.sigs.k8s.io/docs/start/?arch=%2Flinux%2Fx86-64%2Fstable%2Fbinary+download)我感觉不如orb，linux和win只能安装官方的来咯

## 常用命令
### 基础信息查看命令
| 命令                            | 作用                                |
| ----------------------------- | --------------------------------- |
| `kubectl version`             | 查看客户端与服务端版本信息                     |
| `kubectl cluster-info`        | 查看集群的基本信息（API Server、Dashboard 等） |
| `kubectl get nodes`           | 查看集群中的节点                          |
| `kubectl describe node <节点名>` | 查看某个节点的详细信息                       |
| `kubectl get all`             | 查看当前命名空间下所有资源                     |

### Pod 相关操作
| 命令                                     | 作用                     |
| -------------------------------------- | ---------------------- |
| `kubectl get pods`                     | 查看所有 Pod               |
| `kubectl get pods -o wide`             | 查看 Pod 的详细信息（包含 IP、节点） |
| `kubectl describe pod <pod名>`          | 查看某个 Pod 的详细信息         |
| `kubectl logs <pod名>`                  | 查看 Pod 的日志输出           |
| `kubectl exec -it <pod名> -- /bin/bash` | 进入容器内部（需要容器中有 bash）    |
| `kubectl delete pod <pod名>`            | 删除指定 Pod               |

### Deployment、Service 等资源操作
| 命令                                                         | 作用                       |
| ---------------------------------------------------------- | ------------------------ |
| `kubectl get deployment`                                   | 查看 Deployment            |
| `kubectl describe deployment <名字>`                         | 查看 Deployment 详细信息       |
| `kubectl apply -f <yaml文件>`                                | 应用 YAML 文件，创建/更新资源       |
| `kubectl delete -f <yaml文件>`                               | 删除 YAML 文件定义的资源          |
| `kubectl scale deployment <名字> --replicas=<数量>`            | 扩缩容 Deployment 的副本数      |
| `kubectl rollout restart deployment <名字>`                  | 重启 Deployment（会滚动更新 Pod） |
| `kubectl rollout status deployment <名字>`                   | 查看 Deployment 的滚动更新状态    |
| `kubectl expose deployment <名字> --type=NodePort --port=80` | 暴露 Deployment 为服务        |

### 命名空间 Namespace 管理
| 命令                                                      | 作用             |
| ------------------------------------------------------- | -------------- |
| `kubectl get namespaces`                                | 查看所有命名空间       |
| `kubectl create namespace <名称>`                         | 创建新的命名空间       |
| `kubectl delete namespace <名称>`                         | 删除命名空间         |
| `kubectl get pods -n <namespace>`                       | 查看指定命名空间下的 Pod |
| `kubectl config set-context --current --namespace=<名称>` | 设置默认命名空间       |

### 配置管理（ConfigMap & Secret）
| 命令                                                            | 作用                          |
| ------------------------------------------------------------- | --------------------------- |
| `kubectl create configmap <名称> --from-literal=key=value`      | 创建 ConfigMap（从字面值）          |
| `kubectl create configmap <名称> --from-file=<文件路径>`            | 创建 ConfigMap（从文件）           |
| `kubectl get configmap`                                       | 查看 ConfigMap                |
| `kubectl describe configmap <名称>`                             | 查看 ConfigMap 详情             |
| `kubectl create secret generic <名称> --from-literal=key=value` | 创建 Secret                   |
| `kubectl get secret`                                          | 查看 Secret                   |
| `kubectl describe secret <名称>`                                | 查看 Secret 详情（数据为 base64 编码） |

### 资源清理与调试
| 命令                                | 作用                                        |
| --------------------------------- | ----------------------------------------- |
| `kubectl delete pod --all`        | 删除当前命名空间下的所有 Pod                          |
| `kubectl get events`              | 查看事件日志，排查问题                               |
| `kubectl top pod`                 | 查看 Pod 的 CPU 和内存使用情况（需要安装 Metrics Server） |
| `kubectl cp <pod名>:<容器路径> <本地路径>` | 从容器中拷贝文件到本地                               |
| `kubectl debug <pod名>`            | 使用临时容器调试（1.18+ 版本支持）                      |

### 进阶命令和补充
| 命令                         | 作用                                    |
| -------------------------- | ------------------------------------- |
| `kubectl edit <资源类型> <名称>` | 使用编辑器修改资源定义                           |
| `kubectl explain <资源>`     | 查看资源字段的文档说明                           |
| `kubectl api-resources`    | 查看集群支持的 API 资源类型                      |
| `kubectl get <资源> -A`      | 查看所有命名空间的资源（如 `-A` 表示 all namespaces） |

## Pod&Deployment&Service
### Pod
是Kubernetes中最小的可调度单元，表示运行中的的一个or多个容器，比如
```
kubectl get pods                                      
NAME                                  READY   STATUS    RESTARTS   AGE
redis-c479dfb5-wcj8g                  1/1     Running   0          45h
yunjisuan-backend-5fbbd85dd8-kkqq7    1/1     Running   0          43h
yunjisuan-frontend-56fd559cbd-gjf2b   1/1     Running   0          43h
```
我的视角里把他当作一个容器的载体，一般是一对一的关系，而且当这个pod挂掉了，他是不会自动重建的，需要用`Deployment`去启动，这也是为什么官方不会让你直接创建pod的原因？

### Deployment
是一种控制器，用于管理 Pod 的副本、副本数量、升级、回滚等，比如
```
kubectl get deployments    
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE
redis                1/1     1            1           45h
yunjisuan-backend    1/1     1            1           43h
yunjisuan-frontend   1/1     1            1           43h
```
在我视角里他是pod的管理者，并且可以自动重新创建运行失败的pod，具备高可用和可扩展性。Deployment 就像是 Pod 的调度与生命周期控制器  

### Pod与Deployment的关系
可能会注意到
>kubectl get deployments    
kubectl get pods   

这两条指令的输出内容是差不多的，为什么呢？  
看一个层级结构图吧
```
Deployment
   └── ReplicaSet（自动管理）
         └── Pod（实际运行）
```
+ Deployment 是“宣言式配置”：你说我需要 1 个 nginx 服务，它就帮你创建和维持它。
+ ReplicaSet 是由 Deployment 自动创建的副本控制器，不需要你关心。
+ Pod 是最终由 ReplicaSet 实际运行的容器单元。  

那我目前在一个Deployment下只创建了一个pod，`kubectl get deployments`显示的是部署情况，`kubectl get pods`显示的是真实运行的容器实例，所以相似是合理的，并且可以发现，pod在创建时会自动加上一个随机字符串的后缀  

### Service
Pod 是会消失和变化的（比如被重新调度、重启等），而它们的 IP 地址也是 不固定的。

所以为了让外部访问、或内部服务间通信能找到 Pod、负载均衡、自动发现，就需要一个“中间层”来负责这个事，那就是：service  

**为什么需要 Service？**
| 问题              | Service 怎么解决               |
| --------------- | -------------------------- |
| Pod 的 IP 不稳定？   | Service 提供一个固定 IP 和 DNS 名字 |
| 有多个 Pod（副本）？    | Service 自动做负载均衡            |
| 不同命名空间、服务间需要通信？ | Service 让通信变得可控和可配置        |
| 想暴露服务到集群外部？     | Service 可以暴露端口给外部访问        |

**Service 的类型**
| 类型              | 说明                   | 用途               |
| --------------- | -------------------- | ---------------- |
| `ClusterIP`（默认） | 只在集群内部可访问            | 后端服务通信（比如：前端调后端） |
| `NodePort`      | 绑定每个 Node 的某个端口，对外暴露 | 外部访问集群中服务        |
| `LoadBalancer`  | 由云服务商分配一个负载均衡器 IP    | 生产环境常用，适合云平台     |
| `ExternalName`  | 映射到外部 DNS 名称         | 访问外部服务（如数据库）     |

一般部署是通过编辑文件实现效果  
假设有个 Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-backend
  template:
    metadata:
      labels:
        app: my-backend
    spec:
      containers:
        - name: app
          image: my-backend:latest
          ports:
            - containerPort: 8080
```
我们为它创建一个 Service去ClusterIP：
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-backend-service
spec:
  type: ClusterIP
  selector:
    app: my-backend
  ports:
    - port: 80           # Service 暴露的端口
      targetPort: 8080   # 容器实际监听的端口
```
其他的pod就可以通过`http://my-backend-service:80`访问

### Service & Pod 的关联
Kubernetes 中的 Pod 会带有 labels（标签），而 Service 会通过 selector（选择器）来选中这些 Pod，两者通过这个机制产生关联，比如pod的定义如下
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-backend-pod
  labels:
    app: my-backend
    tier: backend
spec:
  containers:
    - name: backend
      image: my-backend:latest
      ports:
        - containerPort: 8080
```
你就可以看见`labels`的内容是`app`和`tier`，然后我们定义一个 Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-backend-service
spec:
  selector:
    app: my-backend
  ports:
    - port: 80
      targetPort: 8080
```
在`selector`里面指向这个`app`，这个server就会找到所有含这个标签的pod，并且添加到Endpoints(负载池)里面。  
示意图
```
[ Service ]
   |
   └── selector: app=xxx
         ↓（匹配标签）
   ┌───────────────┐
   │    Pod 1      │ ← labels: app=xxx
   ├───────────────┤
   │    Pod 2      │ ← labels: app=xxx
   └───────────────┘

Service 自动负载均衡访问这两个 Pod！
```

## Namespace
Namespace 是 Kubernetes 的逻辑隔离机制，可以把同一个集群划分成多个“虚拟子集群”。就像是在一个东西里面又分了好几块，互不影响，各自管理。  

### Namespace 和哪些东西有关系
**资源对象的作用域**
| 属于 Namespace 的资源                     | 示例      |
| ------------------------------------ | ------- |
| Pod / Deployment / StatefulSet / Job | 运行的工作负载 |
| Service / Ingress                    | 服务暴露方式  |
| ConfigMap / Secret                   | 配置和敏感数据 |
| PVC（PersistentVolumeClaim）           | 存储请求    |
| ServiceAccount / Role / RoleBinding  | 权限控制    |

**访问权限控制**
比如
```yaml
kind: Role
metadata:
  namespace: dev
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "create"]
```
配合 RoleBinding(绑定用户用的)，就可以让某个用户只能操作 dev 命名空间里的 Pod  

**资源配额限制**
Kubernetes 支持对每个命名空间限制 CPU、内存、Pod 数量等资源，防止“某一方霸占资源”。
```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: mem-cpu-limit
  namespace: dev
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 4Gi
    limits.cpu: "4"
    limits.memory: 8Gi
```
这样去设置上限  

**名字隔离**
同一个名字在不同的命名空间内是可以重复的
>kubectl get pods -n dev
kubectl get pods -n prod

**DNS 服务发现**
 同名服务在不同命名空间中是不会冲突的
比如`http://my-service.default.svc.cluster.local`的完整格式是`<service-name>.<namespace>.svc.cluster.local`

## ConfigMap & Secret

| 名称            | 作用                       | 内容类型    | 存储方式                   |
| ------------- | ------------------------ | ------- | ---------------------- |
| **ConfigMap** | 存储**非敏感配置**（如环境变量、配置文件）  | 普通明文    | Base64 编码但不加密          |
| **Secret**    | 存储**敏感信息**（如密码、Token、证书） | 加密/编码内容 | 默认 Base64，可配合密钥管理器加密存储 |

### ConfigMap 示例
先创建一个
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: default
data:
  APP_NAME: "MyApp"
  APP_ENV: "dev"
  CONFIG_JSON: |
    {
      "logLevel": "debug",
      "maxConn": 100
    }
```
在pod中作为环境变量使用
```yaml
env:
  - name: APP_NAME
    valueFrom:
      configMapKeyRef:
        name: my-config
        key: APP_NAME
```
在pod中挂载为文件使用
```yaml
env:
  - name: APP_NAME
    valueFrom:
      configMapKeyRef:
        name: my-config
        key: APP_NAME
```

### Secret 示例
先创建一个
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: default
type: Opaque
data:
  DB_PASSWORD: bXlwYXNzd29yZA==
```
作为环境变量使用
```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: my-secret
        key: DB_PASSWORD
```
挂载为文件使用
```yaml
volumes:
  - name: secret-vol
    secret:
      secretName: my-secret
volumeMounts:
  - name: secret-vol
    mountPath: "/etc/secret"
```

## k8s&docker
### 编年史
在很久很久以前(v1.3 ～ v1.19)，k8s默认启动pod是docker，v1.20开始宣布弃用 Dockershim，v1.24正式弃用Dockershim  
可以认为以前的pod启动顺序是
>kubectl → kubelet → Dockershim → Docker → 容器

后面k8s感觉还是太重了，就干脆只用自己的`containerd`了

### 如何k8s+docker

假如我现在有一个写好的三端项目，后端/前端/小程序，我分别包了一个docker去运行，我现在有需求去多节点分布式部署，该怎么办呢？  
答案很简单：k8s里面跑docker(这样我写的dockerfile也不会浪费)  

如何实现这种操作呢？  

首先你要知道，docker里面也有`containerd`，哎，那实际上原理相同，我让k8s的`containerd`去跑docker镜像的内容进行了，如图所示
```
[ 开发者 ]
    ↓ docker build
[ 本地镜像 ]
    ↓ docker push
[ 镜像仓库（如 Harbor / Docker Hub） ]
    ↓ kubectl apply
[ K8s 控制器 ]
    ↓ 调度到 Node
[ kubelet ]
    ↓ container runtime（Containerd）
[ Pod 中容器运行 ]
```
而去调用docker就要依赖`.yaml`文件的编写了，如
```bash
docker build -t myapp:v1 .
docker tag myapp:v1 registry.example.com/myapp:v1
docker push registry.example.com/myapp:v1
```

我这个时候要在pod里面引用这个镜像
```yaml
containers:
  - name: myapp
    image: registry.example.com/myapp:v1
```
然后只要指令部署即可了
```bash
kubectl apply -f myapp-deployment.yaml
```

### 优点
**作用方面**
首先docker和k8s在一定程度上的任务是不同的
| 工具             | 主要职责                   | 类似比喻        |
| -------------- | ---------------------- | ----------- |
| **Docker**     | 用来**构建镜像**，本地运行测试容器    | 工厂生产产品      |
| **Kubernetes** | 管理和编排容器，自动部署、扩缩容、服务发现等 | 仓库 + 快递调度系统 |

**开发/部署/运维方面**
我在本地进行项目开发，完成后构建docker，然后推送镜像，云端只需要写个`.yaml`文件就可以部署了，你说爽不爽。并且这样开发只用在意docker，运维之用在意k8s，各司其职

**自动化**
可以实现自动化推送部署更新
>开发提交代码 → 自动构建 Docker 镜像 → 自动推送 → K8s 自动更新部署

## 未完结
咕咕咕