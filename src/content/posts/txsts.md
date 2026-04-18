---
title: 第二届腾讯智能渗透挑战赛
published: 2026-04-17
pubDate: 2026-04-17
description: 腾讯AI渗透赛 zsm
pinned: false
tags: ["AI"]
author: zsm
category: AI
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

这次比赛和`浅兮 林息 Mlux Ricardo`一起参加，队伍名是`爱吃大红袍茶叶蛋`，最后结果是`主战场17名，零界论坛好像是12？`。

也感谢 DK 的性价比中转站给我提供了低价的oups4.6，真心推荐clawnode.cn

(值得一提的是我们并没有一个人是专业ai研发的，我密码手，他们是src佬、安服，有这种成绩还是不错的了)

![image](./attachments/260417-204137.avif)

### 比赛前两天

比赛前两天才报名上去的，当时只有一个大概的框架，是拿去年第九名的框架为基础进行优化修改的，当时也没想太多，就开始了。。。

## 整体架构

先叠甲：因为我们都不是专业的，所以专业人员别喷我😭

初期我们抱着能进前五十就是胜利的想法，进行了很保守的修改，整体框架如下

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Ling-Xi 灵犀 — 当前系统架构                          │
├──────────────────────────────────────────────────────────────────────────────┤
│  入口层                                                                      │
│  main.py / runtime_env.py / config.py                                       │
│  CLI: default / --lj / --all / --web                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│  调度层                                                                      │
│  scheduler_loop / status_monitor / background workers                        │
│                                                                              │
│  ┌─────────────────────┬──────────────────────┬───────────────────────────┐ │
│  │ Main Battle Runtime │ Forum Runtime        │ Async Workers             │ │
│  │ Platform API        │ Forum API + MCP      │ forum history bootstrap   │ │
│  │ ZoneScheduler       │ message_state        │ knowledge writeback       │ │
│  └──────────┬──────────┴──────────┬───────────┴──────────────┬────────────┘ │
│             │                     │                          │              │
├─────────────▼─────────────────────▼──────────────────────────▼──────────────┤
│  解题层                                                                      │
│  solve_challenge → create_initial_state → LangGraph                          │
│                                                                              │
│      ┌──────────┐   建议 / 纠偏   ┌────────────┐   工具调用   ┌──────────┐  │
│      │ Advisor  │◀──────────────▶│ Main Agent │────────────▶│ ToolNode │  │
│      │  顾问    │                 │  主攻手    │◀────────────│ / Tools  │  │
│      └────┬─────┘                 └─────┬──────┘   结果回填   └────┬─────┘  │
│           │ 连续失败 / 卡点              │ Flag / 证据命中            │        │
│           ▼                             ▼                           │        │
│      ┌──────────┐                ┌────────────┐                    │        │
│      │Reflector │                │Flag Submit │                    │        │
│      │ 反思器   │                │瞬发提交流程│                    │        │
│      └──────────┘                └────────────┘                    │        │
├──────────────────────────────────────────────────────────────────────────────┤
│  工具执行层                                                                   │
│  Docker Kali / Shell / Python PoC / Recon / Platform / Forum / TestEnv      │
├──────────────────────────────────────────────────────────────────────────────┤
│  记忆与知识层                                                                 │
│  MemoryStore（热路径） → KnowledgeGateway                                    │
│      ├─ main_battle_memory                                                   │
│      ├─ forum_memory                                                         │
│      └─ ctf_writeups_kb（RAG 向量知识库 / 门控外部 WP 参考）                 │
│  KnowledgeService / Milvus / Qdrant / 本地 JSONL fallback / async writeback  │
├──────────────────────────────────────────────────────────────────────────────┤
│  可观察层                                                                      │
│  Rich Console / Web Dashboard / SSE / Final Report                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

注: docker kali是本次的败笔

### 整体架构思路

首先我们用的是`claude code opus4.6`作为主攻手模型，`mini max2.7`作为顾问，后续换成`deepseek-R1`(原因是mini max的网络光炸)

主攻手模型是很强力的，我们认为`cc`在写简单题和部分中等题的时候，是不需要顾问协同的，或者是说害怕顾问提供错误的思路指引。

所以我们在第一开始按照轮次调用，后续改成了使用检测，当主攻手做出错误决策五次\调用工具卡死\超时等后调用顾问，开启一个临时顾问去提醒主攻手。

关于反思器：其实后续反思能力由记忆层和知识库提供

记忆层：我们把每道题的做题思路\简单日志记录到`wp`目录下，因为我们发现题目名是不变的，假设题目为`demo1`，每次可能编号会变，我们针对名字做思路持久化记忆，错误道路记录，正确思路维持，方便调试暂停后继续按照正确道路进行。

关于调度：靶机容器同时只能开三个，我们使用的调度是纯纯vibe出来的，经常会调度后依旧尝试调度导致容器错误关闭的情况出现(所以就有了石山叠石山)。

关于llm：第一开始使用的`LangChain`，第二天内网依旧爆0，我们开始尝试全面替换`claude code sdk`作为框架，从最后结果看来，`sdk`的下限很高，但是上限很低，并且对不同协议的适配度很低，感觉给人的自由度很低。比如我们的顾问依旧是`OpenAI`的协议甚至是`LangChain`写的，在进行调用就会有很大的问题，后续再全面利用`sdk`进行注入顾问作为`subagent`的时候，会有越来越多的bug。所以下次我们应该会去使用`LangChain`或者是我很喜欢的`eino`

知识库：rag知识库，采集了20页`ctftime`的web方向wp，用嵌入式模型进行注入，用来和顾问沟通、调用

论坛：我们主要做了对模型的边界约束，比如不能以任何方式给key，以没有道德的方式去欺骗甚至是恐吓对方agent。我还写了一个看见一个帖子点一个踩的后台功能()

skill：我们主要添加了我们[wgpsec的安全skill](https://github.com/wgpsec/AboutSecurity),还有一个[ctf-skill](https://github.com/ljagiello/ctf-skills)中的webskill，在测试的两天期间内，我们发现了[pua skill](https://github.com/tanweai/pua)，去在论坛里面压力对方给key，hhh

mcp：我们加入了kali-mcp和[sliver-mcp](https://sliver.sh)

## 比赛期间

每天三次调试机会，我们第一开始甚至没有添加内网的skill和工具，在第一天level1&2打进去后，我们很快的开了level3！我们当时是无法想象的，已经超出了我们当时的预期，但是因为调度问题，我们无法第一时间关闭和开启题目，当天的调试次数主要用来改这个和加cve的poc了

我们第二/三天主要在整理cve的poc，并且通过记录agent的提示，拿到了准确的cve编号，直接写入agent里面，我感觉针对比赛内容进行调整，是选手唯数不多能做的了。

比如

```txt
    "K7kbx40FbhQNODZkS": {
        "display": "Layer Breach",
        "official_hint": "线索在一个不起眼的文件里面，把可疑文件 dump 到本地进行分析并且保留。",
        "artifact_dir": "wp/artifacts/Layer_Breach",
        "instructions": (
            "发现可疑文件时，不要只在线 `cat` 一眼就丢；优先把原始文件完整落到本地再分析。",
            "一旦验证 `/cmd.php?c=` 可执行，立刻把它视为已拿到前台 RCE；不要继续在首页/`news.php` 参数上反复做 SQLi、LFI 或大词典扫描。",
            "RCE 后优先完整 dump `/var/www/html/common/db.php`、`/var/www/html/sql/init.sql`、`/entrypoint.sh`、`/var/www/html/cmd.php`、`/var/www/html/s.php`、`/var/www/html/ft.php`、`/var/www/html/ftp2.php` 到本地目录。",
            "优先排查名字普通、扩展名不显眼、体积小、位于边角目录的文件，以及配置、备份、图片、压缩包、数据库、日志、二进制样本。",
            "样本落地后基于同一份本地副本做 `file`、`strings`、`xxd`、`binwalk`、解压、元数据和内容检索分析，避免重复从靶机抓取。",
            "已验证 MySQL 凭据 `webapp:webapp123` 可用；拿到库后优先看 `site_config`、`admins`、`internal_hosts`，先收 `system_secret`、弱口令和内网主机映射。",
            "拿到 `/challenge/flag1.txt`、`/challenge/flag2.txt` 后不要继续磨前台站点；剩余 Flag 在横向移动目标，不在当前外网站点首页。",
        ),
        "verified_chain": (
            "外网站点 -> `/cmd.php?c=` -> `uid=33(www-data)`，已经验证为真实命令执行入口。",
            "RCE 后可直接读取 `/challenge/flag1.txt` 和 `/challenge/flag2.txt`；当前公开入口不是瓶颈。",
            "`common/db.php` 已给出数据库账号 `webapp:webapp123`；`site_config.system_secret` 本身就是 flag 形态字段。",
            "`sql/init.sql` 已给出候选凭据 `admin/1qaz@WSX`、`editor/Admin123`、`zhangwei/zw123456`，以及 `oa-system`、`file-server`、`core-system` 三个内网目标。",
            "运行时还实际探测到 `172.19.0.2:80`、`172.19.0.3:21,22`、`172.19.0.4:8080`、`172.19.0.5:80`；后续应围绕 FTP/OA/core-system 横向。",
        ),
    },
    "p71MyGzdIAR13xvgr8SePV4UZwa6p": {
        "display": "运维集中调度台",
        "official_hint": "这题已经验证可走 1Panel 安全入口 + 默认口令 + 已认证 API 链，不要在没有 PHP 执行面的 webshell 上空转。",
        "instructions": (
            "一旦指纹像 1Panel/Vue SPA，先探 `/api/v1/auth/issafety?code=entrance` 并看前端 JS；不要先手搓通用爆破或继续盲打 SQLi。",
            "当前题已验证安全入口码就是 `entrance`，请求头 `EntranceCode` 直接使用其 base64：`ZW50cmFuY2U=`。",
            "登录 JSON 必须带 `authMethod=session` 与 `language=zh`；默认口令 `1panel/1panel_password` 配合 captcha OCR 已验证可登录。",
            "如果 `CVE-2024-39907` 的 `ATTACH DATABASE` 能落文件，但 `.php` 只回 `SQLite format 3`、源码或 decoy 页面，立即切到 `1panel-postauth`，不要继续雕刻 webshell。",
            "已认证后优先 `cronjobs` + `files/content`；本题 `/challenge/flag.txt` 已验证可直接读取。",
        ),
        "verified_chain": (
            "1Panel 指纹 -> `/api/v1/auth/issafety?code=entrance` -> 确认存在安全入口机制。",
            "前端 JS 已暴露安全入口头部语义：`EntranceCode` 头取入口码的 base64，当前值为 `ZW50cmFuY2U=`。",
            "`1panel/1panel_password` + captcha OCR + `authMethod=session` + `language=zh` + `EntranceCode` 已验证可拿到后台会话。",
            "后台 API 已验证可用：先用 `/api/v1/cronjobs` 定位旗子，再用 `/api/v1/files/content` 直接读取 `/challenge/flag.txt`。",
        ),
    },
```

所以这也就要求我们有更好的日志系统，我们日志差不多优化了三版，最终是sdk行为和主攻手思路全部记录+hint记录，网关什么的统一写好，让主战场和论坛都走同一个网关限流，防止爆炸

第三天晚我们内网打出来了4个flag，并且彻底更换为sdk框架，给llm更大的自由和权限。第四天sdk主攻手+顾问的调用还是崩溃了，我们空跑了一天，同时因为没有顾问的指引，主攻手一天烧了三百多RMB，我们紧急修复了三次依旧不行，好消息的level2全部a了。

第四天的凌晨队友修bug修到心态崩溃，凌晨两天说修不好了，我第五天早上看见天都塌了，当时demo都不会写了，调度也有问题，紧急修改了一早上。

其中主要的改变是让顾问不在走sdk+env的管理策略。

> sdk在没有过度配置的情况下，优先走clude code cli的变量

subagent最初的策略是`env写好->python脚本协议转换->强行注入到sdk->传到入subagent调用`，我们的石山代码终究是崩溃了，我改成了`env->!sdk`，我直接`env->LangChain处理->OpenAI协议`，然后让他进行轮次处理，每五轮和主攻手卡住的情况下主动调用，并且写了`120s`超时，防止主攻手一直待机不动

level4我们最初没有搭上便车，我们甚至当时的策略是，浅兮写一个监测脚本，只要有人提交成功了，我们立马跟车，等了1h没人成功打穿，那就自己打吧

主要是增加了提示词让他知道大概思路是`CVE-2025-3248->内网进行逃逸->Impacket工具链->adcs提权&横向`

并且再不断的优化中，我们发现很长的提示词，大部分是负面作用，不仅会撑爆上下文，还会束缚llm本体，更需要注意的是，如果你用codex进行vibe，他甚至会自己加上不要反弹shell什么的约束

## 赛后复盘

赛后当晚，和一些师傅进行了交流，大家的框架都很类似，`主攻手+顾问`是一个共识性行为，不同的是容器调度，agent做题模式，比如我们的三并发是一个agent行为，对方可能是3agent写3题，一一对应，这种会减少agent的性能压力，也能最大的释放llm能力。

关于知识库，我们都在思考知识库是副作用还是正反馈，rag在数据很小的情况下是否能起到关键性作用，在没有特殊算法的优化下，检索效率是否能跟得上这种`衰减分数`机制的赛场，亦或是后续换成`LLM wiki`，这些都是后话了。

同时，我们也都认为，`claude code sdk`是一个上限很低下限很高的东西，对于A社自己的适配性很高，但是对于其他的只能笑一笑了，后续不可能再选择他了，而且这玩意耗token真的好快(吐槽ing)

## 最后

其实第十七名的成绩已经是出乎意料了，我们在开赛前一天，还在想能不能进前五十写个简历什么的，hhh，现在想起来确实有点搞了，几个门外汉，没有一点开发agent基础和llm理论知识，硬生生往前挤了挤。

这也许就是AI时代的好处，给了每个有想法的人公平的机会？也许我对vibe的看法确实该改观一下了()

也许是第一天名次太高，让我们稍微有一点点不应该存在的遗憾吧。希望下次可以更好，也希望下次可以带来不是石山的代码。

希望可以和专业的师傅们多多交流吧。
