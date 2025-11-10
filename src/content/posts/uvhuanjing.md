---
title: 关于uv配置python及工具
published: 2025-11-09
pubDate: 2025-11-09
description: uv配置python环境
pinned: false
tags: ["shell", "mac"]
author: zsm
category: 环境配置
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

这里先介绍一下`uv`，他是一个`rust`开发的`python`包和项目管理工具，优点就是快！功能齐全！

那么下面就开始配置环节吧

## 配置

### 安装 uv

mac or linux

> curl -LsSf https://astral.sh/uv/install.sh | sh

windows

> powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

brew

> brew install uv

自动补全

> echo 'eval "$(uv generate-shell-completion zsh)"' >> ~/.zshrc

### 常用基础命令

更新

> uv self update

查看可用 python 版本

> uv python list

安装 python

> uv python install

卸载 python

> uv python uninstall

运行脚本

> uv run

为项目/脚本添加依赖

> uv add #例如你需要 gmpy2 这个包，就要添加进去

创建新的 python 项目

> uv init

同步项目依赖到环境

> uv sync

这里的同步主要依赖于`pyproject.toml` `uv.lock` `.venv`

添加锁文件

> uv lock

查看依赖树

> uv tree

构建项目

> uv build

发布项目到包索引

> uv publish

创建虚拟环境

> uv venv

pip 接口

> uv pip install
> uv pip list
> uv pip uninstall
> uv pip tree

### 日常使用

假设我目前在一个 0 配置的环境下，我先下载 uv

> brew install uv

然后我是不是需要下载一个 python

```bash
uv python list
cpython-3.15.0a1-macos-aarch64-none                 <download available>
cpython-3.15.0a1+freethreaded-macos-aarch64-none    <download available>
cpython-3.14.0-macos-aarch64-none                   <download available>
cpython-3.14.0+freethreaded-macos-aarch64-none      <download available>
cpython-3.13.9-macos-aarch64-none                   <download available>
cpython-3.13.9+freethreaded-macos-aarch64-none      <download available>
cpython-3.13.7-macos-aarch64-none                   /opt/homebrew/bin/python3.13 -> ../Cellar/python@3.13/3.13.7/bin/python3.13
cpython-3.13.7-macos-aarch64-none                   /opt/homebrew/bin/python3 -> ../Cellar/python@3.13/3.13.7/bin/python3
cpython-3.13.7-macos-aarch64-none                   .local/bin/python3.13 -> .local/share/uv/python/cpython-3.13.7-macos-aarch64-none/bin/python3.13
cpython-3.13.7-macos-aarch64-none                   .local/bin/python -> python3.13
cpython-3.13.7-macos-aarch64-none                   .local/share/uv/python/cpython-3.13.7-macos-aarch64-none/bin/python3.13
cpython-3.12.12-macos-aarch64-none                  <download available>
cpython-3.11.14-macos-aarch64-none                  <download available>
cpython-3.11.13-macos-aarch64-none                  .local/share/uv/python/cpython-3.11.13-macos-aarch64-none/bin/python3.11
cpython-3.10.19-macos-aarch64-none                  <download available>
cpython-3.9.24-macos-aarch64-none                   <download available>
cpython-3.9.6-macos-aarch64-none                    /usr/bin/python3
cpython-3.8.20-macos-aarch64-none                   <download available>
pypy-3.11.13-macos-aarch64-none                     <download available>
pypy-3.10.16-macos-aarch64-none                     <download available>
pypy-3.9.19-macos-aarch64-none                      <download available>
pypy-3.8.16-macos-aarch64-none                      <download available>
graalpy-3.12.0-macos-aarch64-none                   <download available>
graalpy-3.11.0-macos-aarch64-none                   <download available>
graalpy-3.10.0-macos-aarch64-none                   <download available>
graalpy-3.8.5-macos-aarch64-none                    <download available>
```

这里先列出可用的版本，如何下载一个

```bash
uv python install cpython-3.13.7-macos-aarch64-none
```

这里下载之后，我想让全局都吃这个 python 环境，这样一些不用外包的脚本可以快速运行，那就

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
uv python pin 3.13.7
python --version
```

这样就可以了。如果你的项目需要利用其他的 python 版本，直接下载一个就好了，比如我这里就下载了 3.13 和 3.11

那我如何快速搭建一个项目环境呢？

这里推荐直接用 uv 创建

```bash
uv init hello-world
cd hello-world
```

uv 创建的文件是

```
.
├── .python-version
├── README.md
├── main.py
└── pyproject.toml
```

main 文件相当于一个测试文件，可以先运行测试一下

> uv run main.py

注意这个时候是没有 venv 的，需要自己同步一下

```bash
uv sync

ls -la
total 20
drwxr-xr-x 10 zsm staff 320 Nov  9 21:19 .
drwxr-xr-x 10 zsm staff 320 Nov  9 21:17 ..
drwxr-xr-x  9 zsm staff 288 Nov  9 21:17 .git
-rw-r--r--  1 zsm staff 109 Nov  9 21:17 .gitignore
-rw-r--r--  1 zsm staff   5 Nov  9 21:17 .python-version
drwxr-xr-x  8 zsm staff 256 Nov  9 21:19 .venv
-rw-r--r--  1 zsm staff  89 Nov  9 21:17 main.py
-rw-r--r--  1 zsm staff 157 Nov  9 21:17 pyproject.toml
-rw-r--r--  1 zsm staff   0 Nov  9 21:17 README.md
-rw-r--r--  1 zsm staff 131 Nov  9 21:19 uv.lock
```

那么`pyproject.toml`是干什么的呢？

```bash
cat pyproject.toml
[project]
name = "hello-world"
version = "0.1.0"
description = "Add your description here"
readme = "README.md"
requires-python = ">=3.13"
dependencies = []
```

你可以轻松的看懂，有项目名字，版本号，描述，python 版本，还有依赖

比如

```bash
uv add gmpy2

cat pyproject.toml
[project]
name = "hello-world"
version = "0.1.0"
description = "Add your description here"
readme = "README.md"
requires-python = ">=3.13"
dependencies = [
    "gmpy2>=2.2.1",
]
```

是不是很像`requirements.txt`，在我的理解里，这个就是他的升级版，那我以前写好了这个，该怎么快速迁移呢？

> uv add -r requirements.txt -c constraints.txt

输入这个就可以了

那我写好了，直接构建这个项目就行，并且会存到`dist`目录下

```bash
uv build

ls ./dist
hello-world-0.1.0-py3-none-any.whl
hello-world-0.1.0.tar.gz
```

那么`uv.lock`文件是什么呢？是一个通用或跨平台的锁定文件，它记录了在所有可能的 Python 标识（如操作系统、架构和 Python 版本）下要安装的软件包。

这个文件不要自己修改，是 uv 专属的调用文件，快速同步环境可以

## 快速使用项目

当你从`github`上 clone 了一个 python 项目，我们该如何快速使用他呢？这里拿一些举例

### dirsearch

```bash
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
```

这里直接创建一个虚拟环境

> uv venv .venv

看他的文件结构

```bash
ls
__init__.py  CHANGELOG.md  config.ini  CONTRIBUTORS.md  db  dirsearch.py  Dockerfile  lib  options.ini  README.md  requirements.txt  setup.cfg  setup.py  static  testing.py  tests
```

可以发现他是`requirements.txt`管理项目依赖版本的，并且有`setup.py`文件，他类似于上面提到的`pyproject.toml`文件，包括包版本管理、源代码路径、控制台命令等信息，那么我们可以直接依赖他去构建

> uv pip install -e .

非常的方便，但是这个工具构建完我们只能在这个环境使用，我在其他的地方调用终究是麻烦的，这里就可以去修改`.zshrc`文件了

比如我就在里面写了快捷方式

```
# dirsearch
dirsearch() {
  uv run ~/CTF/tool/uv-web/dirsearch/.venv/bin/python3 ~/CTF/tool/uv-web/dirsearch/dirsearch.py "$@"
}
```

当然了，因为构建出来之后依旧要运行 py 文件，所以这样写，这里就举一个不同的例子

### ghauri

这个工具是 sqlmap 改良版本，看看文件结构

> ghauri ghauri.egg-info LICENSE README.md requirements.txt setup.py

是有`setup.py`的，我们就可以直接配置环境，但是没有运行文件，阅读他的代码发现是直接生成到了这个环境的 bin 下面，那我们写快捷方式就要改动一下了

```
# ghauri
ghauri() {
  uv run ~/CTF/tool/uv-web/ghauri/.venv/bin/ghauri "$@"
}
```

### PyGlimmer

一个 python 逆向的小工具，他的文件结构是

> Decompiler Decryptor Disasm example image LICENSE Pyarmor_Unpack PyGlimmer.py PyInstExtractor README.md requirements.txt stegosaurus

只有`requirements.txt`这个东西，我们直接 add 进去就行了

> uv add -r requirements.txt

## neovim 联动

作为一个 nvim 用户，这里推荐一个插件`uv.nvim`，可以直接自动吃当前项目 uv 的虚拟环境

```lua
return {
  "benomahony/uv.nvim",
  -- 仅在打开Python文件时懒加载
  ft = { "python" },
  -- 可选依赖，推荐使用
  dependencies = {
    "folke/snacks.nvim"
  },
  opts = {
    -- 自动激活虚拟环境
    auto_activate_venv = true,
    notify_activate_venv = true,

    -- 目录变化时的自动命令
    auto_commands = true,

    -- 与snacks picker的集成
    picker_integration = true,

    -- 快捷键配置
    keymaps = {
      prefix = "<leader>u",  -- 主前缀改为<leader>u以避免冲突
      commands = true,       -- 显示uv命令菜单 (<leader>u)
      run_file = true,       -- 运行当前文件 (<leader>ur)
      run_selection = true,  -- 运行选中代码 (<leader>us)
      run_function = true,   -- 运行函数 (<leader>uf)
      venv = true,           -- 环境管理 (<leader>ue)
      init = true,           -- 初始化uv项目 (<leader>ui)
      add = true,            -- 添加包 (<leader>ua)
      remove = true,         -- 移除包 (<leader>ud)
      sync = true,           -- 同步包 (<leader>uc)
    },

    -- 执行配置
    execution = {
      run_command = "uv run python",  -- 使用uv run python执行
    }
  },
  config = function(_, opts)
    require('uv').setup(opts)

    -- 添加一些自定义命令
    vim.api.nvim_create_user_command('UVStatus', function()
      vim.cmd('!uv --version')
    end, { desc = '显示uv版本信息' })

    vim.api.nvim_create_user_command('UVInfo', function()
      vim.cmd('!uv info')
    end, { desc = '显示uv项目信息' })
  end
}
```

## 总结

以上都是 uv 的入门级别使用方法，还有很多花里胡哨的技巧，这里本人感觉没什么必要，目前没有使用到，所以就不写了，可以去看官方文档，有详细的介绍。

总体上 uv 绝对是一个值得一试的 python 管理工具。
