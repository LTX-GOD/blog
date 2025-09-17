---
title: Terminal Configuration「2」
published: 2025-09-16
pubDate: 2025-09-16
description: ''
pinned: false
tags: ['shell','mac']
author: zsm
category: 环境配置
draft: false 
licenseName: "MIT"
lang: 'zh_CN'
---

## 前言

配置无止境，越配越着魔？

## 关于配置的一些想法

在我眼里配置shell、编辑器等等并不是为了追求极致的个性化or与众不同  

我的思想里首先要达到应该目标：好用且不会产生过多的性能损耗。

## 浏览器Zen

这个浏览器在mac上真的好用，内核是火狐的，ui非常的特殊，并且可以自己加入主题什么的  

目前来说生态还是不错的，隔壁的arc已经不维护更新了，所以这里换成了zen  

不过还有一些小问题，比如性能开销有一点点问题，这里`btop`进行管理如何关闭。

## Neovim

前一篇其实写了，但是`AstroNvim`我发现有些不适合我，部分插件和快捷键并不喜欢，索性抄了一下别人的配置，然后进行整理。

插件列表

```md
### 🎨 主题和界面
- **catppuccin/nvim** - Catppuccin Mocha 主题，支持透明背景
- **rebelot/heirline.nvim** - 状态栏和标签栏配置
- **echasnovski/mini.nvim** - 多功能插件集合（文件管理、图标、AI等）
- **NvChad/nvim-colorizer.lua** - 颜色代码高亮显示

### 📝 编辑增强
- **hrsh7th/nvim-cmp** - 自动补全引擎
  - hrsh7th/cmp-buffer - 缓冲区补全
  - hrsh7th/cmp-path - 路径补全
  - hrsh7th/cmp-nvim-lsp - LSP补全
  - hrsh7th/cmp-emoji - Emoji补全（Markdown专用）
  - L3MON4D3/LuaSnip - 代码片段引擎
  - saadparwaiz1/cmp_luasnip - Snippet补全源
- **altermo/ultimate-autopair.nvim** - 智能括号配对
- **numToStr/Comment.nvim** - 快速注释
- **folke/flash.nvim** - 快速跳转导航
- **jake-stewart/multicursor.nvim** - 多光标编辑
- **tpope/vim-sleuth** - 自动检测缩进

### 🔧 LSP 和开发工具
- **williamboman/mason.nvim** - LSP/DAP/Formatter 管理器
- **williamboman/mason-lspconfig.nvim** - Mason与LSP配置桥接
- **neovim/nvim-lspconfig** - LSP客户端配置
- **nvimdev/lspsaga.nvim** - LSP UI增强
- **stevearc/conform.nvim** - 代码格式化
- **folke/lazydev.nvim** - Lua开发增强

### 🐛 调试工具
- **mfussenegger/nvim-dap** - 调试适配器协议
- **rcarriga/nvim-dap-ui** - 调试界面
- **theHamsta/nvim-dap-virtual-text** - 调试虚拟文本

### 📁 文件管理
- **stevearc/oil.nvim** - 文件浏览器
- **mikavilpas/yazi.nvim** - Yazi文件管理器集成

### 🌳 语法高亮
- **nvim-treesitter/nvim-treesitter** - 语法高亮和解析

### 🔍 搜索和导航
- **folke/snacks.nvim** - 现代化的picker和通知系统
- **folke/which-key.nvim** - 快捷键提示

### 📋 终端和任务
- **akinsho/toggleterm.nvim** - 终端管理
- **stevearc/overseer.nvim** - 任务运行器

### 🔄 Git 集成
- **lewis6991/gitsigns.nvim** - Git状态显示
- **sindrets/diffview.nvim** - Git差异查看

### 📝 文档和标记
- **MeanderingProgrammer/render-markdown.nvim** - Markdown渲染
- **bullets-vim/bullets.vim** - Markdown列表增强
- **folke/todo-comments.nvim** - TODO注释高亮

### 🔤 语言特定支持
- **iabdelkareem/csharp.nvim** - C#开发支持
- **lervag/vimtex** - LaTeX支持
- **let-def/texpresso.vim** - TeX实时预览
- **kaarmu/typst.vim** - Typst文档支持
- **fladson/vim-kitty** - Kitty配置文件支持


### 🔕 界面增强（已禁用）
- **folke/noice.nvim** - 现代化UI（当前已禁用）
- **kylechui/nvim-surround** - 环绕操作（当前已禁用）

### 📦 支持的LSP服务器
根据Mason配置，自动安装以下LSP服务器：
- **gopls** - Go语言
- **lua_ls** - Lua语言
- **pyright** - Python语言
- **omnisharp** - C#语言
- **rust_analyzer** - Rust语言
- **marksman** - Markdown语言

```

## Blog

hugo退役了xdm，这里换成了`Astro`。  

好处是更加好看且现代了，这个风格我更喜欢，并且以前用的hugo和对应主题有些版本问题，我并不想花时间去修改了，索性整个换了。

目前主题用的是[mizuki](https://github.com/matsuzaka-yuki/mizuki)，一个还在开发中的主题，我目前修改了一部分内容，可能看不出来？后面我会对一些我不喜欢的结构进行更新(咕咕咕)。

整体配置还是比较简单的，关于build缓慢这个事，是因为`Astro`底层的页面优化导致的，目前想法是可以在vps里面`pnpm dev &`，变成一个伪动态Blog


