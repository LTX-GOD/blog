---
title: 在nvim中配置java环境
published: 2026-07-01
description: zsm java nvim
pinned: false
tags: ["java"]
author: zsm
category: 环境配置
draft: false
lang: 'zh_CN'
---

## 在 Neovim 里搭一套能用的 Java / Spring Boot 开发环境

> 目标：不用 IDEA，也能在 Neovim 里补全、跳转、调试、跑 Spring Boot、单独跑测试。
> 全部基于 Neovim 原生 `vim.pack` 做插件管理，jdtls 用 Homebrew 装（绕开被墙的 Eclipse 下载源）。

本文把我踩过的坑和最终配置一次讲清楚，涉及的插件：

- `mfussenegger/nvim-jdtls` —— Java 语言服务器（LSP）
- `mfussenegger/nvim-dap` + `rcarriga/nvim-dap-ui` —— 调试
- Mason 安装的 `java-debug-adapter`、`java-test` 两个 bundle
- `lemminx` —— XML/pom.xml 的 LSP
- 一个自写的 `after/ftplugin/xml.lua` 给 pom.xml 加「跳转到依赖源」

---

## 0. 整体思路

Java 生态和别的语言不太一样，几个关键点先说明白：

1. **jdtls 不是普通 LSP**，它需要一个「工作区（workspace）」目录来缓存每个项目的索引，所以不能直接用 `lspconfig` 起，得用 `nvim-jdtls` 专门管理，且每个项目一个 workspace。
2. **调试 / 测试不是 jdtls 自带的**，要额外把两个 jar bundle（java-debug-adapter、java-test）塞进 jdtls 的 `init_options.bundles`，jdtls 才会暴露「找主类」「跑测试」这些能力。
3. **jdtls 只在启动时读一次 bundles**。所以你新装了 java-test 之后，必须 `:LspRestart` 或者重开 Neovim，不然报 "No LSP client found that supports resolving possible test cases"。

---

## 1. 安装 jdtls（重点：用 brew，别用 Mason 下载）

Mason 装 jdtls 会去 Eclipse 官方源拉包，国内经常拉不动。直接用 Homebrew：

```bash
brew install jdtls
```

装完路径在 `/opt/homebrew/opt/jdtls/libexec`，配置里直接指向它。

其余几个组件用 Mason 装（这些托管在 GitHub/开源源，通常没问题）：

```lua
-- lua/custom/plugins/lsp.lua
{
  'WhoIsSethDaniel/mason-tool-installer.nvim',
  opts = {
    ensure_installed = { 'google-java-format', 'java-debug-adapter', 'java-test' },
  },
},
```

- `google-java-format` —— 格式化
- `java-debug-adapter` —— 调试（DAP）
- `java-test` —— 单测运行/调试

XML 的 LSP `lemminx` 交给 mason-lspconfig：

```lua
require('mason-lspconfig').setup {
  ensure_installed = { ..., 'lemminx' },
  handlers = {
    function(server_name) ... end,
    -- jdtls 由 nvim-jdtls 单独管理，这里跳过自动 setup
    ['jdtls'] = function() end,
  },
}
```

> ⚠️ 注意最后这行 `['jdtls'] = function() end`：mason-lspconfig 默认会帮你 setup 所有装了的 LSP，但 jdtls 我们要用 nvim-jdtls 手动起，所以必须把它的默认 handler 置空，否则会起两个冲突的 jdtls。

---

## 2. nvim-jdtls 主配置

核心文件 `lua/custom/plugins/jdtls.lua`。挑重点讲。

### 2.1 启动命令与 workspace

```lua
local jdtls_path = '/opt/homebrew/opt/jdtls/libexec'
local launcher = vim.fn.glob(jdtls_path .. '/plugins/org.eclipse.equinox.launcher_*.jar')
local os_cfg = vim.fn.has('mac') == 1 and 'config_mac'
  or vim.fn.has('win32') == 1 and 'config_win'
  or 'config_linux'

-- 每个项目一个独立 workspace，用项目目录名区分
local project_name = vim.fn.fnamemodify(vim.fn.getcwd(), ':p:h:t')
local workspace = vim.fn.stdpath('data') .. '/jdtls-workspace/' .. project_name
```

**为什么每个项目单独 workspace**：workspace 里存的是这个项目的 Maven 依赖索引、编译产物、符号表。多个项目共用一个 workspace 会互相污染索引，出现跳转跳错、幽灵报错。

### 2.2 加载 bundles（调试 + 测试能力的来源）

```lua
local mason_pkg = vim.fn.stdpath('data') .. '/mason/packages'

-- 调试 adapter
local bundles = vim.split(
  vim.fn.glob(mason_pkg .. '/java-debug-adapter/extension/server/com.microsoft.java.debug.plugin-*.jar', true),
  '\n', { trimempty = true })

-- java-test：让 jdtls 支持跑单个测试方法 / 测试类
vim.list_extend(bundles, vim.split(
  vim.fn.glob(mason_pkg .. '/java-test/extension/server/*.jar', true),
  '\n', { trimempty = true }))

-- ...
init_options = { bundles = bundles },
```

这一步是「能不能调试 / 能不能跑测试」的开关。少了对应的 jar，jdtls 就不认那些命令。

### 2.3 用 FileType 事件启动

jdtls 只对 Java buffer 有意义，用 `ft = 'java'` 懒加载 + FileType autocmd 启动：

```lua
vim.api.nvim_create_autocmd('FileType', {
  pattern = 'java',
  callback = start_jdtls,
})

-- config 是被第一个 java buffer 的 FileType 触发的，此时事件已经过去了，
-- 所以要对「当前这个 buffer」再手动调一次
if vim.bo.filetype == 'java' then
  start_jdtls()
end
```

> 这个「补一刀」很容易漏。插件的 `config` 本身就是被 FileType 触发的，等你注册 autocmd 时，当前 buffer 的 FileType 事件早就结束了，不手动调一次，第一个打开的 Java 文件不会起 jdtls。

---

## 3. 调试配置（DAP）—— 这里坑最多

### 3.1 dap.lua 基础

```lua
-- lua/custom/plugins/dap.lua
{
  'rcarriga/nvim-dap-ui',
  dependencies = { 'mfussenegger/nvim-dap', 'nvim-neotest/nvim-nio' },
  keys = {
    { '<leader>du', function() require('dapui').toggle() end, desc = 'DAP: Toggle UI' },
  },
  config = function()
    local dap, dapui = require('dap'), require('dapui')
    dapui.setup()
    -- 调试/测试开始时自动打开 UI
    dap.listeners.after.event_initialized['dapui'] = dapui.open
    -- 不在结束时自动关闭，保留结果供查看；看完用 <leader>du 手动关闭
  end,
}
```

> **坑 A：测试跑完 UI 自动关掉，看不到结果。**
> 很多教程里会写这两行：
> ```lua
> dap.listeners.before.event_terminated['dapui'] = dapui.close
> dap.listeners.before.event_exited['dapui'] = dapui.close
> ```
> 它们会在调试/测试一结束就把结果面板关掉。我把这两行删了，改成手动 `<leader>du` 关，结果和输出就能留着慢慢看。

### 3.2 在 jdtls 的 on_attach 里接上调试

```lua
on_attach = function(_, bufnr)
  -- nvim-dap / dap-ui 是懒加载的，这里强制加载，否则 setup_dap 会静默失败
  require('custom.pack').load('nvim-dap')
  require('custom.pack').load('nvim-dap-ui')
  require('jdtls').setup_dap { hotcodereplace = 'auto' }
  -- ...
end
```

> **坑 B（我卡了最久的一个）：报 "No configuration found for `java`" / "module 'dap' not found"，F5 死活起不来调试。**
>
> 根本原因：nvim-dap 是**懒加载**的，只有按了 `<F5>` 之类的 keys 才会被拉起来。但我在 Java buffer 里又用 `map('<F5>', ...)` 覆盖了那个懒加载触发键——于是 dap 永远不会被加载。而 `nvim-jdtls` 的 `setup_dap` 内部用 `pcall(require, 'dap')` 保护，dap 没加载它就**静默什么都不做**，不报错，最难查。
>
> 解法：在 on_attach 一开始就**手动强制加载** dap 和 dap-ui（我这套用的是自写 pack 管理器的 `require('custom.pack').load(name)`，换成 lazy.nvim 就是 `require('lazy').load({ plugins = { 'nvim-dap' } })`）。加载完再 `setup_dap`，这样 dap-ui 的自动开关监听器也才存在。

### 3.3 主类发现要等 jdtls 导入完项目

`setup_dap_main_class_configs()` 是**异步**的，它得等 jdtls 把 Maven 依赖导入完、类编译完，才能扫出带 `main` 方法的类。刚打开项目就按 F5，大概率「找不到主类」。

我写了一个带反馈 + 重试的封装：

```lua
local function refresh_and_debug(attempt)
  attempt = attempt or 1
  require('jdtls.dap').setup_dap_main_class_configs {
    verbose = true,
    on_ready = function()
      local configs = require('dap').configurations.java or {}
      if #configs > 0 then
        vim.notify('找到 ' .. #configs .. ' 个主类，启动调试', vim.log.levels.INFO)
        require('dap').continue()
      elseif attempt < 5 then
        vim.notify('jdtls 仍在导入项目，重试 ' .. attempt .. '/5…', vim.log.levels.WARN)
        vim.defer_fn(function() refresh_and_debug(attempt + 1) end, 2000)
      else
        vim.notify('未发现主类。确认：1) 类有 main 方法 2) 已 mvn compile 3) jdtls 完成项目导入', vim.log.levels.ERROR)
      end
    end,
  }
end

-- 启动 3 秒后先自动扫一次主类
vim.defer_fn(function() require('jdtls.dap').setup_dap_main_class_configs() end, 3000)

-- Java buffer 内的 F5：有配置就直接 continue，没有就走刷新逻辑
map('<F5>', function()
  local configs = require('dap').configurations.java or {}
  if #configs > 0 then require('dap').continue() else refresh_and_debug() end
end, 'DAP: Continue (Java)')

map('<leader>dJ', function() refresh_and_debug() end, 'Java: 刷新主类并启动调试')
```

---

## 4. 跑 Spring Boot / 跑测试

### 4.1 一键跑 Spring Boot

自动识别用 `mvnw` / `gradlew` / `mvn` / `gradle`，在 snacks 的浮动终端里跑：

```lua
map('<leader>jr', function()
  local root = vim.fs.root(0, { 'mvnw', 'gradlew', 'pom.xml', 'build.gradle' })
  if not root then vim.notify('未找到 Spring Boot 项目根目录', vim.log.levels.ERROR); return end
  local cmd
  if vim.uv.fs_stat(root .. '/mvnw') then cmd = 'chmod +x mvnw && ./mvnw spring-boot:run'
  elseif vim.uv.fs_stat(root .. '/gradlew') then cmd = 'chmod +x gradlew && ./gradlew bootRun'
  elseif vim.uv.fs_stat(root .. '/pom.xml') then cmd = 'mvn spring-boot:run'
  else cmd = 'gradle bootRun' end
  require('snacks').terminal(cmd, { cwd = root })
end, 'Java: 运行 Spring Boot')
```

优先用项目自带的 `mvnw`/`gradlew`（wrapper），版本更可控。

### 4.2 单独跑一个测试方法 / 测试类

这就是 java-test bundle 的价值所在：

```lua
-- 光标停在某个 @Test 方法里，跑这一个方法
map('<leader>jt', function() require('jdtls').test_nearest_method() end, 'Java: 测试光标处方法')
-- 跑当前文件的整个测试类
map('<leader>jT', function() require('jdtls').test_class() end, 'Java: 测试当前类')
```

结果会进 dap-ui 的 console 面板；失败的用例还会进 quickfix，`:copen` 看，`]q` / `[q` 跳。

> 记住第 0 节说的：装完 java-test 一定要 `:LspRestart` 或重开 Neovim，jdtls 才会加载这个 bundle。

---

## 5. 给 pom.xml 加「跳转到依赖源」

`lemminx` 只懂 XML 语法，不懂 Maven 语义——所以在 pom.xml 里对着 `<dependency>` 按 `gd` 是没反应的。我写了个 ftplugin 补上这个能力：光标停在 `<dependency>` / `<parent>` / `<plugin>` 块里按 `gd`，就去 `~/.m2/repository` 找到对应的 `.pom` 打开。

```lua
-- after/ftplugin/xml.lua（节选）
local fname = vim.fn.expand('%:t')
if fname ~= 'pom.xml' and not fname:match('%.pom$') then return end
-- 注意：.pom 文件本身（从 .m2 打开的）也要能继续跳，所以条件里带上 %.pom$
```

实现要点：

- 解析当前 XML 块的 `groupId` / `artifactId` / `version`，拼出 `~/.m2/repository/<group 路径>/<artifact>/<version>/<artifact>-<version>.pom`。
- `<leader>jP` 专门跳到 `<parent>` POM。
- 局限：解析不了 `${xxx}` 版本变量（值在 properties 或 parent 里），这种就跳不了；本地 `.m2` 没缓存的会提示先 `mvn dependency:resolve`。

> **坑 C**：一开始条件写成只匹配 `pom.xml`，导致从 `.m2` 跳进去的 `xxx-1.0.pom` 文件里没法继续往上跳。加上 `%.pom$` 匹配后，依赖链能一层层点进去。

---

## 6. 快捷键速查

| 快捷键 | 作用 | 生效范围 |
| --- | --- | --- |
| `<F5>` | 继续 / 启动调试（Java 内会自动找主类） | Java |
| `<F10>` / `<F11>` / `<F12>` | 单步跳过 / 进入 / 跳出 | 调试中 |
| `<leader>db` / `<leader>dB` | 断点 / 条件断点 | 全局 |
| `<leader>dr` / `<leader>dq` | 重启 / 终止调试 | 全局 |
| `<leader>du` | 开关 DAP UI（看完结果手动关） | 全局 |
| `<leader>dJ` | 刷新主类并启动调试 | Java |
| `<leader>jr` | 一键跑 Spring Boot | Java |
| `<leader>jt` / `<leader>jT` | 跑光标处测试方法 / 整个测试类 | Java |
| `gd` | pom.xml 里跳转到依赖 POM | pom.xml / *.pom |
| `<leader>jP` | 跳转到 parent POM | pom.xml / *.pom |

---

## 7. 常见报错对照表

| 报错 | 原因 | 解决 |
| --- | --- | --- |
| `No configuration found for java` | dap 没加载 / 主类还没扫出来 | 在 on_attach 强制 load dap；用 `<leader>dJ` 等 jdtls 导入完再试 |
| `module 'dap' not found` | 懒加载的 dap 被自定义键覆盖了触发，永远没被加载 | on_attach 里手动 `load('nvim-dap')` |
| `No LSP client found that supports resolving possible test cases` | java-test bundle 没装或没加载 | `:MasonInstall java-test` 后 `:LspRestart` |
| pom.xml 里 `gd` 无反应 / `No results found for lsp_definitions` | lemminx 不懂 Maven 语义 | 用自写 ftplugin 的 gd |
| Spring Boot 启动报 `Failed to determine a suitable driver class` | 引了 data-jpa 但没配数据库 | 加数据库依赖（快速测试可用 H2）或配 datasource |
| 编译报 `The type List is not generic` | import 错成了 `java.awt.List` | 改成 `java.util.List` |
| 保存 Java 就 `[100%] Building` | jdtls 保存时增量编译，正常现象 | 无需处理 |

---

## 小结

Java 在 Neovim 里能跑起来的关键就三件事：

1. **jdtls 用 brew 装**，每项目独立 workspace，且用 nvim-jdtls 手动起（记得禁掉 mason-lspconfig 的默认 handler）。
2. **调试/测试靠 bundle**，java-debug-adapter + java-test 塞进 `init_options.bundles`，装完必须重启 jdtls。
3. **懒加载要小心**：dap 得在 on_attach 里手动强制加载，否则 `setup_dap` 静默失效——这是最隐蔽的一个坑。

剩下的都是体验优化：一键跑 Spring Boot、单测、pom 跳转、结果面板别自动关。全部配置在我的 dotfiles 里，欢迎参考。

