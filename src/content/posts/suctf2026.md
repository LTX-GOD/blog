---
title: suctf2026
published: 2026-03-16
pubDate: 2026-03-16
description: Bluebud wp zsm
pinned: false
tags: ["Bluebud-xctf"]
author: zsm
category: Bluebud
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

周六一天软件安全，刚刚好撞了一天，第二天看看题，打着打着头晕xd，年纪大了真不行了，排名才35

wp就写几个密码和一个osint吧

## 题目

### SU_Lattice

- 赛题附件下载后，得到一个可执行程序chall，执行时出现报错信息Failed to open file...，针对于这是一道Crypto的赛题，将其放在IDA里分析一下底层逻辑发现其之所以直接运行错误是当前文件夹下其没有找到data文件，关于data文件的读取操作在IDA中的代码呈现为：

```
__int64 sub_401D1D()
{
  int v0; // er8
  int v1; // er9
  __int64 result; // rax
  int v3; // er8
  int v4; // er9
  int i; // [rsp+0h] [rbp-10h]
  int j; // [rsp+4h] [rbp-Ch]
  __int64 v7; // [rsp+8h] [rbp-8h]

  v7 = sub_41A910("./data", "r");
  if ( !v7 )
  {
    sub_41AD00("Failed to open file...");
    sub_40B390(1LL);
  }
  result = sub_40C120(v7, (unsigned int)"%lld", (unsigned int)&qword_4E83A0, (unsigned int)"%lld", v0, v1);
  for ( i = 0; i <= 23; ++i )
    result = sub_40C120(v7, (unsigned int)"%lld", (unsigned int)&qword_4E8220[i], (unsigned int)"%lld", v3, v4);
  for ( j = 0; j <= 23; ++j )
    result = sub_40C120(v7, (unsigned int)"%lld", (unsigned int)&qword_4E82E0[j], (unsigned int)"%lld", v3, v4);
  return result;
}
```

- 其中data文件中包含以下数据：

1. 1个long long:m
2. 24个long long:A[0..23]
3. 24个long long:X[0..23]

- 在进入菜单之前，程序会计算ans = (X[0] + X[1] + ... + X[23]) % m;这里这样写是为了方便，程序本身为了防止数值溢出，每次加法都在进行模加操作。此后就是常见的menu了，一共有两个有效操作：[1] Get Flag与[2] Get Hint，为了看着舒服一些这里给出化简之后的逻辑：

```
printf("Please enter your answer: ");
scanf("%lld", &user_input);

if (user_input != ans) {
    puts("Wrong answer!");
    exit(1);
}

fp = fopen("./flag", "r");
if (!fp) {
    puts("Failed to open file...");
    exit(1);
}

fgets(buf, 0x40, fp);
printf("Congratulations! Here is your flag: %s\n", buf);
fclose(fp);
```

```
long long get_hint_bits(int n) {
    assert(n <= 60);

    long long nxt = 0;
    for (int i = 0; i < 24; i++) {
        nxt = (nxt + mulmod(X[i], A[i])) % m; // nxt = (nxt + A[i] * X[i]) mod m
    }

    // 左移状态窗口
    for (int i = 0; i < 23; i++) {
        X[i] = X[i + 1];
    }
    X[23] = nxt;

    return nxt >> (60 - n);
}
long long hint = get_hint_bits(0x28); // 0x28 = 40
printf("Here is your hint: %lld\n", hint);
```

打法是根据`An improved method for predicting truncated multiple recursive generators with unknown parameters`这个论文，喂给ai就行了，不放exp了

### SU_RSA

签到

```python
from Crypto.Util.number import long_to_bytes
import time

N =
e =
c =
S =

A = N - S + 1
X = 2^338
Y = 2^399
m = 5
t = 2

PR.<x, y> = PolynomialRing(ZZ)
f = x*y - A*x - 1

original_polys = []
for i in range(m + 1):
    for j in range(m - i + 1):
        original_polys.append(y^j * f^i * e^(m - i))

for i in range(m + 1):
    for j in range(1, t + 1):
        original_polys.append(x^j * f^i * e^(m - i))

def LM_key(monom):
    degs = monom.degrees()
    return (degs[1], degs[0])

def get_LM(p):
    return max(p.monomials(), key=LM_key)

poly_dict = {}
all_monomials = set()

for p in original_polys:
    lm = get_LM(p)
    poly_dict[lm] = p
    all_monomials.update(p.monomials())

for monom in list(all_monomials):
    if monom not in poly_dict:
        extra_p = monom * (e^m)
        poly_dict[monom] = extra_p
        all_monomials.update(extra_p.monomials())

sorted_monomials = sorted(list(all_monomials), key=LM_key)
dim = len(sorted_monomials)

M = Matrix(ZZ, dim, dim)

for i in range(dim):
    lm = sorted_monomials[i]
    p_scaled = poly_dict[lm](x*X, y*Y)
    for j in range(dim):
        monom = sorted_monomials[j]
        M[i, j] = p_scaled.monomial_coefficient(monom)

M_lll = M.LLL()

roots_polys = []
for row in M_lll:
    if row.is_zero():
        continue
    p_scaled = sum(row[j] * sorted_monomials[j] for j in range(dim))
    p_unscaled = p_scaled(x/X, y/Y)
    roots_polys.append(p_unscaled)

var_x, var_y = roots_polys[0].parent().gens()

k_val = None
x_val = None
found = False

for i in range(len(roots_polys)):
    if found:
        break
    p1 = roots_polys[i]
    if p1.is_constant():
        continue
    for j in range(i + 1, min(i + 4, len(roots_polys))):
        p2 = roots_polys[j]
        if p2.is_constant():
            continue
        res = p1.resultant(p2, var_y)
        if res.is_zero() or res.is_constant():
            continue
        res_uni = res.univariate_polynomial()
        roots = res_uni.roots()
        for root, _ in roots:
            if root == 0:
                continue
            k_guess = int(root)
            p1_sub = p1.subs({var_x: k_guess})
            y_roots = p1_sub.univariate_polynomial().roots()
            for y_root, _ in y_roots:
                if y_root != 0:
                    k_val = k_guess
                    x_val = int(y_root)
                    found = True
                    break
            if found:
                break

if k_val is not None:
    p_plus_q = S + x_val
    PR_Z.<z> = PolynomialRing(ZZ)
    eqn = z^2 - p_plus_q * z + N
    p_q_roots = eqn.roots()
    if len(p_q_roots) >= 2:
        p = int(p_q_roots[0][0])
        q = int(p_q_roots[1][0])
        phi = (p - 1) * (q - 1)
        d = inverse_mod(e, phi)
        m_pt = pow(c, d, N)
        print(long_to_bytes(int(m_pt)).decode(errors='ignore'))
```

### SU_Restaurant

签到

```python
import json
import re
from hashlib import sha3_512

import numpy as np

from pwn import remote

HOST = "101.245.107.149"
PORT = 10019
RNG = np.random.default_rng(0)


def h(msg: str) -> np.ndarray:
    return np.array(list(sha3_512(msg.encode()).digest()), dtype=int).reshape(8, 8)


def trop_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    n, k = a.shape
    k2, m = b.shape
    assert k == k2
    out = np.full((n, m), 10**9, dtype=int)
    for i in range(n):
        for j in range(m):
            out[i, j] = min(int(a[i, t]) + int(b[t, j]) for t in range(k))
    return out


def build_ab(
    row_min: np.ndarray, col_min: np.ndarray
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    target = np.minimum(row_min.reshape(8, 1) + 1, col_min.reshape(1, 8) + 1)
    for _ in range(10000):
        a_extra = 129 + RNG.integers(0, 2, size=(8, 5), dtype=int)
        b_extra = 129 + RNG.integers(0, 2, size=(5, 8), dtype=int)
        a = np.column_stack([row_min, np.ones(8, dtype=int), a_extra])
        b = np.vstack([np.ones((1, 8), dtype=int), col_min.reshape(1, 8), b_extra])
        if np.linalg.matrix_rank(a) != 7 or np.linalg.matrix_rank(b) != 7:
            continue
        if np.array_equal(trop_mul(a, b), target):
            return a, b, target
    raise RuntimeError("failed to build A/B")


def build_pr(
    m: np.ndarray, row_min: np.ndarray, col_min: np.ndarray, target: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    row_arg = np.argmin(m, axis=1)
    col_arg = np.argmin(m, axis=0)
    need_x = np.zeros((8, 8), dtype=bool)
    need_y = np.zeros((8, 8), dtype=bool)

    for i in range(8):
        for j in range(8):
            if row_min[i] < col_min[j]:
                need_x[row_arg[i], j] = True
            elif row_min[i] > col_min[j]:
                need_y[i, col_arg[j]] = True

    for _ in range(20000):
        x = RNG.integers(0, 2, size=(8, 8), dtype=int)
        y = RNG.integers(0, 2, size=(8, 8), dtype=int)
        x[need_x] = 0
        y[need_y] = 0

        ok = True
        for i in range(8):
            for j in range(8):
                if row_min[i] == col_min[j] and x[row_arg[i], j] and y[i, col_arg[j]]:
                    ok = False
                    break
            if not ok:
                break
        if not ok:
            continue

        p = 1 + x
        r = 1 + y
        if np.linalg.matrix_rank(p) != 8 or np.linalg.matrix_rank(r) != 8:
            continue
        z = np.minimum(trop_mul(m, p), trop_mul(r, m))
        if np.array_equal(z, target):
            return p, r
    raise RuntimeError("failed to build P/R")


def build_s(target: np.ndarray) -> np.ndarray:
    mask_256 = target == 256
    for _ in range(10000):
        s = 255 + RNG.integers(0, 2, size=(8, 8), dtype=int)
        s[mask_256] = 256
        if (
            np.all(s >= target)
            and np.linalg.matrix_rank(s) == 8
            and not np.array_equal(s, target)
        ):
            return s
    raise RuntimeError("failed to build S")


def forge(msg: str) -> dict[str, list[list[int]]]:
    m = h(msg)
    row_min = m.min(axis=1)
    col_min = m.min(axis=0)
    a, b, target = build_ab(row_min, col_min)
    p, r = build_pr(m, row_min, col_min, target)
    s = build_s(target)

    left = trop_mul(a, b)
    right = np.minimum(np.minimum(trop_mul(m, p), trop_mul(r, m)), s)
    assert np.array_equal(left, target)
    assert np.array_equal(right, target)
    assert np.linalg.matrix_rank(a) == 7
    assert np.linalg.matrix_rank(b) == 7
    assert np.linalg.matrix_rank(p) == 8
    assert np.linalg.matrix_rank(r) == 8
    assert np.linalg.matrix_rank(s) == 8

    return {
        "A": a.tolist(),
        "B": b.tolist(),
        "P": p.tolist(),
        "R": r.tolist(),
        "S": s.tolist(),
    }


def solve_remote() -> str:
    io = remote(HOST, PORT)
    io.recvuntil(b">>> ")
    io.sendline(b"2")
    line = io.recvline().decode()
    match = re.search(r"Please make (.*) for me!", line)
    if not match:
        raise RuntimeError(line)
    payload = json.dumps(forge(match.group(1))).encode()
    io.recvuntil(b">>> ")
    io.sendline(payload)
    out = io.recvall(timeout=3).decode(errors="ignore")
    io.close()
    return out


if __name__ == "__main__":
    print(solve_remote())
```

### SU_CyberTrack

osint题目，github静态博客，直接去github仓库看一眼，git clone下来

lazygit看看记录

![image](./attachments/260316-101337.avif)

拿到邮箱`evanlin1123@foxmail.com`，继续翻mc，有一堆名字

![image](./attachments/260316-101426.avif)

x上面搜一下每一个id

![image](./attachments/260316-101442.avif)

discord里面拿到后面的string

给邮箱发邮件

![image](./attachments/260316-101515.avif)

拿到flag

## 后话

这次排35，和自己状态不好肯定是有关系的，害继续努力吧
