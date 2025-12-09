---
title: TKKCTF2025
published: 2025-12-08
pubDate: 2025-12-08
description: tkkctf crypto wp
pinned: false
tags: ["crypto"]
author: zsm
category: CTF-crypto
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

这次校赛正赛因为时间不够，自己有一个琢磨了很久的题没有端上来，后面有机会再来吧。

其实整体密码题的质量不算特别高？

## 题目

### Secure Vault

> 他们说 AES 是对称加密算法，所以加密和解密本质上是一样的，对吧？

task.py

```python
import os
import random
import string
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

ALPHABET = string.ascii_letters + string.digits

API_SECRET = ''.join(random.choices(ALPHABET, k=48))
KEY = os.urandom(32)

def get_flag():
    return os.environ.get('FLAG', 'xujc{test_flag_local}')

def encrypt_session(user_id):
    payload = user_id + API_SECRET
    padded_payload = pad(payload.encode(), 16)
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(padded_payload)

def main():
    print("=== Secure Vault ===", flush=True)
    while True:
        print("\n1. Generate Token")
        print("2. Admin Login")
        try:
            choice = input("> ").strip()
            if choice == '1':
                u = input("ID: ").strip()
                if len(u) < 16:
                    print("Error: ID too short.", flush=True)
                    continue
                print(f"Token: {encrypt_session(u).hex()}", flush=True)
            elif choice == '2':
                if input("Secret: ").strip() == API_SECRET:
                    print(f"Flag: {get_flag()}", flush=True)
                    sys.exit(0)
                else:
                    print("Access Denied.", flush=True)
                    sys.exit(0)
        except:
            sys.exit(0)

if __name__ == "__main__":
    main()
```

很经典的CBC攻击对吧

```python
def encrypt_session(user_id):
    payload = user_id + API_SECRET
    padded_payload = pad(payload.encode(), 16)
    iv = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(padded_payload) # ⬅️ 错误所在！
```

逐字节恢复即可

```python
import string
import sys

from pwn import *

HOST = '47.122.52.77'
PORT = 33101

ALPHABET = string.ascii_letters + string.digits

def xor(b1, b2):
    return bytes([a ^ b for a, b in zip(b1, b2)])

def get_token(io, user_id):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'ID: ', user_id.encode())
    line = io.recvline().decode().strip()
    if "Token: " in line:
        return bytes.fromhex(line.split(": ")[1])
    return None

def solve():
    io = remote(HOST, PORT)

    known_secret = ""

    for i in range(48):
        offset = (15 - i) % 16
        pad_len = 16 + offset
        uid_target = "0" * pad_len

        token = get_token(io, uid_target)

        total_idx = pad_len + i
        block_idx = total_idx // 16

        r_target = token[block_idx*16 : (block_idx+1)*16]

        full_plaintext = (uid_target + known_secret).encode()
        p_prev_target = full_plaintext[(block_idx-1)*16 : block_idx*16]

        target_val = xor(r_target, p_prev_target)

        prefix = full_plaintext[total_idx-15 : total_idx]

        batch_uid = b"0" * 16
        candidates = []

        for char in ALPHABET:
            block = prefix + char.encode()
            batch_uid += block
            candidates.append(char)

        batch_token = get_token(io, batch_uid.decode())

        found_char = None

        for j, char in enumerate(candidates):
            k = j + 1

            r_guess = batch_token[k*16 : (k+1)*16]
            p_prev_guess = batch_uid[(k-1)*16 : k*16]

            computed_val = xor(r_guess, p_prev_guess)

            if computed_val == target_val:
                found_char = char
                break

        if found_char:
            known_secret += found_char
            sys.stdout.write(f"\r[+] Found {i+1}/48: {known_secret}")
            sys.stdout.flush()
        else:
            print(f"\n[-] Failed to find char at index {i}")
            break

    print("\n[*] Secret recovered!")

    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Secret: ', known_secret.encode())

    io.interactive()

if __name__ == '__main__':
    solve()
```

### Isomorphia

> 我们开发了一套校验系统。
> 系统的开发者向我保证，他在代码里写了非常严格的结构检查逻辑，绝对不可能有任何黑客能混过去。

task.py

```python
import os
import random as py_random
import sys
import traceback

from sage.all import *

FLAG = os.getenv('FLAG')

class Challenge:
    def __init__(self):
        self.q = 127
        self.n = 26
        self.k = 14
        self.F = GF(self.q)
        self.border = "┃"

        self.G = self._gen_random_basis()
        self.Q = self._gen_monomial()
        self.H = (self.G * self.Q).echelon_form()

    def _gen_random_basis(self):
        return random_matrix(self.F, self.k, self.n)

    def _gen_monomial(self):
        M = zero_matrix(self.F, self.n, self.n)
        indices = list(range(self.n))
        py_random.shuffle(indices)

        for r in range(self.n):
            while True:
                val = self.F.random_element()
                if val != 0:
                    M[r, indices[r]] = val
                    break
        return M

    def _print(self, *args):
        s = " ".join(map(str, args))
        sys.stdout.write(s + "\n")
        sys.stdout.flush()

    def _read(self):
        return sys.stdin.buffer.readline().decode('utf-8').strip()

    def start(self):

        self._print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
        self._print(f"{self.border} .:::      Isomorphia       :::.", self.border)
        self._print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

        while True:
            menu = f"{self.border} Options: \n"
            menu += f"{self.border}\t[G]et the G and H! \n"
            menu += f"{self.border}\t[S]olve the System! \n"
            menu += f"{self.border}\t[Q]uit"
            self._print(menu)

            try:
                line = self._read()
                if not line: break
                choice = line.lower()
            except Exception:
                break

            if choice == 'g':
                self._print(f"G = {self.G}")
                self._print(f"H = {self.H}")

            elif choice == 's':
                self._print(self.border, "Please send the matrix U row by row: ")
                try:
                    u_rows = []
                    for _ in range(self.k):
                        line = self._read()
                        if not line: raise ValueError("Empty input")
                        u_rows.append([int(x) for x in line.split(',')])

                    self._print(self.border, "Now, please send the matrix P row by row: ")
                    p_rows = []
                    for _ in range(self.n):
                        line = self._read()
                        if not line: raise ValueError("Empty input")
                        p_rows.append([int(x) for x in line.split(',')])
                    U_cand = matrix(self.F, u_rows)
                    P_cand = matrix(self.F, p_rows)

                    is_valid = True
                    if U_cand * self.G * P_cand != self.H:
                        is_valid = False
                    if not U_cand.is_invertible() or not P_cand.is_invertible():
                        is_valid = False
                    for row in P_cand:
                        if list(row).count(0) != self.n - 1:
                            pass

                    if is_valid:
                        self._print(self.border, f"Congrats, you got the flag: {FLAG}")
                        sys.exit(0)
                    else:
                        self._print(self.border, "Verification failed! Bye!!")
                        sys.exit(0)

                except Exception:
                    self._print(self.border, "Something went wrong with your input :| Quitting!")
                    sys.exit(0)

            elif choice == 'q':
                self._print(self.border, "Quitting...")
                sys.exit(0)
            else:
                self._print(self.border, "Bye...")
                sys.exit(0)

def main():
    try:
        if sys.stdout.encoding.lower() != 'utf-8':
            sys.stdout.reconfigure(encoding='utf-8')

        task = Challenge()
        task.start()
    except Exception:
        sys.stdout.write(f"\n[SERVER ERROR] {traceback.format_exc()}\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
```

其实是后面那个题的非预期版本

核心漏洞在

```python
for row in P_cand:
    if list(row).count(0) != self.n - 1:
        pass
```

这里因为直接是pass处理，根本没要求 P 是单项式矩阵，所以要求的过为宽泛了。

这就变成了一个线性代数题目了

令

$$U = G_0^{-1}$$

那么：

$$UG = G_0^{-1}[G_0 \mid G_1] = [I_{14} \mid B]$$

其中 $B = G_0^{-1}G_1$ 是一个 $14 \times 12$ 的矩阵。

把 $P$ 按行（26 行）拆成块矩阵：

$$P = \begin{pmatrix} P_{11} & P_{12} \\ P_{21} & P_{22} \end{pmatrix}$$

- $P_{11}$ 是 $14 \times 14$
- $P_{12}$ 是 $14 \times 12$
- $P_{21}$ 是 $12 \times 14$
- $P_{22}$ 是 $12 \times 12$

我们希望：

$$[I \mid B] \begin{pmatrix} P_{11} & P_{12} \\ P_{21} & P_{22} \end{pmatrix} = [I \mid C]$$

算一下这个乘积：

$$[I \mid B]P = [I P_{11} + B P_{21} \mid I P_{12} + B P_{22}] = [P_{11} + B P_{21} \mid P_{12} + B P_{22}]$$

为了让左边等于 $[I \mid C]$，只需要满足：

1.  $P_{11} + B P_{21} = I_{14}$
2.  $P_{12} + B P_{22} = C$

我们选一个最简单的方案：

- 取 $P_{21} = 0$, $P_{11} = I_{14}$, 这样自动满足 (1)
- 再取 $P_{22} = I_{12}$ (显然可逆)

那么只要设

$$P_{12} = C - B P_{22} = C - B$$

这样构造出来的 $P$ 是一个**块上三角矩阵**：

$$P = \begin{pmatrix} I_{14} & C - B \\ 0 & I_{12} \end{pmatrix}$$

对块上三角矩阵，行列式是对角块行列式的乘积：

$$\det(P) = \det(I_{14}) \cdot \det(I_{12}) = 1 \cdot 1 = 1 \ne 0$$

所以 $P$ 可逆。

而这时：

$$UGP = [I \mid B]P = [I \mid (C - B) + B] = [I \mid C] = H$$

所以这个 $U, P$ 一定能通过验证，拿到 flag。

exp.py

```python
q = 127
F = GF(q)

G = Matrix(F, [
])
H = Matrix(F, [
])

G0 = G[:, 0:14]
G1 = G[:, 14:26]
H0 = H[:, 0:14]
C  = H[:, 14:26]

U = G0.inverse()
A = U * G
B = A[:, 14:26]

P11 = identity_matrix(F, 14)
P21 = Matrix(F, 12, 14, 0)
P22 = identity_matrix(F, 12)
P12 = C - B

P_top = P11.augment(P12)
P_bottom = P21.augment(P22)
P = P_top.stack(P_bottom)

assert U * G * P == H
```

### Isomorphia_revenge

> 上次的系统上线后被黑客秒破了，我们紧急修复了这个漏洞，并开除了实习生。现在，校验逻辑已经严丝合缝。这一次，纯粹的技巧已经救不了那群无聊的黑客了！

task.py

```python
import os
import random as py_random
import sys
import traceback

from sage.all import *

FLAG = os.getenv('FLAG')

class Challenge:
    def __init__(self):
        self.q = 127
        self.n = 26
        self.k = 14
        self.F = GF(self.q)
        self.border = "┃"

        self.G = self._gen_random_basis()
        self.Q = self._gen_monomial()
        self.H = (self.G * self.Q).echelon_form()

    def _gen_random_basis(self):
        return random_matrix(self.F, self.k, self.n)

    def _gen_monomial(self):
        M = zero_matrix(self.F, self.n, self.n)
        indices = list(range(self.n))
        py_random.shuffle(indices)

        for r in range(self.n):
            while True:
                val = self.F.random_element()
                if val != 0:
                    M[r, indices[r]] = val
                    break
        return M

    def _print(self, *args):
        s = " ".join(map(str, args))
        sys.stdout.write(s + "\n")
        sys.stdout.flush()

    def _read(self):
        return sys.stdin.buffer.readline().decode('utf-8').strip()

    def start(self):

        self._print("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
        self._print(f"{self.border} .:::      Isomorphia       :::.", self.border)
        self._print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

        while True:
            menu = f"{self.border} Options: \n"
            menu += f"{self.border}\t[G]et the G and H! \n"
            menu += f"{self.border}\t[S]olve the System! \n"
            menu += f"{self.border}\t[Q]uit"
            self._print(menu)

            try:
                line = self._read()
                if not line: break
                choice = line.lower()
            except Exception:
                break

            if choice == 'g':
                self._print(f"G = {self.G}")
                self._print(f"H = {self.H}")

            elif choice == 's':
                self._print(self.border, "Please send the matrix U row by row: ")
                try:
                    u_rows = []
                    for _ in range(self.k):
                        line = self._read()
                        if not line: raise ValueError("Empty input")
                        u_rows.append([int(x) for x in line.split(',')])

                    self._print(self.border, "Now, please send the matrix P row by row: ")
                    p_rows = []
                    for _ in range(self.n):
                        line = self._read()
                        if not line: raise ValueError("Empty input")
                        p_rows.append([int(x) for x in line.split(',')])
                    U_cand = matrix(self.F, u_rows)
                    P_cand = matrix(self.F, p_rows)

                    is_valid = True
                    if U_cand * self.G * P_cand != self.H:
                        is_valid = False
                    if not U_cand.is_invertible() or not P_cand.is_invertible():
                        is_valid = False
                    for row in P_cand:
                        if list(row).count(0) != self.n - 1:
                            is_valid=False
                            break

                    if is_valid:
                        self._print(self.border, f"Congrats, you got the flag: {FLAG}")
                        sys.exit(0)
                    else:
                        self._print(self.border, "Verification failed! Bye!!")
                        sys.exit(0)

                except Exception:
                    self._print(self.border, "Something went wrong with your input :| Quitting!")
                    sys.exit(0)

            elif choice == 'q':
                self._print(self.border, "Quitting...")
                sys.exit(0)
            else:
                self._print(self.border, "Bye...")
                sys.exit(0)

def main():
    try:
        if sys.stdout.encoding.lower() != 'utf-8':
            sys.stdout.reconfigure(encoding='utf-8')

        task = Challenge()
        task.start()
    except Exception:
        sys.stdout.write(f"\n[SERVER ERROR] {traceback.format_exc()}\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
```

本质上就是修复了上题的漏洞，但是我忘记加时间限制了，硬爆有可能会出来，怪难受的，早知道狠心一点了😡。

这道题在学术界被称为 线性码等价问题 (Linear Equivalence Problem, LEP)

如果你是osint大师的话，在询问ai后知道了问题，就可以开始搜索，不去找论文，直接找[github的实现仓库](https://github.com/juliannowakowski/lep-cf/tree/main)即可

这个仓库的佬是概率性碰撞，差不多50%的几率这个题能出来，直接多运行几次就行

exp.py

```python
from pwn import remote
from re import findall
# from sage.all import *

q = 127
k,n = 26,14
io = remote("127.0.0.1", "8989")
io.recvuntil(b'uit\n')
io.sendline(b'g')
io.recvuntil(b'G = ')
Glist = io.recvuntil(b'\nH')[:-2].decode()

io.recvuntil(b'= ')
Hlist = io.recvuntil('\n┃'.encode())[:-4].decode()
def parse_matrix(s):
    rows = s.split('\n')
    matrix = []
    for row in rows:
        if row.strip():
            matrix.append([int(x) for x in findall(r'\d+', row)])
    return matrix
F = GF(q)
G = matrix(F, parse_matrix(Glist))
H = matrix(F, parse_matrix(Hlist))

load("utils.sage")
load("lep_solver.sage")

q = 127
n = 26
k = 14

Fq = GF(q)

# G1 = random_matrix(Fq, k, n)
# Q = randomMonomial(n, q)
# G2 = (G1*Q).echelon_form()

result = lepCollSearch(G, H)
if result != None:
    U, P = result
    # assert G2 == U*G1*P
    assert H == U*G*P
    print("lepCollSearch succesfully recovered solution.")


_U,_P = result
print(_U*G*_P==H)
print(_U.dimensions())
print(_P.dimensions())
io.recvuntil(b"uit\n")
io.sendline(b"s")
io.recvuntil(b"Please send the matrix U row by row: ")
print(_U.dimensions())
print(_P)
for i in range(14):
    print(str(list(_U[i]))[1:-1])
    io.sendline(str(list(_U[i]))[1:-1].encode())
io.recvuntil(b"Now, please send the matrix P row by row: ")
for _ in range(n):
    print(str(list(_P[_]))[1:-1])
    io.sendline(str(list(_P[_]))[1:-1].encode())
io.interactive()
print(io.recvline().decode())
```

### Matzs Nightmare（re)

> “今天我们宣布发布一款全新的编程语言：xujc！它完美的解决了C++迄今为止令人唾弃的内存管理问题……”

这是当时red让我测题的时候写的，个人感觉挺好玩的，如果你是re老手，当然我不是，可能会敏锐的发现这个是用什么写的。

我是后面在010中找到了`mruby`的头，然后手动分离，然后字节码逆向出来的，加密就是分块xor，主要是前面的分离，还是很好玩的

## 后话

感谢师傅们可以来玩这次的tkkctf，希望师傅们也多多包含，这也算是我校跨出校门的第一步。
