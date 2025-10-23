---
title: ApoorvCTF 2025
published: 2025-03-09
pinned: false
description: ApoorvCTF 2025，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-09
pubDate: 2025-03-09
---

## 前言

赛时就做了两题，跟着佬的wp复现一下

## 题目

### Genjutsu_Labyrinth

task
```
from sympy import primerange
import random
from collections import deque

def generate(size):
    grid = [[random.randint(0, 9) for col in range(size)] for row in range(size)]
    grid[0][0] = 0
    return grid

def encrypt(n, a, b, mod=101):
    return (a * n + b) % mod

def build_encrypted_grid(grid, a, b, mod=101):
    size = 10
    encry_grid = []
    for y in range(size):
        row = []
        for x in range(size):
            enc_val = encrypt(grid[y][x], a, b, mod)
            row.append(str(enc_val).zfill(2))
        encry_grid.append(row)
    return encry_grid

def optimize(grid):
    #hidden
    pass

grid = generate(10)
a = random.choice(list(primerange(2, 12)))
b = random.choice(range(101))
encry_grid = build_encrypted_grid(grid, a, b, mod=101)

#nc chals1.apoorvctf.xyz 4002
```

generate是正常一个10*10的迷宫，每个数字0-9，起点是0
encrypt是正常的线性同余加密
optimize没啥用
build_encrypted_grid是生成一个没个数加密后的矩阵，并且输出为字符串，比如5->05

a=[2,3,5,7,11]

```
//nc情况
  ____                 _         _
 / ___|  ___  _ __    (_) _   _ | |_  ___  _   _
| |  _  / _ \| '_ \   | || | | || __|/ __|| | | |
| |_| ||  __/| | | |  | || |_| || |_ \__ \| |_| |
 \____| \___||_| |_| _/ | \__,_| \__||___/ \__,_|
                    |__/

Welcome to Genjutsu Labyrinth!
Your goal is to navigate from the top-left to the bottom-right successfully
Note: Your current position is denoted by Pa. The first cell has a value 0
-------------------------------------------------

Pa 49 42 42 00 00 21 00 21 00
49 00 42 21 28 56 07 00 42 56
21 28 42 42 14 21 21 21 00 14
07 49 07 35 07 07 42 56 35 07
63 28 28 07 00 49 00 56 21 28
07 56 07 35 14 42 21 35 35 00
14 21 00 07 21 35 49 07 14 28
21 35 07 00 49 14 21 00 42 42
42 21 56 28 49 56 07 14 49 28
63 07 49 35 07 07 07 28 63 00

Use S/D to move down or right. Type 'exit' to quit.
Enter move (S/D):
```

哎，其实我们要找的是xor为0，即从 enc_val 中穷举 a, b 的值。然后根据 a, b 的值求出 grid 的值，进行穷举路径，找到 XOR 值为 0 的路径。

exp

```
from pwn import *
import itertools
from Crypto.Util.number import inverse

p = remote('chals1.apoorvctf.xyz', 4002)

for _ in range(12):
    data = p.recvuntil(b'\n').strip().decode()
    print(data)

# 读取加密网格，每行接收后替换'Pa'为'00'，并转换成数字列表
encry_grid = []
for _ in range(10):
    data = p.recvuntil(b'\n').strip().decode()
    print(data)
    data = data.replace('Pa', '00')
    row = list(map(int, data.split()))
    encry_grid.append(row)

encs = []
for i in range(10):
    for j in range(10):
        if encry_grid[i][j] not in encs:
            encs.append(encry_grid[i][j])

found = False
for a in [2, 3, 5, 7, 11]:
    for b in range(101):
        success = True
        for i in range(10):
            c = (a * i + b) % 101
            if c not in encs:
                success = False
                break
        if success:
            found = True
            break
    if found:
        break

grid = []
for i in range(10):
    row = []
    for j in range(10):
        r = (encry_grid[i][j] - b) * inverse(a, 101) % 101
        row.append(r)
    grid.append(row)

# 构造移动指令：总共需要18步，选取9步向下（S）移动，其余为向右（D）移动，
# 利用排列枚举所有可能的路径，选择 XOR 结果为 0 的路径
seq = list(range(18))
for perm in itertools.permutations(seq, 9):
    com = ''
    val = 0
    x = 0
    y = 0
    for i in range(18):
        if i in perm:
            com += 'S'
            x += 1
            val ^= grid[x][y]
        else:
            com += 'D'
            y += 1
            val ^= grid[x][y]
    if val == 0:
        break

for i in range(18):
    data = p.recvuntil(b': ')
    print(data.decode() + com[i])
    p.sendline(com[i].encode())
    data = p.recvuntil(b'\n').strip().decode()
    print(data)

data = p.recvuntil(b'exit!\n').strip().decode()
print(data)
for _ in range(2):
    data = p.recvuntil(b'\n').strip().decode()
    print(data)

p.interactive()

```

### Split_Lies

两个照片什么都没有，有点抽象
尝试了很多方法后，将 RGB 的值相加后除以 256 的余数，中央出现了旗帜。

```
from PIL import Image

img1 = Image.open('part1.png').convert('RGB')
img2 = Image.open('part2.png').convert('RGB')

w, h = img1.size

output_img = Image.new('RGB', (w, h), (255, 255, 255))

for y in range(h):
    for x in range(w):
        r1, g1, b1 = img1.getpixel((x, y))
        r2, g2, b2 = img2.getpixel((x, y))
        r = (r1 + r2) % 256
        g = (g1 + g2) % 256
        b = (b1 + b2) % 256
        output_img.putpixel((x, y), (r, g, b))

output_img.save('flag.png')
```

### Finding_Goku

task

```
import hashlib

def check_hex_data(hex1, hex2, start_string):
    if hex1 == hex2:
        return "Error: Even a Saiyan warrior knows that true strength lies in difference! The two inputs must not be identical."

    try:
        data1 = bytes.fromhex(hex1)
        data2 = bytes.fromhex(hex2)
    except ValueError:
        return "Error: Looks like you misfired a Ki blast! Invalid hex input detected."

    start_bytes = start_string.encode()

    if not (data1.startswith(start_bytes) and data2.startswith(start_bytes)):
        return "Error: These aren't true warriors! Both inputs must start with the legendary sign of 'GOKU' to proceed."

    def md5_hash(data):
        hasher = hashlib.md5()
        hasher.update(data)
        return hasher.hexdigest()

    hash1 = md5_hash(data1)
    hash2 = md5_hash(data2)

    if hash1 != hash2:
        return "Error: These warriors are impostors! They wear the same armor but their Ki signatures (MD5 hashes) don't match."

    try:
        with open("flag.txt", "r") as flag_file:
            flag = flag_file.read().strip()
        return f"🔥 You have found the real Goku! Your flag is: {flag}"
    except FileNotFoundError:
        return "Error: The Dragon Balls couldn't summon the flag! 'flag.txt' is missing."

if __name__ == "__main__":
    start_string = "GOKU"
    hex1 = input("Enter first hex data: ")
    hex2 = input("Enter second hex data: ")
    print(check_hex_data(hex1, hex2, start_string))
```

总而言之言而总之想让md5相等，直接开爆

```
from pwn import *

p = remote('chals1.apoorvctf.xyz', 5002)

with open('md5_data1', 'rb') as f:
    data1 = f.read().hex()

with open('md5_data2', 'rb') as f:
    data2 = f.read().hex()

data = p.recvuntil(b': ')
print(data.decode() + data1)
p.sendline(data1.encode())
data = p.recvuntil(b': ')
print(data.decode() + data2)
p.sendline(data2.encode())

data = p.recvuntil(b'\n').rstrip()
print(data.decode())

p.interactive()
```

### Kowareta_Cipher
task
```
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randbytes

def main():
    key = randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    flag = b'apoorvctf{fake_flag_123}'

    print("Welcome to the ECB Oracle challenge!")
    print("Enter your input in hex format.")

    try:
        while True:
            print("Enter your input: ", end="", flush=True)
            userinput = sys.stdin.readline().strip()

            if not userinput:
                break

            try:
                userinput = bytes.fromhex(userinput)
                ciphertext = cipher.encrypt(pad(userinput + flag + userinput, 16))
                print("Ciphertext:", ciphertext.hex())

            except Exception as e:
                print(f"Error: {str(e)}")

    except KeyboardInterrupt:
        print("Server shutting down.")

if __name__ == "__main__":
    main()

# nc chals1.apoorvctf.xyz 4001
```

很有意思，加密格式变成`x+flag+x`，我们`ECB`的特点就是相同的明文块会生成相同的密文块，padding怎么办呢？消除影响就好了

exp
```
from pwn import *

p = remote('chals1.apoorvctf.xyz', 4001)

for _ in range(2):
    data = p.recvuntil(b'\n').strip().decode()
    print(data)

flag = ''
for i in range(32):
    for code in range(33, 127):
        inp = 'X' * (31 - i) + flag + chr(code) + 'X' * (31 - i)
        print('[+] input:', inp)
        inp_hex = inp.encode().hex()
        prompt = p.recvuntil(b': ').decode()
        print(prompt + inp_hex)
        p.sendline(inp_hex.encode())
        data = p.recvuntil(b'\n').strip().decode()
        print(data)
        ct = data.split(' ')[-1]
        if ct[32:64] == ct[96:128]:
            flag += chr(code)
            break

print('[*] flag:', flag)
p.interactive()
```