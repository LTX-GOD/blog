---
title: 2025PolarCTF春季赛
published: 2025-03-22
pinned: false
description: 2025PolarCTF春季赛，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-22
pubDate: 2025-03-22
---


## 前言

去南京的路上，顺手写写

## 题目

### crypto

#### RSA1-2

task
```
import os
from Crypto.Util.number import *
from typing import Union
from flag import flag

bits = 512


def polar(msg: Union[bytes, bytearray], length: int) -> bytes:
    assert length > len(msg), "指定的长度必须大于原始消息长度加 1。"
    return bytes(msg) + b'\x00' + os.urandom(length - len(msg) - 1)


def unpolar(msg: Union[bytes, bytearray]) -> bytes:
    msg = bytes(msg)
    assert b'\x00' in msg, "输入的字节串中不包含分隔符。"
    return msg.split(b'\x00')[0]


def getflag1(m):
    result = []
    for i in range(2):
        result.append(getPrime(bits))
    p, q = result
    if p <= q:
        p, q = q, p
    e = 0x10001
    n = p * q
    c = pow(m, e, n)
    hint = pow(2024 * p + 2025, q, n)
    print('---------- getflag 1 ----------')
    print(f'{c = }')
    print(f'{n = }')
    print(f'{hint = }')


def getflag2(m):
    result = []
    for i in range(2):
        result.append(getPrime(bits))
    p, q = result
    n = p * q
    hint1 = pow(m, p, n)
    hint2 = pow(m, q, n)
    print('---------- getflag 2 ----------')
    print(f'{hint1 = }')
    print(f'{hint2 = }')
    print(f'{n = }')



def getflag3(m):
    result = []
    for i in range(2):
        result.append(getPrime(bits))
    p, q = result
    e = 0x10001
    n = p * q
    g = 20242025
    hint = pow(g + p * 1111, e, n)
    c = pow(m, e, n)
    print('---------- getflag 3 ----------')
    print(f'{c = }')
    print(f'{n = }')
    print(f'{hint = }')


assert len(flag) == 42
mm = []
for i in range(0, 42, 14):
    mm.append(bytes_to_long(polar(flag[i:i + 14], bits // 4 - 1)))

m1, m2, m3 = mm
getflag1(m1)
getflag2(m2)
getflag3(m3)

```

三个很经典的数论题堆到了一起，额，后面补长度，其实没啥区别，直接写就行了，如果想看细节推导的话，可以等我下周写（

exp
```
from Crypto.Util.number import *
import gmpy2

c = 
n = 
hint = 

e=65537

p = gmpy2.gcd(pow(2025,n,n)-hint,n)
q = n // p
d = gmpy2.invert(e,(p-1)*(q-1))
m = pow(c,d,n)
print(long_to_bytes(m))


from Crypto.Util.number import *

n = 
x = 
y = 
a=pow(x,n,n)
p=GCD(a-y,n)
q=n//p
d = inverse(p,(p-1)*(q-1))
m = pow(x,d,n)
print(long_to_bytes(m))



from Crypto.Util.number import *
import gmpy2

c = 
n = 
hint = 

e = 65537
b = 20242025

p = gmpy2.gcd(pow(b,e,n)-hint,n)
q = n // p
d = gmpy2.invert(e,(p-1)*(q-1))
m = pow(c,d,n)
print(long_to_bytes(m))

```

#### beginner
task
```
assert(len(open('flag.txt', 'rb').read()) <= 50)
assert(str(int.from_bytes(open('flag.txt', 'rb').read(), byteorder='big') << 10000).endswith('16732186163543403522711798960598469149029861032300263763941636254755451456334507142958574415880945599253440468447483752611840'))

#endwith后为125位
#其中加密方式为utf-8
```

{{< raw >}}
$$
10^{125}=2^{125}*5^{125}
$$
{{< /raw >}}
分解模数之后分开处理，计算 1840 能被 2 整除的最高次幂，然后搞定就行了

```
K = 16732186163543403522711798960598469149029861032300263763941636254755451456334507142958574415880945599253440468447483752611840
m = 5**125
r = pow(2, 10000, m)
r_inv = pow(r, -1, m)
F = (K % m * r_inv) % m
uflag = F.to_bytes((F.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
print(uflag)
```

#### Ununicast
task
```
import libnum
import gmpy2
import random
from flag import *

m = libnum.s2n(flag) 

n_list = []
c_list = []
q_list = []
p_list = []

for i in range(1, 6):  
    p = libnum.generate_prime(1024) 
    q = libnum.generate_prime(1024)  
    n = p * q * (i + 1)  

    p_list.append(p)  
    q_list.append(q)  
    n_list.append(n)  

while True:
    e = random.randint(10, 30)  

    if gmpy2.is_prime(e):  
        break

for index in range(len(n_list)):
    c = pow(m, e, n_list[index])  
    c_list.append(c_list.append(c * (index + 1)))  
    print("n" + str(index + 1) + " =", n_list[index])  
    print("c" + str(index + 1) + " =", c_list[index])  
```
经典的crt问题，稍微复杂一点，看看互素的是哪几个，然后算模逆，e的筛选不用管，遍历就行了
exp
```
import gmpy2

k1 = c1
k2 = c2 // 2
k4 = c4 // 4

# 计算 N 和 CRT 参数
N = n1 * n2 * n4
y1 = n2 * n4
y2 = n1 * n4
y4 = n1 * n2

# 计算模逆
z1 = gmpy2.invert(y1, n1)
z2 = gmpy2.invert(y2, n2)
z4 = gmpy2.invert(y4, n4)

# 计算 a = m^e mod N
a = (k1 * y1 * z1 % N + k2 * y2 * z2 % N + k4 * y4 * z4 % N) % N

# 可能的 e 值
possible_e = [11, 13, 17, 19, 23, 29]

# 尝试每个 e，计算 m
for e in possible_e:
    root, exact = gmpy2.iroot(a, e)
    if exact:
        m = int(root)
        # 将 m 转换为字节
        flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        try:
            # 尝试解码为字符串
            flag = flag_bytes.decode('ascii')
            print(f"e = {e}, flag = {flag}")
            # 检查是否符合 flag 格式
            if flag.startswith('flag{'):
                print(f"找到 flag: {flag}")
                break
        except UnicodeDecodeError:
            print(f"e = {e}, flag_bytes = {flag_bytes}")
```

#### LCG
task
```
a =  
b =  
c =  
m =  
一共循环十次

```

这个就更简单了，直接逆十次
```
a =  
b =  
c =  
m = 
inv_a = pow(a, -1, m)
x = c
for _ in range(10):
    x = (inv_a * (x - b)) % m

x0 = x

byte_length = (x0.bit_length() + 7) // 8
flag_bytes = x0.to_bytes(byte_length, byteorder='big')

flag = flag_bytes.decode('ascii')
print(f"Flag: {flag}")
```

#### playstreamone
task
```
from Flag import flag
assert flag.startswith("flag{")
assert flag.endswith("}")
assert len(flag) == 24


def LFSR(R, mask):
    output = (R << 1) & 0xffffff
    i = (R & mask) & 0xffffff
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return output, lastbit



def Fx1x2x3(R1, R1_mask, R2, R2_mask, R3, R3_mask):
    R1_NEW, x1 = LFSR(R1, R1_mask)
    R2_NEW, x2 = LFSR(R2, R2_mask)
    R3_NEW, x3 = LFSR(R3, R3_mask)

    output = (x1 * x2) ^ ((x2 ^ 1) * x3)

    return R1_NEW, R2_NEW, R3_NEW, output



R1 = int(flag[5:11], 16)
R2 = int(flag[11:17], 16)
R3 = int(flag[17:23], 16)


assert len(bin(R1)[2:]) == 21
assert len(bin(R2)[2:]) == 22
assert len(bin(R3)[2:]) == 21

R1_mask = 0x20010
R2_mask = 0x8002c
R3_mask = 0x200004

for fi in range(1024):
    print(f"Processing file {fi}")
    tmp1mb = bytearray()

    for i in range(1024):
        tmp1kb = bytearray()

        for j in range(1024):
            tmp = 0

            for k in range(8):
                R1, R2, R3, out = Fx1x2x3(R1, R1_mask, R2, R2_mask, R3, R3_mask)
                tmp = (tmp << 1) ^ out

            tmp1kb.append(tmp)

        tmp1mb.extend(tmp1kb)

    with open(f"./output/{fi}", "ab") as f:
        f.write(tmp1mb)

    print(f"File {fi} written successfully.")

```

看源码知道是个lfsr，三组，生成` output = (x1 * x2) ^ ((x2 ^ 1) * x3)`，但是貌似只能爆破，在车上写了一个范围在`10**21~10**22`的，但是不行，回头修改一下，按着wp稍微修改了一下代码，发现第一开始写的复杂了，Geffe 的输出与 x1相同的概率为 3/4，Geffe 的输出与 x2 相同的概率为 1/2，Geffe 的输出与 x3 相同的概率为 3/4这说明输出与第一个和第三个的关联性非常大。 因此，我们可以暴力去枚举第一个和第三个 LFSR 的输出判断其与 类 Geffe 的输出相等的个数，如果大约在 75% 的话，就可以认为是正确的。第二个就直接暴力枚举了，R1和R3可以单独通过correlation attack求出来，最后再用brute force找出R2，第一开始还真的不知道这两个方法？一直都是手搓的

```
def LFSR(R, mask):
    output = (R << 1) & 0xffffff
    i = (R & mask) & 0xffffff
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return output, lastbit


def Fx1x2x3(R1, R1_mask, R2, R2_mask, R3, R3_mask):
    R1_NEW, x1 = LFSR(R1, R1_mask)
    R2_NEW, x2 = LFSR(R2, R2_mask)
    R3_NEW, x3 = LFSR(R3, R3_mask)

    output = (x1 * x2) ^ ((x2 ^ 1) * x3)

    return R1_NEW, R2_NEW, R3_NEW, output

n3 = 21
n2 = 22
n1 = 21

R1_mask = 0x20010
R2_mask = 0x8002c
R3_mask = 0x200004


def guess(beg, end, num, mask):
    ansn = range(beg, end)

    with open('./output/0', 'rb') as f:
        data = f.read(num)  

    data = ''.join(bin(byte)[2:].zfill(8) for byte in data)

    now = 0
    res = 0
    for i in ansn:
        r = i
        cnt = 0
        for j in range(num * 8):
            r, lastbit = LFSR(r, mask)
            lastbit = str(lastbit)
            cnt += (lastbit == data[j])
        if cnt > now:
            now = cnt
            res = i
            print(now, res)
    return res


def bruteforce2(x, z):
    with open('./output/0', 'rb') as f:
        data = f.read(50)    
        data = ''.join(bin(byte)[2:].zfill(8) for byte in data)

    for y in range(pow(2, n2 - 1), pow(2, n2)):
        R1, R2, R3 = x, y, z
        flag = True
        for i in range(len(data)):
            (R1, R2, R3, out) = Fx1x2x3(R1, R1_mask, R2, R2_mask, R3, R3_mask)
            if str(out) != data[i]:
                flag = False
                break
        if y % 10000 == 0:
            print('now: ', x, y, z)
        if flag:
            print('ans: ', hex(x)[2:], hex(y)[2:], hex(z)[2:])
            break


'''R1 = guess(pow(2, n1 - 1), pow(2, n1), 40, R1_mask)
print(R1)
R3 = guess(pow(2, n3 - 1), pow(2, n3), 40, R3_mask)
print(R3)'''

R1 = 1225459
R3 = 1613986
R2= bruteforce2(R1, R3)
print(R2)


```


### web

#### 来个弹窗
就是个xss，直接一把梭哈

#### 椰子树晕淡水鱼

真正的信息收集，你可以看见藏头诗“文件上传”，然后关于里面是用户名，密码本可以靠dirb扫出来，然后bp开爆，然后是个文件上传，传个png马，然后蚂剑上不去，手打得到flag，在根目录

#### coke的登陆
f12看cookie是密码，账户是coke

其他的忘了过程了

## 总结
2025PolarCTF春季赛质量还好吧，在车上不能认真的去写，有很多琐事缠身，最后rank是12有点可惜吧，毕竟后面几个小时一直没写，wp也懒得写了