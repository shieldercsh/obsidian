# Rev / Unknown Virt

### 분석

대회 때는 cursor 깔짝대고 안 풀려서 손 안 댔는데, 정연산이 꽤나 쉽고 깔끔하다. 정연산 먼저 파악 후 역연산 짜주면 된다.

정연산 어셈 해석
```
0x0 : reg[0] = 1
0x3 : reg[1] = 2
0x6 : reg[1] <<= 8
0x9 : reg[0] |= reg[1]
0xc : reg[4] = a1[reg[0]]
0xf : reg[5] = 64
0x12 : flag = (reg[4] == reg[5])
0x15 :
    if self.flag != 0 :
        if 0 != 0 : pc = 66
        else : pc = 0x2042
    else : pc += 4
jump
0x19 : reg[3] = reg[4]
0x1c : flag = (reg[3] == reg[5])
0x1f :
    if self.flag != 0 :
        if 0 != 0 : pc = 66
        else : pc = 0x2042
    else : pc += 4
jump
0x23 : reg[0] = 0
0x26 : reg[1] = 0
0x29 : reg[1] <<= 8
0x2c : reg[0] |= reg[1]
0x2f : reg[0] += reg[3]
0x32 : reg[1] = 170
0x35 : a1[reg[0]] = reg[1]
0x38 : reg[0] = 1
0x3b : reg[3] += reg[0]
0x3e :
    if 0 != 0 : pc = 28
    else : pc = 0x201c
jump // input 64 만들기 0xaa 입력함
0x42 : reg[3] = 0
0x45 : flag = (reg[3] == reg[5])
0x48 :
    if self.flag != 0 :
        if 0 != 0 : pc = 211
        else : pc = 0x20d3
    else : pc += 4
jump
0x4c : reg[0] = 0
0x4f : reg[1] = 0
0x52 : reg[1] <<= 8
0x55 : reg[0] |= reg[1]
0x58 : reg[0] += reg[3] // idx
0x5b : reg[6] = a1[reg[0]]  // input[idx]
0x5e : reg[0] = 13
0x61 : reg[1] = reg[3] // idx
0x64 : reg[0] *= reg[1] // 13 * idx
0x67 : reg[1] = 7
0x6a : reg[0] += reg[1] // (13 * idx) + 7
0x6d : reg[1] = 255
0x70 : reg[0] &= reg[1] // ((13 * idx) + 7) & 0xff
0x73 : reg[2] = reg[0]
0x76 : reg[0] = reg[3]
0x79 : reg[1] = 7
0x7c : reg[0] %= reg[1] // (idx % 7)
0x7f : reg[1] = 1
0x82 : reg[0] += reg[1] // (idx % 7) + 1
0x85 : reg[1] = reg[0]
0x88 : reg[0] = reg[6]
0x8b : reg[0] = f1(reg[0], reg[1]) // f1(input[idx], (idx % 7) + 1)
0x8e : reg[0] ^= reg[2] // f1(input[idx], (idx % 7) + 1) ^ (((13 * idx) + 7) & 0xff)
0x91 : reg[1] = 42
0x94 : reg[0] += reg[1] // (f1(input[idx], (idx % 7) + 1) ^ (((13 * idx) + 7) & 0xff)) + 42
0x97 : reg[1] = 255
0x9a : reg[0] &= reg[1] // ((f1(input[idx], (idx % 7) + 1) ^ (((13 * idx) + 7) & 0xff)) + 42) & 0xff
0x9d : reg[1] = 0
0xa0 : reg[2] = 1
0xa3 : reg[2] <<= 8
0xa6 : reg[1] |= reg[2]
0xa9 : reg[1] += reg[3]
0xac : reg[1] = a1[reg[1]]
0xaf : flag = (reg[0] == reg[1])
0xb2 :
    if self.flag == 0 :
        if 0 != 0 : pc = 192
        else : pc = 0x20c0
    else : pc += 4
jump
0xb6 : reg[0] = 1
0xb9 : reg[3] += reg[0]
0xbc :
    if 0 != 0 : pc = 69
    else : pc = 0x2045
jump
0xc0 : reg[0] = 0
0xc3 : reg[1] = 0
0xc6 : reg[2] = 2
0xc9 : reg[2] <<= 8
0xcc : reg[1] |= reg[2]
0xcf : a1[reg[1]] = reg[0]
0xd2 : 0, what?
0xd3 : reg[0] = 1
0xd6 : reg[1] = 0
0xd9 : reg[2] = 2
0xdc : reg[2] <<= 8
0xdf : reg[1] |= reg[2]
0xe2 : a1[reg[1]] = reg[0]
```

`input` 배열을 `0x40` 길이로 만들고 정해진 알고리즘을 적용하여 한 글자씩 비교하는 모습이다.
### ex.py

```python
ans = open('./prob', 'rb').read()[0x5020:0x5020+64]

def f1(a1, a2):
    return ((a1 >> (a2 & 7)) | (a1 << (8 - (a2 & 7))))
# ((f1(input[idx], (idx % 7) + 1) ^ (((13 * idx) + 7) & 0xff)) + 42) & 0xff
flag = b''
print(hex(((f1(ord('c'), (0 % 7) + 1) ^ (((13 * 0) + 7) & 0xff)) + 42) & 0xff))
for i in range(len(ans)):
    a = (ans[i] - 42) & 0xff
    a ^= (((13 * i) + 7) & 0xff)
    a = f1(a, 8 - ((i % 7) + 1)) & 0xff
    flag += bytes([a])
print(flag)
```

# bkernel

### 보호기법

```bash
qemu-system-x86_64 \
  -kernel bzImage \
  -initrd $1 \
  -nographic \
  -append "console=ttyS0 quiet loglevel=3 oops=panic pti=on kaslr" \
  -m 128M \
  -cpu kvm64,+smep,+smap,rdrand \
  -monitor /dev/null \
  -no-reboot
```
`smep, smap, kaslr, pti`가 걸려있다.

### 익스 계획

전형적인 `note chall`이다. `free`에 `UAF` 취약점이 있고, `read, write` 기능ㅇ ㅣ모