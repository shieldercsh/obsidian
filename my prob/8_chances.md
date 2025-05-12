# 8_chances

# Concept

- sql injection
- mariadb

# Writeup

####  chall.py

```python
from Crypto.Util.number import *
import random

class DSA:
    def __init__(self):
        while True:
            self.q = getPrime(160)
            r = random.randrange(1 << 863, 1 << 864)
            self.p = self.q * r + 1
            if self.p.bit_length() != 1024 or isPrime(self.p) != True:
                continue
            h = random.randrange(2, self.p - 1)
            self.g = pow(h, r, self.p)
            if self.g == 1:
                continue
            self.x = random.randrange(1, self.q)
            self.y = pow(self.g, self.x, self.p)
            break

    def sign(self, h):
        k = random.randrange(1, self.q)
        r = pow(self.g, k, self.p)
        s = inverse(k, self.q) * (h + self.x * r) % self.q
        return (r, s)

    def verify(self, h, sig):
        r, s = sig
        if s == 0:
            return False
        s_inv = inverse(s, self.q)
        e1 = h * s_inv % self.q
        e2 = r * s_inv % self.q
        r_ = pow(self.g, e1, self.p) * pow(self.y, e2, self.p) % self.p
        if r_ == r:
            return True
        else:
            return False

flag = "hspace{}"

dsa = DSA()
h0 = random.randrange(1, dsa.q)
r, s = dsa.sign(h0)
print(f"h = {h0}")
print(f"p = {dsa.p}")
print(f"q = {dsa.q}")
print(f"g = {dsa.g}")
print(f"y = {dsa.y}")
print(f"r = {r}")
print(f"s = {s}")

h = int(input("h = "))
r = int(input("r = "))
s = int(input("s = "))

if dsa.verify(h, [r, s]) and (h0 - h) % dsa.q != 0:
    print(flag)
else:
    print("I knew DSA was safe.")
```

실제 DSA와 몇 가지 차이점이 존재합니다

1. `h = hash(m)`의 과정을 거치지 않고, 바로 `m` 자체가 `h`의 역할을 수행합니다.
2. sign, verify 과정에서 `r`을 계산할 때 `p`로 나눈 나머지를 계산한 후 `q`에 대한 나머지를 계산하지 않습니다.

목표는 특정 `h0`에 대한 서명이 알려져 있을 때, 다른 `h`에 대한 서명을 생성하는 것입니다. 입력받는 `h`에 범위 제한이 있어, `h0`에 `q`를 더하고 빼는 방법으로는 해결할 수 없습니다.

$g^{\frac{h_0 + xr_0}{s_0}} \equiv r_0 \pmod p$ 이라는 식으로부터 시작하겠습니다.

양변에 $g$를 곱해주면 다음과 같습니다. 몇 번 곱해주든 상관없지만, 1회 곱하겠습니다.

$$g^{\frac{h_0 + xr_0}{s_0} + 1} \equiv gr_0 \pmod p$$

새로 사용할 $r = gr_0 \mod p$로 정의하겠습니다. $p$로 나눈 나머지를 설정하지 않으면 $g$의 pow 연산 후의 결과가 $p$보다 클 수 없기 때문에 검증에 실패합니다.

이제 좌변의 지수를 식의 꼴에 맞게 변형해주겠습니다.

$$\frac{h_0 + xr_0}{s_0} + 1 \equiv \frac{h_0 + s_0 + xr_0}{s_0} \equiv \frac{r(h_0 + s_0)/r_0 + xr}{rs_0/r_0} \pmod q$$

새로 생성한 $r$은 $q$를 법으로 기존과 전혀 다른 수이기 때문에 이렇게 수동으로 값을 나누어주어야 합니다.

$$h = r(h_0 + s_0)/r_0, s = rs_0/r_0$$
이와 같이 새 $r, h, s$를 정의하면 해결할 수 있습니다.


#### ex.py
```python
from pwn import *

io = process(["python3", "chall.py"])

def recv():
    io.recvuntil(b" = ")
    return int(io.recvline())

h, p, q, g, y, r, s = [recv() for _ in range(7)]

r_ = (g * r) % p
h_ = ((s + h) * r_ * pow(r, -1, q)) % q
s_ = (s * r_ * pow(r, -1, q)) % q

io.sendlineafter(b"h = ", str(h_).encode())
io.sendlineafter(b"r = ", str(r_).encode())
io.sendlineafter(b"s = ", str(s_).encode())

io.interactive()

```

다른 여러 h값에 대한 서명도 생성 가능합니다.