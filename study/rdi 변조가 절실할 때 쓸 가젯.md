`system`은 호출할 수 있는데 `rdi`를 `&"/bin/sh\x00"`로 변조할 수 없다면 2차전 시작이다. `rdi`를 변조할 수 있는 방법을 온갖 창의적인 생각과 함께 바이너리에서 찾아내야 한다. 이럴 때 보통 `libc base`는 가지고 있을 테니 쓸만한 가젯 몇 개를 정리해보겠다.

```
0x00000000000984df : mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x380]
0x00000000000af7b5 : mov rdi, qword ptr [rdi + 0x48] ; mov rsi, r12 ; call rax
0x0000000000085fba : mov rdi, qword ptr [rdi + 0xe0] ; call rax
0x0000000000085f7d : mov rdi, qword ptr [rdi + 0xe0] ; jmp rax
0x00000000000a1f47 : mov rdi, qword ptr [rdi + 8] ; call qword ptr [rbx]
```

특히 첫 번째 가젯은 힙에 있는 함수 포인터를 참조하여 실행할 때 쓰기 좋다.