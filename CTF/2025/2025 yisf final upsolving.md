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

3번의 함수 포인터 실행에 집중하자. 현재 저장되어 있는 `sub_4015AC`은 아무 기능도 안 하지만 `sub_401389`러 ㅂ