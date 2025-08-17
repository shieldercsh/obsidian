![[Pasted image 20250817185028.png]]

예선 1등으로 본선에 간다. 청소년부에 폰은 총 6문제 출제되었다. (Heapappy : 250, book : 487, Artisan : 86, Chain : 962, Time Capsule : 962, MyBlog : 1000(0 Solve)) 대회 진행 중 마지막 문제를 제외한 5문제를 풀었다. MyBlog도 조금만 집중하면 풀 수 있었을 거 같은데 커널 문제를 풀 때 조건을 제대로 확인하지 않아서 두 시간을 날리기도 했고, 우리 팀 리버서도 나를 도와줄 정신 상태가 아니어서 깔끔하게 접고 쉬었다. 각설하고 풀이를 적어보겠다.

---
## 목차

1. Heapappy
2. book
3. Artisan
4. Chain
5. Time Capsule

---

# Heapappy

```bash
[*] '/mnt/d/cce/qual/Heapappy/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

PIE가 꺼져 있고 Partial RELRO이다.

```C
unsigned __int64 prompt()
{
  unsigned __int64 v1; // [rsp+0h] [rbp-40h]
  char nptr[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = 0LL;
  printf("Choice: ");
  while ( v1 <= 0x1E && fread(&nptr[v1], 1uLL, 1uLL, stdin) == 1 )
  {
    if ( nptr[v1] == 10 )
    {
      nptr[v1] = 0;
      break;
    }
    ++v1;
  }
  nptr[v1] = 0;
  return strtoul(nptr, 0LL, 10);
}

int adopt()
{
  __int64 v1; // [rsp+0h] [rbp-10h]

  if ( pet )
    return puts("Already adopted.");
  pet = malloc(0x28uLL);
  if ( !pet )
    exit(1);
  memset(pet, 0, 0x28uLL);
  *((_DWORD *)pet + 6) = 0;
  *((_QWORD *)pet + 4) = act_tutorial;
  printf("Name length: ");
  v1 = prompt();
  if ( v1 > 24 )
    return puts("Name too long.");
  printf("Name bytes: ");
  input((__int64)pet, v1);
  return puts("Adopted.");
}
```

