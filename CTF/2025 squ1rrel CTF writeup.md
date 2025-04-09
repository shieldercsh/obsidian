
1. deja vu
2. jail!
3. squ1rrel-casino

--- 
# deja vu

```bash
[*] '/mnt/d/squ1rrel/deja vu/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Partial RELRO, No canary, No PIE

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64]; // [rsp+0h] [rbp-40h] BYREF

  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  printf("pwnme: ");
  gets(v4);
  return 0;
}
```

So easy prob. It has `bof` vuln. Even,

```C
int win()
{
  char s[8]; // [rsp+0h] [rbp-70h] BYREF
  __int64 v2; // [rsp+8h] [rbp-68h]
  __int64 v3; // [rsp+10h] [rbp-60h]
  __int64 v4; // [rsp+18h] [rbp-58h]
  __int64 v5; // [rsp+20h] [rbp-50h]
  __int64 v6; // [rsp+28h] [rbp-48h]
  __int64 v7; // [rsp+30h] [rbp-40h]
  __int64 v8; // [rsp+38h] [rbp-38h]
  __int64 v9; // [rsp+40h] [rbp-30h]
  __int64 v10; // [rsp+48h] [rbp-28h]
  __int64 v11; // [rsp+50h] [rbp-20h]
  __int64 v12; // [rsp+58h] [rbp-18h]
  int v13; // [rsp+60h] [rbp-10h]
  FILE *stream; // [rsp+68h] [rbp-8h]

  *(_QWORD *)s = 0LL;
  v2 = 0LL;
  v3 = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0;
  puts("You got it!!");
  stream = fopen("flag.txt", "r");
  if ( !stream )
    return puts("Error: Could not open flag.txt (create this file for testing)");
  fgets(s, 100, stream);
  printf("%s", s);
  return fclose(stream);
}
```

It has `win` function. Do `Return Address Overwrite`(`RAO?`).

