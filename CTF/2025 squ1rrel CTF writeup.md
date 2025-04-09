
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

