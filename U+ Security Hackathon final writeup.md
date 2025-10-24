작성자 : 조수호(shielder)

## pwn / playlist

```C
unsigned __int64 create()
{
  int i; // [rsp+0h] [rbp-120h]
  int v2; // [rsp+4h] [rbp-11Ch]
  int v3; // [rsp+4h] [rbp-11Ch]
  char *dest; // [rsp+8h] [rbp-118h]
  char s[128]; // [rsp+10h] [rbp-110h] BYREF
  char buf[136]; // [rsp+90h] [rbp-90h] BYREF
  unsigned __int64 v7; // [rsp+118h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  if ( song_len <= 63 )
  {
    memset(s, 0, sizeof(s));
    memset(buf, 0, 0x80uLL);
    printf("Enter song name: ");
    v2 = read(0, buf, 0x80uLL);
    if ( buf[v2 - 1] == 10 )
      buf[v2 - 1] = 0;
    printf("Enter artist: ");
    v3 = read(0, s, 0x80uLL);
    if ( s[v3 - 1] == 10 )
      s[v3 - 1] = 0;
    if ( buf[0] && s[0] )
    {
      dest = (char *)malloc(0x100uLL);
      if ( dest )
      {
        strcpy(dest, buf);
        strcpy(dest + 128, s);
        for ( i = 0; i <= 63; ++i )
        {
          if ( !song_chunk[i + 8] )
          {
            song_chunk[i + 8] = (__int64)dest;
            break;
          }
        }
        ++song_len;
        puts("Song added to playlist!");
      }
      else
      {
        puts("Memory allocation failed!");
      }
    }
    else
    {
      puts("Invalid input!");
    }
  }
  else
  {
    puts("Playlist is full!");
  }
  return v7 - __readfsqword(0x28u);
}
```

`create`의 `strcpy`에서 힙 오버플로우가 발생한다. 이를 이용해서 size 조작을 할 수 있고, 서로 다른 unsorted bin이 두 개 있으면