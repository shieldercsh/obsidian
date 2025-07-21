2025.07.10에 열린 codegate CTF final에서 8등을 했다. 6등부터 13등까지 4솔인데 나는 3솔로 8등을 차지했다. 쉬운 문제가 4문제 있었는데, 이 문제들은 빨리 풀 수 있을 것 같아 집중력이 좋을 때 pwn에서 잡을 만한 문제를 먼저 풀기로 했다. pwn에서 좋은 점수를 거두지 못하면 쉬운 문제를 풀어봤자 의미가 없기 때문이다.
폰 1번은 5시간에 걸쳐 익스를 마쳤다. 250점 두 개는 각각 1분 컷 냈고, 대회 시간은 12시간이었기 때문에 폰 2번을 풀면 나머지 쉬운 두 문제 중 하나를 풀면 수상권이었다. 하지만 krop까지만 깎고 간 내 실력으로 kernel UAF를 마주하여 수상권에 들지 못했다. 11시간 동안 포기하지 않고 찾아봤지만 당황한 상황에서 긴 영어 블로그를 (짧다면) 짧은 시간 안에 완벽히 이해할 수는 없었다. 나머지 1시간에는 그냥 3솔인 채로 쉬었다. 지금은 풀 수 있지만, 아쉽진 않고 대회 전 부족한 내 공부를 탓하겠다.
쉬운 두 문제는 1분 컷이기 때문에 건너뛰겠다.

# Packet

```C
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  uint16_t v3; // ax
  int v4; // eax
  int optval; // [rsp+1Ch] [rbp-44h] BYREF
  socklen_t addr_len; // [rsp+20h] [rbp-40h] BYREF
  int fd; // [rsp+24h] [rbp-3Ch]
  int v8; // [rsp+28h] [rbp-38h]
  __pid_t v9; // [rsp+2Ch] [rbp-34h]
  sockaddr addr; // [rsp+30h] [rbp-30h] BYREF
  struct sockaddr v11; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v12; // [rsp+58h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  optval = 1;
  addr_len = 16;
  setvbuf(_bss_start, 0LL, 2, 0LL);
  if ( argc != 2 )
  {
    printf("Usage : %s PORT\n", *argv);
    exit(0);
  }
  signal(17, (__sighandler_t)sigchld_handler);
  fd = socket(2, 1, 0);
  setsockopt(fd, 1, 2, &optval, 4u);
  addr.sa_family = 2;
  v3 = atoi(argv[1]);
  *(_WORD *)addr.sa_data = htons(v3);
  *(_DWORD *)&addr.sa_data[2] = 0;
  bind(fd, &addr, 0x10u);
  listen(fd, 5);
  v4 = atoi(argv[1]);
  printf("Server listening on port %d...\n", v4);
  while ( 1 )
  {
    while ( 1 )
    {
      v8 = accept(fd, &v11, &addr_len);
      if ( v8 >= 0 )
        break;
      printf("accept");
    }
    v9 = fork();
    if ( !v9 )
      break;
    if ( v9 <= 0 )
    {
      printf("fork error");
      exit(-1);
    }
    close(v8);
  }
  close(fd);
  puts("Client connected.");
  handle_packet(v8);
}
```

`while` 안에서 `fork`를 수행 중이므로 원하는 만큼 자식 프로세스를 연결할 수 있다. `fork`는 부모 프로세스의 메모리를 그대로 복사하므로 익스에 활용할 부분이 많지만 