## pwn

### kvdb

```c
struct VarDyn // sizeof=0x10
00000000 {                                       // XREF: Variant::$B24CBE35B6509F7A0727794E4B7DDDE2/r
00000000     unsigned __int64 len;
00000008     char *ptr;
00000010 };

00000000 struct Node // sizeof=0x18
00000000 {
00000000     unsigned __int64 key;
00000008     struct Variant *val;
00000010     struct Node *next;
00000018 };

00000000 struct KVTable // sizeof=0x10
00000000 {
00000000     struct Node **buckets;
00000008     unsigned __int64 nbuckets;
00000010 };

00000000 union Variant::$B24CBE35B6509F7A0727794E4B7DDDE2 // sizeof=0x100
00000000 {                                       // XREF: Variant/r
00000000     unsigned __int64 number;
00000000     struct VarDyn dyn;
00000000     char str[256];
00000000 };

00000000 struct Variant // sizeof=0x108
00000000 {
00000000     union Variant::$B24CBE35B6509F7A0727794E4B7DDDE2 v;
00000100     unsigned __int8 tag;
00000101     unsigned __int8 _pad[7];
00000108 };
```

구조체를 위와 같이 정의할 수 있다. 중요한 것은 `Variant` 함수에서 0x100 만큼을 차지하는 `union Variant::$B24CBE35B6509F7A0727794E4B7DDDE2 v;`이다. edit -> fixed string에서 입력을 257바이트 받기 때문에 1바이트 overflow가 발생해서 `tag`를 변경할 수 있다. pie가 꺼져 있기 때문에 dynamic으로 해석할 때의 size와 주소를 변조하고 dynamic으로 tag를 변경하면 libc를 긁을 수 있고, 그 뒤에 같은 방식으로 변조해서 FSOP한다.

# 