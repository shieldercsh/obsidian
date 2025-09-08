pwn을 하면서 `libc` 주소를 알아내고 `ld` 영역을 overwrite해야 하는 경우가 심심치 않게 있다. 그럴 때마다 로컬과 리모트의 `libc, ld` offset이 달라서 `i * 0x1000`으로 브포를 돌리는 것이 인텐으로 자리 잡고 있다. 나의 경우 c++ binary 익스에서 exit handler overwrite를 하는데 브포를 돌려도 익스가 안 되는 것이다. 그래서 한참 헤매다가 이 방법을 발견하고 offset을 확인해보니 꽤 멀리 떨어져 있었다. 이 글을 읽는 포너들은 앞으로 브포하지 말고 도커에서 한 번에 offset을 구하길 바란다.

- 준비물 : Dockerfile

1. docker에서 `ls /proc`을 친다.
2. `nc localhost {port}`를 실행한 후 `ls /proc`을 쳐서 1번에서 없던 pid를 찾는다.
3. `cat /proc/{pid}/maps`