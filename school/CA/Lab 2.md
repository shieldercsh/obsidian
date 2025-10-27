# Todo 1

ppt에 주어진 `opcode map`과 `riscv_format`을 바탕으로 `func3`, `func7`을 따진다. `if`문을 계속 쓰는 것보다 `switch`문을 사용하는 것이 적절하다고 생각하여 이로 진행하였다.
![[Pasted image 20251027145338.png]]

# Todo 2

중간고사 공부할 때 그린 `single-cycle cpu` 그림으로 대체하겠습니다.
![[KakaoTalk_20251020_013221328.png]]

# Todo 3

`components/control.scala`를 읽으면 `opcode`를 `control.io.opcode`에 연결해야 함을 알 수 있다. `components/register-file.scala`를 읽고 `rs1, rs2, rd`를 잘 연결해준다. `components/control.scala`를 읽으면 `opcode`를 `control.io.opcode`에 연결해야 함을 알 수 있다.

![[Pasted image 20251027181323.png]]