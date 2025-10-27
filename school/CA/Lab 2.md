# Todo 1

ppt에 주어진 `opcode map`과 `riscv_format`을 바탕으로 `func3`, `func7`을 따진다. `if`문을 계속 쓰는 것보다 `switch`문을 사용하는 것이 적절하다고 생각하여 이로 진행하였다.
![[Pasted image 20251027145338.png]]

# Todo 2

중간고사 공부할 때 그린 `single-cycle cpu` 그림으로 대체하겠습니다.
![[KakaoTalk_20251020_013221328.png|300]]
# Todo 3

`components/control.scala`를 읽으면 `opcode`를 `control.io.opcode`에 연결해야 함을 알 수 있다. `components/register-file.scala`를 읽고 `rs1, rs2, rd`를 잘 연결해준다. 우리가 작성한 `components/alucontrol.scala`에 따라 `func7, func3`을 연결해주고 `add, immediate`는 가정에 따라 `false`로 처리한다. `alu`는 과제 1과 작동 방법이 같은데, `components/alu.scala`에 따라 `operation`을 연결해준다. `Write-Back` 단계와 `PC` 증가도 구현해주면 끝이다.
이를 수행하는 과정에서 오류가 두 가지 발생했다. 첫 번째는 컴파일 단계에서 `registers` 모듈이 이상하게 처리되어서 제대로 실행이 안 되었는데, 이는 `dontTouch(registers.regs)`을 추가하여 해결할 수 있다. 두 번쨰는 우리에게 주어진 `components/control.scala`에서 `regwrite`를 절대 `true` 처리해주지 않는 문제가 있었는데, 이 부분만 잘 작동하도록 조금 구현해주어 해결하였다.

![[Pasted image 20251027181323.png]]

# Todo 4

`Todo 3`에서 구현을 다 해놨기 때문에 크게 바꿔줄 것은 없다. 하지만 그대로 돌렸을 때 `add0`에서 실패가 뜨는데, 이것은 원래 `RISC-V`에서 `x0`는 항상 0인 값을 가져야 하는데 그걸 구현하지 않았기 때문이다. 따라서 `register.io.wen`에 ` && (registers.io.writereg =/= 0.U)`을 추가하면 된다.
디버깅 로그 출력은 
```
printf(p"Write Reg index : ${registers.io.writereg}, Write value : ${alu.io.result}, Wen Signal : ${registers.io.wen}\n")
```
를 이용하였다. 아래에는 마지막 테스트 케이스에 대한 로그 출력과 함께 성공 장면을 찍은 것이다.

![[Pasted image 20251027191034.png|300]]![[Pasted image 20251027191638.png|300]]
