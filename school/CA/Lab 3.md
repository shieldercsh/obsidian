# Control Unit Overview

`Lab 2`의 `Todo 3`에서 했어야 했던 것이므로 코드를 그대로 가져온다. 우리에게 주어진 `components/control.scala`에서 `regwrite`를 절대 `true` 처리해주지 않는 문제가 있었는데, 이 부분만 잘 작동하도록 구현해주었다.
# Todo 4

`Todo 3`에서 구현을 다 해놨기 때문에 크게 바꿔줄 것은 없다. 하지만 그대로 돌렸을 때 `add0`에서 실패가 뜨는데, 이것은 원래 `RISC-V`에서 `x0`는 항상 0인 값을 가져야 하는데 그걸 구현하지 않았기 때문이다. 따라서 `register.io.wen`에 ` && (registers.io.writereg =/= 0.U)`을 추가하면 된다.
디버깅 로그 출력은 
```
printf(p"Write Reg index : ${registers.io.writereg}, Write value : ${alu.io.result}, Wen Signal : ${registers.io.wen}\n")
```
를 이용하였다. 아래에는 마지막 테스트 케이스에 대한 로그 출력과 함께 성공 장면을 찍은 것이다.

![[Pasted image 20251027191034.png|300]]![[Pasted image 20251027191638.png|300]]
