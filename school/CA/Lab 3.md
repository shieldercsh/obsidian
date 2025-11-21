# Control Unit Overview

`Lab 2`의 `Todo 3`에서 했어야 했던 것이므로 코드를 그대로 가져온다. 우리에게 주어진 `components/control.scala`에서 `regwrite`를 절대 `true` 처리해주지 않는 문제가 있었는데, 이 부분만 잘 작동하도록 구현해주었다.
# Part I: Memory Instructions

`control.scala`에서는 `opcode`에 따라 각 명령어가 필요로 하는 제어 신호를 생성하도록 제어 테이블을 확장하였다. 기존에는 R-type 명령어만 정의되어 있었기 때문에, 본 실험에서는 다음 명령어들을 추가하였다.