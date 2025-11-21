# Control Unit Overview

`Lab 2`의 `Todo 3`에서 했어야 했던 것이므로 코드를 그대로 가져온다. 우리에게 주어진 `components/control.scala`에서 `regwrite`를 절대 `true` 처리해주지 않는 문제가 있었는데, 이 부분만 잘 작동하도록 구현해주었다.
# Part I: Memory Instructions

`control.scala`에서는 `opcode`에 따라 각 명령어가 필요로 하는 제어 신호를 생성하도록 제어 테이블을 확장하였다. 기존에는 R-type 명령어만 정의되어 있었기 때문에, 테이블을 보고 적절하게 맞춰서 추가해주면 된다. `cpu.scala`에서는 각 제어 신호를 실제 hardware 모듈들과 연결하여 명령어의 동작이 완성되도록 구성하였다. ALU 입력 선택부는 Control Unit의 `alusrc1` 및 `immediate` 신호를 참조하여, ALU의 첫 번째 입력이 rs1, 0, 혹은 PC 중 하나가 되도록 설정하였고, 두 번째 입력은 rs2 또는 즉시값 중 하나를 선택하도록 구현하였다. Load/Store 명령어를 처리하기 위해 데이터 메모리 인터페이스에 주소, 쓰기 데이터, 읽기/쓰기 제어 신호를 연결하였다. 특히 Load 명령어에서 필요한 sign-extend와 zero-extend를 정확히 수행하기 위해, 메모리의 확장 방식과 접근 크기를 funct3를 기반으로 전달하였다. 레지스터 파일의 write-back 경로는 Control Unit의 `toreg` 신호에 따라 ALU 결과, 메모리 읽기값, 또는 PC+4 중 하나를 선택하도록 하였다.