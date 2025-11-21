# Control Unit Overview

`Lab 2`의 `Todo 3`에서 했어야 했던 것이므로 코드를 그대로 가져온다. 우리에게 주어진 `components/control.scala`에서 `regwrite`를 절대 `true` 처리해주지 않는 문제가 있었는데, 이 부분만 잘 작동하도록 구현해주었다.
# Part I: Memory Instructions

`control.scala`에서는 `opcode`에 따라 각 명령어가 필요로 하는 제어 신호를 생성하도록 제어 테이블을 확장하였다. 기존에는 R-type 명령어만 정의되어 있었기 때문에, 테이블을 보고 적절하게 맞춰서 추가해주면 된다. `cpu.scala`에서는 각 제어 신호를 실제 hardware 모듈들과 연결하여 명령어의 동작이 완성되도록 구성하였다. ALU 입력 선택부는 Control Unit의 `alusrc1` 및 `immediate` 신호를 참조하여, ALU의 첫 번째 입력이 rs1, 0, 혹은 PC 중 하나가 되도록 설정하였고, 두 번째 입력은 rs2 또는 즉시값 중 하나를 선택하도록 구현하였다. Load/Store 명령어를 처리하기 위해 데이터 메모리 인터페이스에 주소, 쓰기 데이터, 읽기/쓰기 제어 신호를 연결하였다. 특히 Load 명령어에서 필요한 sign-extend와 zero-extend를 정확히 수행하기 위해, 메모리의 확장 방식과 접근 크기를 funct3를 기반으로 전달하였다. 레지스터 파일의 write-back 경로는 Control Unit의 `toreg` 신호에 따라 ALU 결과, 메모리 읽기값, 또는 PC+4 중 하나를 선택하도록 하였다.

## Part II: Branch Instructions

Part 2에서는 단일 사이클 CPU가 `branch`와 `JAL/JALR` 명령을 올바르게 수행할 수 있도록 제어 신호와 PC 업데이트 경로를 구현해야 했다.
우선 `BranchControl` 모듈에는 이전까지 분기 여부를 판단하는 로직이 전혀 없었기 때문에, RISC-V에서 사용하는 각 분기 명령의 비교 규칙에 따라 두 입력 값의 관계를 판단해 `io.taken` 신호를 출력하도록 구현하였다. 이를 통해 `BEQ, BNE, BLT, BGE`와 같은 signed 비교뿐 아니라 `BLTU, BGEU` 같은 unsigned 비교 명령도 모두 정상적으로 처리할 수 있게 되었다.
`Control` 모듈에서는 `branch 및 jump 명령에 대해 필요한 제어 신호들을 추가하였다. jump 신호는 JAL과 JALR을 구분해 처리할 수 있도록 설정했으며, 점프 명령의 공통적인 특성인 PC+4 값을 목적지 레지스터에 기록하기 위해 toreg를 새롭게 사용했다. 또한 JALR의 경우 rs1과 즉값을 더해야 하므로 immediate 입력을 활성화하도록 하였고, 모든 점프 명령에서 레지스터 갱신이 필요하므로 regwrite도 활성화되도록 처리하였다. 기존에는 PC가 항상 PC+4로 증가하는 구조였기 때문에 분기나 점프가 전혀 동작하지 않는 문제가 있었다. 이를 해결하기 위해 branchAdd를 사용해 branch target 주소를 계산하고, JALR의 목적지 주소는 rs1+imm의 결과를 하위 비트를 0으로 맞춘 형태로 생성하였다. 이후 MUX를 이용하여 jump, jalr, branch 신호를 우선순위에 따라 평가하고, 해당 조건이 없을 때만 PC+4로 진행하도록 설정하였다.
마지막으로, CPU가 올바른 명령어를 가져오도록 하기 위해 instruction memory의 주소 입력을 PC에 연결하는 작업도 필요했다. 이 부분이 빠져 있으면 PC가 변경되더라도 항상 같은 명령만 반복해서 읽어오는 문제가 발생하기 때문에, io.imem.address에 PC를 직접 연결하여 프로그램 카운터가 가리키는 위치의 명령을 읽어오도록 수정하였다.