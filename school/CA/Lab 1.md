`SimpleAdder`은 ALU에서 덧셈 구현만 해주면 되기 때문에 `io.result := io.inputx + io.inputy` 한 줄만 넣어주면 된다.
`SimpleSystem`에서 실질적인 하드웨어의 구현이 이루어진다. 우선 `adder1`과 `adder2`를 선언하고, 

![[Pasted image 20251005021843.png]]