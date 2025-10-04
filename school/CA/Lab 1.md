`SimpleAdder`은 ALU에서 덧셈 구현만 해주면 되기 때문에 `io.result := io.inputx + io.inputy` 한 줄만 넣어주면 된다.
`SimpleSystem`에서 실질적인 하드웨어의 구현이 이루어진다. 우선 `adder1`과 `adder2`를 선언한다. `adder1`의 두 입력값은 `reg1`, `reg2`이고, `adder2`의 두 입력값은 `adder1.io.result, 3`이다. `io.success`는 `adder2.io.result`와 128을 비교한 값이 True면 1, False면 0으로 설정하는 `Mux`를 사용하면 된다.(사실 보통 True를 1, False를 0으로 받아들이기 때문에 `Mux`를 사용하지 않아도 괜찮다고 생각한다. 하만 이론적으로 True는 0을 제외한 모든 값으로 해석되므로 정확히 의도된 값을 도출해내기 위함도 있고, 하드웨어 그림에서도 `Mux`를 사용하고 있어서 코드에서 사용하였다.) 그리고 `reg1`은 `adder1.io.result`로, `reg2`는 `adder2.io.result`로 업데이트된다.

이 때 `reg2 := adder2.io.result`인데 왜 `reg2`가 64일 때 `success`가 1인지 도저히 이해가 안 되서 카운터 레지스터 `i`를 추가하여 출력하였다. 그 결과 한 클럭이 끝나고 상태가 모두 업데이트된 후에 출력이 이루어짐을 알 수 있었다.
근데 그러면 ```reg2가 128일 때 success가 1이어야 하는 게 아닌가```라는 의문이 든다. 이는 `adder`의 작동을 생가

![[Pasted image 20251005021843.png]]