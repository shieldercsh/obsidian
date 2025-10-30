## 1. 다음 두 영상(Grim1.jpg, Grim2.jpg)에 대한 다른 그림 찾기에서 변화 영역을 감지

```
% Work 1
Grim1 = imread('./실습이미지 파일1-2/Grim1.jpg');
Grim2 = imread('./실습이미지 파일1-2/Grim2.jpg');
Grim_diff = Grim1 - Grim2;
imshow(Grim_diff);
```

![[Pasted image 20251031011355.png]]
틀린그림찾기이므로 뺄셈을 통해 알아낼 수 있다.

## 2. 두 이미지와 연산을 활용해 금연 표시를 제작(Prohibit.png, Dambe.png)

```
% Work 2
Prohibit = double(imread('./실습이미지 파일1-2/Prohibit.png'));
Dambe = double(imread('./실습이미지 파일1-2/Dambe.PNG'));
No_Dambe = mat2gray(Prohibit.*Dambe);
imshow(No_Dambe);
```

![[Pasted image 20251031011930.png]]

곱하기를 통해서 자연스럽게 합칠 수 있다.

## 3. 어파인 변환 중 하나를 택하여 결과이미지출력(픽셀수는자유롭게