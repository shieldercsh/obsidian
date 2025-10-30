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

## 3. 어파인 변환 중 하나를 택하여 결과 이미지 출력(픽셀 수는 자유롭게

```
% Work 3
Cars = imread('./실습이미지 파일1-2/Cars.jpg');
tform = affine2d([0.05 0 0; 0 0.02 0; 0 0 1]);
J = imwarp(Cars, tform);
imshow(J);
```

![[Pasted image 20251031012446.png]]

## 4. LUT를 만들어서 명암 영상인 cat1.png에 대해 화소 값이 100-150 사이의 픽셀은 0으로 출력한 영상을 제작

```
% Work 4
cat1 = imread('./실습이미지 파일1-2/cat1.png');
F = 0:255;
T = F;
for k = 100:150
    T(k+1)=0;
end
T = uint8(T);
cat1_after = T(cat1 + 1);
imshow(cat1_after);
```

![[Pasted image 20251031013015.png]]

for 문을 이용하여 100-150의 값을 가지는 부분을 0으로 바꿔주면 된다.