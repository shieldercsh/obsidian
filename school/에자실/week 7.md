## 1. 다음두영상(Grim1.jpg, Grim2.jpg)에대한다른그림찾기에서변화영 역을감지

```
% Work 1
Grim1 = imread('./실습이미지 파일1-2/Grim1.jpg');
Grim2 = imread('./실습이미지 파일1-2/Grim2.jpg');
Grim_diff = Grim1 - Grim2;
imshow(Grim_diff);
```

![[Pasted image 20251031011355.png]]
틀린그림찾기이므로 뺄셈을 통해 알아낼 수 있다.

## 2. 두이미지와연산을활용해금연표시를제작(Prohibit.png, Dambe.png)

```
% Work 2
Prohibit = double(imread('./실습이미지 파일1-2/Prohibit.png'));
Dambe = double(imread('./실습이미지 파일1-2/Dambe.PNG'));
No_Dambe = mat2gray(Prohibit.*Dambe);
imshow(No_Dambe);
```

