처음 주어지는 사진 파일을 HxD로 열어보니 여러 PNG 파일이 나열되어 있음을 알 수 있었다. 따라서 이를 파이썬 코드를 사용하여 분리한다.

```python
import binascii

def hex_to_binary(hex_str):
    # 공백과 줄바꿈 제거
    hex_str = ''.join(hex_str.split())
    # hex를 바이너리로 변환
    return binascii.unhexlify(hex_str)

def find_png_files(binary_data):
    # PNG 시그니처와 IEND 청크를 찾아 파일 분리
    png_signature = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
    iend_chunk = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
    
    png_files = []
    start_pos = 0
    
    while True:
        # PNG 시그니처 찾기
        start_pos = binary_data.find(png_signature, start_pos)
        if start_pos == -1:
            break
            
        # IEND 청크 찾기
        end_pos = binary_data.find(iend_chunk, start_pos) + 8
        if end_pos == 7:  # IEND를 찾지 못한 경우
            break
            
        # PNG 파일 추출
        png_data = binary_data[start_pos:end_pos]
        png_files.append(png_data)
        
        start_pos = end_pos
        
    return png_files

def save_png_files(png_files):
    # 추출된 PNG 파일들을 저장
    for i, png_data in enumerate(png_files):
        with open(f'extracted_{i}.png', 'wb') as f:
            f.write(png_data)
        print(f'Saved extracted_{i}.png')

def main():
    # Hex 문자열을 읽어오기 (여기서는 hex_data 변수에 hex 문자열이 있다고 가정)
    with open('paste.txt', 'r') as f:
        hex_data = f.read()
    
    # Hex를 바이너리로 변환
    binary_data = hex_to_binary(hex_data)
    
    # PNG 파일들 찾기
    png_files = find_png_files(binary_data)
    
    print(f'Found {len(png_files)} PNG files')
    
    # PNG 파일들 저장
    save_png_files(png_files)

if __name__ == '__main__':
    main()
```

위 코드를 돌리면 0번이 깨져 나오고 1, 2, 3번은 QR코드가 1/4로 쪼개져서 나온다. 0번 사진의 파일이 제대로 분리되지 않아 손수 다시 만들어줬다.

```python
from PIL import Image
import numpy as np

def combine_qr_images():
    # 새로운 이미지 생성 (가로 2개, 세로 2개로 배치)
    target = Image.new('RGB', (330, 330), 'white')
    
    # 4개의 부분 이미지를 올바른 위치에 배치
    positions = [
        (0, 0),        # 좌측 상단
        (165, 0),      # 우측 상단
        (0, 165),      # 좌측 하단
        (165, 165)     # 우측 하단
    ]
    
    # 각 부분 이미지를 해당 위치에 붙여넣기
    for i, pos in enumerate(positions, 1):
        part = Image.open(f'extracted_{i - 1}.png')
        target.paste(part, pos)
    
    # 결과 저장
    target.save('complete_qr.png')
    print("QR code has been combined")

combine_qr_images()
```

위 코드를 통해 QR코드를 완성했으며, QR코드를 인식하니 flag가 나타났다.

`scpCTF{Co113cT_d1V1d3d_QRc0d3}`