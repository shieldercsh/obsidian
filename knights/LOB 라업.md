### 조수호(shielder)

### 목차
1. Write-up (6-10)
   - Chapter6
   - Chapter7
   - Chapter8
   - Chapter9
   - Chapter10
2. 피드백
3. 마무리

안녕하세요, HSPACE 나이츠에서 활동중인 조수호(shielder)입니다. 본 글에서는 앞선 글에 이어 [Space Alone](https://github.com/hspace-io/HSPACE-LOB) Chapter6 ~ Chapter10를 풀어보겠습니다.

---
## Write-up

### Chapter6

- 보호기법 분석

```bash
Crisis_at_the_Vault@hsapce-io:~$ checksec prob
[*] '/home/Crisis_at_the_Vault/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

`Partial RELRO` 상태입니다. 카나리가 있고, `PIE`가 꺼져 있습니다.

- 코드 분석
```C
#include <stdio.h>

void menu(){
    puts("1. read diary");
    puts("2. write diary");
    puts("3. put down the diary");
    printf("> ");
}

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    int ch, index = 0;
    char page1[] = "As soon as I arrived here, I locked the door tightly.\nCatching my breath, it feels like a miracle that I managed to escape safely.";
    char page2[] = "Looking around, there isn't much food left.\nTo survive, I'll have to go out again soon.";
    char page3[] = "I checked my weapons and packed the necessary supplies in my bag.\nAccording to rumors I heard outside, there's a vaccine at a nearby lab.";
    char page4[] = "As I headed out, I could hear the zombies' cries.\nMy heart was pounding wildly, but I moved quietly.";
    char page5[] = "At that moment, a zombie suddenly attacked me.\nAs I checked the bite wound on my arm, I realized that the vaccine at the lab was now my last hope.";
    char hidden[] = "Failed, failed, failed, failed, failed, faile... itchy, tasty";
    char* diary[] = {page1, page2, page3, page4, page5, hidden};\

	중략(출력 부분)

    while(1){
        menu();
        scanf("%d", &ch);
        if (ch == 1){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            puts(diary[index]);
        }
        else if (ch == 2){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            printf("content > ");
            read(0, diary[index], 0x100);
        }
        else if (ch == 3){
            break;
        }
    }
    puts("Ok let's go!");
    return 0;
```

2번 메뉴에서 `0x100` 바이트만큼 쓸 수 있습니다. 그런데 `page1, page2, page3, page4, page5, hidden`을 보니 `0x100` 바이트보다 적은 길이를 가지고 있어보입니다. `scp` 명령어로 파일을 꺼내 `ida`로 이어서 분석하겠습니다.

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+8h] [rbp-308h] BYREF
  unsigned int v5; // [rsp+Ch] [rbp-304h] BYREF
  char *s[6]; // [rsp+10h] [rbp-300h]
  char v7[64]; // [rsp+40h] [rbp-2D0h] BYREF
  char v8[96]; // [rsp+80h] [rbp-290h] BYREF
  char v9[112]; // [rsp+E0h] [rbp-230h] BYREF
  char v10[144]; // [rsp+150h] [rbp-1C0h] BYREF
  char v11[144]; // [rsp+1E0h] [rbp-130h] BYREF
  char v12[152]; // [rsp+270h] [rbp-A0h] BYREF
  unsigned __int64 v13; // [rsp+308h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  v5 = 0;
  strcpy(
    v10,
    "As soon as I arrived here, I locked the door tightly.\n"
    "Catching my breath, it feels like a miracle that I managed to escape safely.");
  strcpy(v8, "Looking around, there isn't much food left.\nTo survive, I'll have to go out again soon.");
  strcpy(
    v11,
    "I checked my weapons and packed the necessary supplies in my bag.\n"
    "According to rumors I heard outside, there's a vaccine at a nearby lab.");
  strcpy(v9, "As I headed out, I could hear the zombies' cries.\nMy heart was pounding wildly, but I moved quietly.");
  strcpy(
    v12,
    "At that moment, a zombie suddenly attacked me.\n"
    "As I checked the bite wound on my arm, I realized that the vaccine at the lab was now my last hope.");
  strcpy(v7, "Failed, failed, failed, failed, failed, faile... itchy, tasty");
  s[0] = v10;
  s[1] = v8;
  s[2] = v11;
  s[3] = v9;
  s[4] = v12;
  s[5] = v7;

후략
```

위의 코드와 비교해보면 `v12`가 `page5`와 같음을 알 수 있습니다. `v12`는 `rbp-0xa0`에 정의되어 있으므로 `bof`가 발생합니다.

- 익스 계획 
## 피드백

5장과 6장이 매우 유사한데 둘 다 넣을 필요가 있나
심지어 5장에 canary있는데 태그에 안 적혀있음

