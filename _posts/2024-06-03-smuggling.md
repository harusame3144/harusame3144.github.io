---
layout: post
category: [wargame, web]
title: Smuggling
---

## [문제](https://h4ckingga.me/challenges#Smuggling-15)


## 문제 분석

문제 웹페이지 사진   
![main](/assets/img/2024-06-03-smuggling/main.png)

다양한 엔드포인트를 Bruteforce(?) 해보았으나 전부 404 오류가 발생하였다.. ``/admin`` ``/dashboard`` ``/login`` 등...

서버는 gunicorn을 사용한다는 것을 알 수 있었다.   
![gunicorn](/assets/img/2024-06-03-smuggling/server_info.png)

일단 문제에 주어진 서버 파일을 살펴보았다.

```py
# main.py
from flask import Flask

app = Flask(__name__)

flag = open("FLAG").read()

@app.route('/', methods=['GET', 'POST'])
def main():
    return 'Hello! Our Team is TeamH4C'

@app.route('/guest', methods=['GET', 'POST'])
def guest():
    return 'ref. jfrog'

@app.route('/flag', methods=['GET', 'POST'])
def get_flag():
	return flag


if __name__ == '__main__':
    app.run()
```

엔드포인트는 3개로 ``/guest`` ``/flag`` 가 있는 걸 확인할 수 있었다.

``/flag`` 엔드포인트에 접속해보았다.

![403](/assets/img/2024-06-03-smuggling/forbidden.png)

서버 소스에는 403 에러가 발생하는 부분이 없으나, ``/flag`` 엔드포인트에 접속하면 403 에러로 접근을 거부하고 있는 것을 알 수 있다.

서버 코드가 너무 심플한데.... 서버에서 403을 일으키진 않는 것 같아 문제 파일을 조금 더 살펴보았다.

```yaml
# docker-compose.yaml
version: '3.7'
services:
  web:
    image: haproxy:2.2.16
    volumes:
      - ./config:/usr/local/etc/haproxy
    ports:
      - "10008:8000"
  flask:
    build: .
```

이 파이썬 앱은 ``docker-compose`` 를 이용하여 도커 환경의 서버에서 서빙되고 있는 것을 알 수 있다. 또한 파이썬 앱에 직접적으로 연결되는 것이 아닌 ``haproxy`` 라고 하는 리버스 프록시 서버 뒤에서 작동하는 것을 확인하였다.

``config/haproxy.cfg`` 파일을 보면
```
frontend web 
    bind *:8000  
    http-request deny if { path_beg /flag }
    http-request deny if { path_beg // }
```
위 부분에서 ``path_beg`` 가 ``/flag`` 의 경우 http 요청을 거부하는 규칙이 있음을 알 수 있다.

또한 아래의 설정 구문을 보면, flask 호스트네임의 5000번으로 요청을 프록시하고 있는 것을 알 수 있다.
```
backend websrvs 
    http-reuse always
    server srv1 flask:5000
```

그래서 이제 haproxy가 ``/flag`` 엔드포인트에 접근을 막고 있는 것을 알게 되었다. 구글링 해볼 시간이다.

![구글신 만세](/assets/img/2024-06-03-smuggling/google.png)

검색 결과를 확인해보니.. ``Encoded URL`` 은 path_beg 가 매칭되지 않는다는 것을 알 수 있다.

또한 HAProxy 가 ACL(Access Control List) bypass 를 가능하게 한다는 레딧 글이 있다.

첫번째 글의 경우 URL 이 인코딩된 URL 의 경우 200 응답이 수신된다고 하지만 ``/flag`` 는 인코딩하여도 그대로이기 때문에 관련이 없다고 볼 수 있다.

[두번째 글](https://www.reddit.com/r/sysadmin/comments/pl5hjb/haproxy_vulnerability_allows_acl_bypass/) 의 경우, 이 글이 링크되어 있다.

[HAProxy vulnerability enables HTTP request smuggling attacks | The Daily Swig (portswigger.net)](https://portswigger.net/daily-swig/haproxy-vulnerability-enables-http-request-smuggling-attacks)

"Security researchers have disclosed a HTTP request smuggling vulnerability in HAProxy, the popular open source load balancer."
> 보안 연구원들이 인기 있는 오픈 소스 로드 밸런서인 HAProxy의 HTTP Request Smuggling 취약점을 공개했습니다.
   
"Researchers at DevOps platform JFrog demonstrated how an integer overflow flaw (CVE-2021-40346) can be abused to perform HTTP request smuggling attacks that bypass any access control lists (ACLs) defined in HAProxy."
> DevOps 플랫폼 JFrog의 연구원들은 정수 오버플로 결함(CVE-2021-40346) 을 악용하여 HAProxy에 정의된 ACL(액세스 제어 목록) 을 우회하는 HTTP Request Smuggling 공격을 수행할 수 있는 방법을 시연했습니다.

``jfrog..?`` 아까 서버 코드에 ref. jfrog 라고 적혀있는 게 힌트였던 것 같다.

```py
@app.route('/guest', methods=['GET', 'POST'])
def guest():
    return 'ref. jfrog'
```

[CVE-2021-40346-POC](https://github.com/donky16/CVE-2021-40346-POC)
