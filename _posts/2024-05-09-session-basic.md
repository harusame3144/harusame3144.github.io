---
layout: post
category: [wargame, web]
title: session-basic
---

## [문제](https://dreamhack.io/wargame/challenges/409)
관리자 계정으로 로그인에 성공하면 플래그를 획득할 수 있는 문제다.

## 문제 분석
문제 파일을 다운로드해 코드를 보면 ``/admin`` 에서 관리자 세션 확인을 하고 세션 스토리지를 보여줘야 하지만 주석 처리 되어있어 관리자가 아닌 모든 사용자가 세션 스토리지를 볼 수 있다.

```py
@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    # 관리자 확인 코드가 완전히 주석 처리 되어있다.

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage
```

## 문제 풀이
테스트 서버의 ``/admin`` 으로 접근할 경우 원래라면 표시되지 않아야 할 세션 아이디가 표시되는 것을 볼 수 있다.
```
{
  "0c1819d0b7251733c6a059fdde1702924c0f74c1346cbc0fee152a1a508cc18a": "guest",
  "2a7ba66540f9c01d70d7b216fa2a66f6e6ba9254e32f14e984adf94d5bb83138": "admin",
}
```

크롬의 개발자 도구를 이용해 ``sessionid`` 쿠키의 값을 ``admin`` 계정의 세션 아이디로 변조한다.

![관리자의 세션 아이디를 탈취하였다](/assets/img/2024-05-09-session-basic/devtool-cookie.png)

이후 메인 페이지에 접속하면 관리자로 로그인되어 플래그가 표시되는 것을 확인할 수 있다.

![FLAG](/assets/img/2024-05-09-session-basic/flag.png)