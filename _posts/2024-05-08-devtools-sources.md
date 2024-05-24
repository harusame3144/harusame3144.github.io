---
layout: post
category: [wargame, web]
---

## [문제](https://dreamhack.io/wargame/challenges/267)
개발자 도구의 Sources 탭 기능을 활용해 플래그를 찾아보세요.

## 문제 풀이
> 개발자 도구 여는법
 - F12
 - Ctrl + Shift + I
 - 마우스 오른쪽 버튼 클릭 후 "검사" 클릭
 
문제 파일을 다운로드 받고, 개발자 도구의 Sources 탭을 열어보면 `webpack://` 이라는 폴더가 있는 것을 확인할 수 있다.

main.scss 파일의 맨 밑에 플래그가 주석으로 달려있는 것을 확인할 수 있다.

![devtools-image](/assets/img/2024-05-08-devtools-sources/devtool.png)

> 위와 같이 클라이언트에서는 웹사이트를 사용하는 사람이 소스를 확인할 수 있기 때문에, 중요한 정보나 중요한 로직들은 서버에서 처리하는 것이 바람직하다.