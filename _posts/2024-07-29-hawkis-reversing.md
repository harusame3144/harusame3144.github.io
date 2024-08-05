---
layout: post
category: [reversing]
title: 2asy Revers1ng
---

# 문제

![문제](/assets/img/2024-07-29-hawkis-reversing/problem.png)

exe 파일을 리버싱하는 문제이다.

## EXE 파일 확인

![PE](/assets/img/2024-07-29-hawkis-reversing/pe.png)   
[Detect It Easy](https://github.com/horsicq/Detect-It-Easy) 라는 툴을 사용해 PE정보를 확인할 수 있었다.

MinGW 환경에서 컴파일 된 C/C++ 기반의 프로그램인 것을 확인할 수 있다.

## 디스어셈블링

> 디스어셈블링이란?   
컴파일된 컴퓨터 프로그램의 실행 파일이나 오브젝트 파일을 사람이 읽을 수 있는 어셈블리어(assembly language) 코드로 변환하는 과정이다.   
이 과정을 도와주는 툴이 디스어셈블러이고, 여러 디스어셈블러 중 이 글에서는 IDA 를 이용하여 디스어셈블링 후 FLAG 값을 찾아보도록 하겠다.


디스어셈블링을 위해 IDA 를 이용해 EXE 파일을 확인해보자

![IDA](/assets/img/2024-07-29-hawkis-reversing/ida.png)

IDA 를 킨 후 New 버튼을 클릭해준다.

![파일 선택창](/assets/img/2024-07-29-hawkis-reversing/open_file.png)

디스어셈블 할 파일을 선택 후 Open 해준다.

![파일 선택 완료창](/assets/img/2024-07-29-hawkis-reversing/file_next.png)


DWARF Debug Information 을 찾아서 로드하겠냐고 물어보는 창이 표시되었다.
> DWARF Debug Information 이란?   
DWARF is a widely used, standardized debugging data format.   
DWARF 는 광범위하게 사용되고, 표준화된 디버깅 데이터 포멧이다.   
프로그램의 디버깅을 위해 설계된 데이터 포멧이라고 한다.   

아마 컴파일 할때 DWARF 디버그 정보가 포함되어 컴파일 된 것 같다.

심볼 정보등이 포함되어 있는 것으로 보이기 때문에 Yes 를 눌러서 진행한다.

![DWARF](/assets/img/2024-07-29-hawkis-reversing/dwarf.png)


> 함수 목록 - 프로그램의 함수들이 나열되어 있는 목록이다.   
그래프 뷰 - 프로그램의 함수 내용을 분기로 나눠서 그래프로 보여준다.   
디스어셈블리 창 - 디스어셈블링 된 함수를 어셈블리어로 보여준다.

![Overview](/assets/img/2024-07-29-hawkis-reversing/overview.png)

main 함수의 어셈블리 창을 클릭 후 F5키를 클릭해 의사코드 (Pseudo code) 로 변환하여 소스코드를 확인해보았다.

![main 함수](/assets/img/2024-07-29-hawkis-reversing/main_asm.png)

flag 변수에 ``obfuscate_flag`` 함수로 설정한 후, 마지막에 ``strcmp()`` 함수를 사용해 FLAG 를 비교하는 것을 확인할 수 있다.

![pseudocode](/assets/img/2024-07-29-hawkis-reversing/pseudocode.png)

``obfuscate_flag`` 함수를 다시 의사코드로 변경해보자.

![obfuscate_flag](/assets/img/2024-07-29-hawkis-reversing/obfuscate.png)

![obfuscate_flag_explanation](/assets/img/2024-07-29-hawkis-reversing/obfuscate_flag_explanation.png)

``parts`` 2차원 배열에 문자열을 넣고, order 배열의 순서대로 풀면 FLAG 가 나온다.

![solve](/assets/img/2024-07-29-hawkis-reversing/solve.png)