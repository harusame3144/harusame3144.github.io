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



## GDB 를 사용해 프로그램 디버깅
``gdb ./baby_bof`` 명령어를 터미널에 입력해 문제 파일을 디버거로 열어준 후, ``info functions`` 명령어를 입력한다.

![functions](/assets/img/2024-08-05-hawkis-baby-bof/gdb_1.png)


```
0x0000000000401060  puts@plt
0x0000000000401070  printf@plt
0x0000000000401080  gets@plt

0x0000000000401176  print_flag
0x0000000000401190  vuln
0x00000000004011c4  main
```

``puts``, ``printf``, ``gets`` 함수들을 사용한 것을 확인할 수 있으며, ``print_flag``, ``vuln``, ``main`` 함수를 확인할 수 있다.

``vuln`` 함수를 ``disassemble`` 명령어를 사용해 디스어셈블링 해보았다.

![디스어셈블링 된 vuln함수](/assets/img/2024-08-05-hawkis-baby-bof/disassembled_vuln.png)

``0x0000000000401198`` 주소의 함수를 보면 ``%rsp`` 레지스터에 ``$0x40 (64바이트)`` 을 빼는 것을 확인할 수 있다.

%rbp를 8바이트 아래로 이동하고, %rsp 에 %rbp 주소를 저장한 후, 스택 포인터의 주소값에서 64바이트 아래로 이동한다는 뜻은 새 스택 프레임을 만들고, 스택 공간을 64바이트만큼 할당하겠다는 의미로 볼 수 있기 때문에, 버퍼의 크기는 64바이트라고 유추할 수 있다.

이제 ``Return Address`` 를 덮어씌우기 위해 변수의 크기를 알 수 있게 되었다.

![스택 프레임 구조](/assets/img/2024-08-05-hawkis-baby-bof/stackframe.png)

변수 공간의 크기는 64바이트, ``Return Address`` 의 위치를 알기 위해서는 ``%rbp`` 레지스터의 크기를 알아야 한다.

위 어셈블리 언어 사진에서 볼 수 있듯이, 인텔 기준 어셈블리언어 에서는 ``push`` 오퍼레이션이 레지스터의 주소에서 8바이트를 뺀다고 하지만, 직접 gdb 로 확인해보았다.

이걸 알기 위해, ``vuln`` 함수의 ``0x0000000000401198`` 주소에 브레이크포인트를 걸고 프로그램을 실행한 후, gdb 를 통해 ``%rbp`` 레지스터의 크기를 확인해보자.

``vuln`` 함수 내부에 브레이크포인트를 걸어, 프로그램 실행이 일시 중지된 것을 확인할 수 있다.

![브레이크포인트 걸린 모습](/assets/img/2024-08-05-hawkis-baby-bof/bp.png)

``print sizeof($rbp)`` 명령어를 입력해 ``%rbp`` 레지스터의 크기를 확인해보자.

![rbp레지스터 크기 확인](/assets/img/2024-08-05-hawkis-baby-bof/rbp_size.png)

``%rbp`` 레지스터의 크기가 8바이트인 것을 알수 있다.

``Return Address`` 를 덮어씌우기 위해서는, 스택 프레임에 할당된 64바이트의 공간과, rbp 레지스터의 크기인 8바이트 이상의 데이터를 넣어주면 될 것 같다.

![Segmentation Fault](/assets/img/2024-08-05-hawkis-baby-bof/segfault.png)

할당된 메모리 공간을 넘어서는 데이터 입력으로 인해 Segmentation Fault가 발생하였다.

데이터 입력란에 메모리 공간을 넘어서는 데이터와, 실행시킬 함수의 주소를 포함시킨 후 입력한다. 이로 인해 버퍼 오버플로우가 발생하면, 범위를 넘어서는 데이터가 베이스 포인터(Base Pointer)와 리턴 주소(Return Address)를 침범하게 되며 원래 함수가 종료된 후 리턴 주소가 변경되어 의도하지 않은 코드 실행을 유도할 수 있다.

![버퍼 오버플로우](/assets/img/2024-08-05-hawkis-baby-bof/buffer_overflow.png)

## pwntools 를 이용한 공격 페이로드 작성

```py
from pwn import *

context.arch = "amd64" # 실행 환경

addr = 0x0000000000401176 # print_flag 주소값

p = process('./baby_bof') # 실행할 프로그램

# A 문자 64개 (변수) + A문자 8개 (베이스 포인터) + 덮어씌울 리턴 주소값
payload = b'A' * 64 + b'A' * 0x8 + p64(addr)

# Bytes 로 파일 쓰기
f = open('./payload.txt', 'wb')
f.write(payload) # 파일에 페이로드를 작성한다.
f.close()
```

만들어진 페이로드를 xxd 로 확인해보았다.   

![Hex](/assets/img/2024-08-05-hawkis-baby-bof/hex.png)

4141 4141 7611 4000 부분을 확인해보면, print_flag 의 주소값이 포함된 것을 확인할 수 있다.

(순서가 다른 건, 파이썬은 리틀 엔디안을 사용하지만 뷰어에서는 빅 엔디안으로 보이기 때문이다.)

``cat ./payload.txt | ./baby_bof`` 를 통해 페이로드를 보냈다.   

![FLAG](/assets/img/2024-08-05-hawkis-baby-bof/flag.png)