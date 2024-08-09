---
layout: post
category: [steganography]
title: What kind of picture is this?
---

# 문제

사진에 숨겨져있는 플래그 값을 찾는 문제이다.


# 문제 풀이

![문제](/assets/img/2024-08-06-hawkis-what-kind-of-picture-is-this/problem.png)


문제에 포함된 사진이다.

![문제 사진](/assets/img/2024-08-06-hawkis-what-kind-of-picture-is-this/What_kind_of_picture_is_this.png)

EXIF 데이터와, strings 명령어를 사용해 사진에 숨겨진 플래그를 찾아보았으나 플래그를 찾지 못하였다.

사진에 포함되어 있는 QR코드 (오른쪽 밑 QR코드) 를 찍어보았다.

![QR코드 인식 결과](/assets/img/2024-08-06-hawkis-what-kind-of-picture-is-this/qr_code.png)

```c
#include <stdio.h>

#include <stdlib.h>

int main(void) {
  unsigned char rawData[8] = {
    0x6b,0x65,0x79,0x3a,0x30,0x78,0x35,0x41
  };

  for (int i = 0; i < 8; i++) {
    printf("%c", rawData[i]);
  }

  printf("\n");
  return 0;
}
```

C 코드를 실행해보았다.

```
/tmp/bHaEleV2zm.o
key:0x5A

=== Code Execution Successful ===
```

key: 0x5A 값을 얻을 수 있었다.

다른 바코드들도 찍어보았다.

```
"16=3B2839353E3F27"

"32=LR4DCZJTGQ2SSOZPFBOHQMBVLR4DCOA="

"64=XHgxMjstMVx4MTNcdCFrY1x4MDUK"
```

위와 같은 값을 얻을 수 있었다.

base64 로 인코딩 되어 있는 값인거 같아 확인해보았다.

``"\x12;-1\x13\t!kc\x05"`` key를 이용하여 해독하는 문제인 것 같다..

32와 16도 base32, hex 값으로 디코딩해보았다.

```
";(95>?'" = base16
"\x1e345);/(\x05\x18" = base32
"\x12;-1\x13\t!kc\x05" = base64
```

```py
# 문자열을 10진수 정수 배열로 변환하는 함수
def str_to_int_array(data):
    return [ord(c) for c in data] # 문자열을 10진수로 변환

# Function to apply XOR
def xor(data, key):
    return ''.join([chr((n) ^ key) for n in data]) # XOR 연산 후 문자열로 변환

key = 0x5A

# 디코드 된 문자열을 합쳐서 xor 한 결과값
str_base16 = ";(95>?'"
str_base32 = "\x1e345);/(\x05\x18"
str_base64 = "\x12;-1\x13\t!kc\x05"
print(xor(str_to_int_array(str_base64 + str_base32 + str_base16), key))
```

문자열을 0x5A 로 XOR 연산하여 플래그를 획득할 수 있었다.

![FLAG](/assets/img/2024-08-06-hawkis-what-kind-of-picture-is-this/flag.png)