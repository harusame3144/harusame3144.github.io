---
layout: post
category: [wargame, web]
---

## [문제](https://dreamhack.io/wargame/challenges/96)

![Carve party](/assets/img/2024-05-08-carve-party.png)   

호박을 10000번 클릭해 플래그를 획득하면 되는 문제이다.

문제가 HTML 파일로 주어졌기 때문에 HTML 문서를 크롬의 개발자 도구를 사용해 열어보았다.

아래와 같은 소스코드가 있는 것을 확인할 수 있었다
## 클라이언트 소스코드
```js
// FLAG 가 들어있는 변수
var pumpkin = [ 124, 112, 59, 73, 167, 100, 105, 75, 59, 23, 16, 181, 165, 104, 43, 49, 118, 71, 112, 169, 43, 53 ];
// 클릭 횟수를 세는 카운터 변수
var counter = 0;
// 뭔가 필요해 보이는 값
var pie = 1;

// 10000번 이상 클릭한 경우 FLAG를 보여주는 함수
function make() {
  if (10000 < counter) {
    /** 생략 (캔버스 관련 코드) */
  }
  else {
    // 몇 번 남았는지 보여주는 코드
    $('#clicks').text(10000 - counter);
  }
}

$(function() {
  // 호박을 클릭하면 실행되는 코드
  $('#jack-target').click(function () {
    // 카운터를 1 증가시킨다
    counter += 1;
    // 만약 카운터가 10000 이하고, 100의 배수일 경우
    if (counter <= 10000 && counter % 100 == 0) {
      // FLAG의 길이만큼 반복한다
      for (var i = 0; i < pumpkin.length; i++) {
        // FLAG배열의 i번째 값을 XOR 연산하여 대입한다
        pumpkin[i] ^= pie;
        // pie 값을 현재 pie 값의 255 만큼 xor 연산한 후 i * 10을 더한 값을 255 로 AND 연산한다
        pie = ((pie ^ 0xff) + (i * 10)) & 0xff;
      }
    }
    // MAKE 함수를 실행한다
    make();
  });
});
```

## 풀이
위 코드 중에서 중요한 부분은 호박을 클릭할 때마다 `pumpkin` 배열의 값을 XOR, AND 연산하는 부분이기 때문에   
연산하는 부분만 따로 실행하여 플래그를 획득하였다.
```js
// FLAG 배열
const pumpkin = [ 124, 112, 59, 73, 167, 100, 105, 75, 59, 23, 16, 181, 165, 104, 43, 49, 118, 71, 112, 169, 43, 53 ];
// 클릭 횟수를 세는 카운터 변수
let counter = 0;
// XOR 연산에 필요한 값
let pie = 1;

// 10000번 반복될 때에 100의 배수일 경우만 실행되기 때문에, 10000 / 100 번 반복한다 (100번)
for (let j = 0; j < 10000 / 100 ; j ++) {
    // FLAG의 길이만큼 반복한다
    for (let i = 0; i < pumpkin.length; i++) {
        // FLAG의 i번째 값을 XOR 연산한다
        pumpkin[i] ^= pie;
        // pie 값을 현재 pie 값의 255 만큼 xor 연산한 후 i * 10을 더한 값을 255 로 AND 연산한다
        pie = ((pie ^ 0xff) + (i * 10)) & 0xff;
      }
}

// FLAG를 출력한다
console.log(pumpkin.map(x => String.fromCharCode(x)).join('')); // DH{** FLAG **}
```

### 비트 연산 XOR

| A | B | A XOR B |
|---|---|---------|
| 0 | 0 | 0       |
| 0 | 1 | 1       |
| 1 | 0 | 1       |
| 1 | 1 | 0       |


### 비트 연산 AND

| A | B | A AND B |
|---|---|---------|
| 0 | 0 | 0       |
| 0 | 1 | 0       |
| 1 | 0 | 0       |
| 1 | 1 | 0       |