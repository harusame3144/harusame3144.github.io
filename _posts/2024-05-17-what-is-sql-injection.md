---
layout: post
category: [web]
title: SQL Injection 이란?
---

SQL Injection 을 알아보기 전, RDBMS 와 SQL 에 대해 알아 볼 필요가 있다.

RDBMS - Relational Database Management System / 관계형 데이터베이스 관리 시스템의 약자

## RDBMS
RDBMS 는 관계형 데이터 모델에 기초를 둔 데이터베이스이다.

RDBMS는 데이터를 테이블이라는 형태로 구조화하며, 이러한 테이블은 행(Row)과 열(Column)로 구성된다.

### Column (컬럼)
컬럼은 테이블의 열을 의미한다. 각 컬럼은 특정한 유형의 데이터를 저장한다.예를 들어 사용자 데이터를 저장할 경우 "이름", "아이디", "비밀번호" 등 각각의 컬럼은 한 Row의 속성이라고 할 수 있다. 필드라고도 불린다.

### Row (로우)
로우는 테이블의 행을 의미한다. 각 로우에는 테이블에 저장된 실제 데이터를 나타낸다. 예를 들어 위 컬럼의 사용자 테이블의 각 로우는 특정 사용자의 정보를 담고 있을 수 있다. 튜플이라고도 불린다.

![RDBMS](/assets/img/2024-05-17-what-is-sql-injection/column-row.png)

## SQL
RDBMS는 주로 데이터를 조작할 때 Structured Query Language (SQL) 을 사용한다.

예를 들어 이름이 ``홍길동`` 인 사용자의 이름을 가져오고 싶을 경우

```sql
SELECT username FROM users WHERE username = "홍길동";
```

이와 같이 명령어를 사용하면 된다.

데이터베이스에서 사용되는 다양한 유형의 SQL 명령어는 크게 3가지로 분류된다. (``DDL`` ``DML`` ``DCL``)

### DDL (Data Definition Language) - 데이터 정의 언어
- 데이터 구조를 정의하고 수정하는 데 사용된다.
- 데이터베이스의 스키마를 정의하고 변경하기 위해 사용된다.
- 주요 명령어는 ``CREATE`` ``ALTER`` ``DROP`` 등이 포함된다.
- 예를 들어 ``users`` 테이블을 삭제하고 싶을 경우 ``DROP TABLE user`` 와 같이 사용한다.

#### 데이터베이스 생성
``TEST_DATABASE`` 데이터베이스를 생성한다.

```sql
CREATE DATABASE TEST_DATABASE;
```

#### 테이블 생성
```sql
USE TEST_DATABASE; # TEST_DATABASE 를 사용
# users 테이블을 생성한다.
CREATE TABLE users(
    userid int auto_increment,
    username varchar(10) not null,
    phone varchar(20) not null,
    primary key (userid)
)
```

### DML (Data Manipulation Language) - 데이터 조작 언어
- 데이터를 쿼리하고 조작하는 데 사용된다.
- 데이터베이스에 데이터를 삽입, 갱신, 삭제한다.
- 주요 명령어는 ``SELECT`` ``INSERT`` ``UPDATE`` ``DELETE`` 등이 포함된다.
- 예를 들어 특정 테이블에서 데이터를 선택하고 싶을 때 사용할 수 있다. (위 예제 참고)

#### 테이블 테이터 생성
```sql
INSERT INTO users values (0, "엄준식", "010-1234-1234");
```

#### 테이블 데이터 조회
전화번호가 ``010-1234-1234`` 인 사용자 데이터를 모두 조회한다.
```sql
SELECT username FROM users WHERE phone = "010-1234-1234"
```

#### 테이블 데이터 변경
사용자 이름이 엄준식인 로우의 컬럼 값을 홍길동으로 변경한다.
```sql
UPDATE users SET username = "홍길동" WHERE username = "엄준식"
```

### DCL (Data Control Language) - 데이터 제어 언어
- 데이터베이스에 대한 접근 권한을 제어하는 데 사용된다.
- 데이터베이스에 대한 보안, 권한 및 접근 제어를 관리한다.
- 주요 명령어는 ``GRANT`` ``REVOKE`` 등이 포함된다.
- 예를 들어 특정 사용자에게 특정 테이블에 대한 읽기, 쓰기 권한을 부여할 때 사용된다.

#### 특정 사용자에게 권한을 부여
``user@localhost`` 에 ``users`` 테이블에서 ``SELECT`` 권한을 부여
```sql
GRANT SELECT ON users TO 'user'@'localhost'
```

## SQL Injection

- TODO -