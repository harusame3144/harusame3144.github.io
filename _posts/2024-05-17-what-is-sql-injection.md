---
layout: post
category: [web]
title: SQL Injection 이란?
---

SQL Injection 을 알아보기 전, RDBMS 와 SQL 에 대해 알아볼 필요가 있다.

## RDBMS
RDBMS는 Relational Database Management System, 즉 관계형 데이터베이스 관리 시스템의 약자이다. 이는 데이터를 테이블 형태로 구조화하며, 테이블은 행(Row)과 열(Column)로 구성된다..

### Column (컬럼)
컬럼은 테이블의 열을 의미하며, 특정한 유형의 데이터를 저장한다. 예를 들어 사용자 데이터를 저장할 경우 "이름", "아이디", "비밀번호" 등이 컬럼에 해당한다. 컬럼은 필드라고도 불린다.

### Row (로우)
로우는 테이블의 행을 의미하며, 각 로우는 테이블에 저장된 실제 데이터를 나타낸다. 예를 들어 사용자 테이블의 각 로우는 특정 사용자의 정보를 담고 있다. 로우는 튜플이라고도 불린다.

![RDBMS](/assets/img/2024-05-17-what-is-sql-injection/column-row.png)

## SQL
RDBMS는 데이터를 조작하기 위해 Structured Query Language (SQL)을 사용한다.

예를 들어, 이름이 "홍길동"인 사용자의 이름을 가져오려면 다음과 같은 명령어를 사용한다:
```sql
SELECT username FROM users WHERE username = "홍길동";
```

SQL 명령어는 크게 DDL, DML, DCL 3가지로 분류된다.

### DDL (Data Definition Language) - 데이터 정의 언어
- 데이터 구조를 정의하고 수정하는 데 사용된다.
- 데이터베이스의 스키마를 정의하고 변경한다.
- 주요 명령어: `CREATE`, `ALTER`, `DROP`

#### 데이터베이스 생성
```sql
CREATE DATABASE TEST_DATABASE;
```

#### 테이블 생성
```sql
USE TEST_DATABASE;
CREATE TABLE users(
    userid int auto_increment,
    username varchar(10) not null,
    phone varchar(20) not null,
    primary key (userid)
);
```

### DML (Data Manipulation Language) - 데이터 조작 언어
- 데이터를 쿼리하고 조작한다.
- 데이터베이스에 데이터를 삽입, 갱신, 삭제한다.
- 주요 명령어: `SELECT`, `INSERT`, `UPDATE`, `DELETE`

#### 테이블 데이터 생성
```sql
INSERT INTO users values (0, "엄준식", "010-1234-1234");
```

#### 테이블 데이터 조회
```sql
SELECT username FROM users WHERE phone = "010-1234-1234";
```

#### 테이블 데이터 변경
```sql
UPDATE users SET username = "홍길동" WHERE username = "엄준식";
```

### DCL (Data Control Language) - 데이터 제어 언어
- 데이터베이스에 대한 접근 권한을 제어한다.
- 데이터베이스의 보안, 권한 및 접근 제어를 관리한다.
- 주요 명령어: `GRANT`, `REVOKE`

#### 특정 사용자에게 권한 부여
```sql
GRANT SELECT ON users TO 'user'@'localhost';
```

# SQL Injection

> Injection 이란?   
사전적 의미: 주입, 삽입   
컴퓨터에서의 Injection: 악의적으로 작성된 입력이 애플리케이션에 전송되어 의도하지 않은 명령어를 실행하거나 허가되지 않은 데이터에 접근하도록 속이는 공격의 광범위한 범주를 의미한다.

예시 코드를 통해 SQL Injection을 알아보자.

```python
@app.route('/check')
def search():
    user_id = request.args.get('id')
    user_password = request.args.get('pw')

    db = get_db()
    cursor = db.cursor()

    # SQL Injection 취약 코드
    sql_query = f"SELECT * FROM users WHERE name = '{user_id}' AND password = '{user_password}'"

    cursor.execute(sql_query)
    results = cursor.fetchall()
    
    if len(results) == 0:
        return "No user found / ID or password incorrect"
    
    if results[0][0] == "admin":
        return "Welcome admin"
    else:
        return "You are not an admin"
```

## 주석을 사용한 SQL Injection

위 코드에서 사용자의 입력을 그대로 SQL 쿼리에 삽입하고 있다. 이는 SQL Injection으로 쿼리를 조작하기 매우 쉽다.

정상적인 요청:
``http://localhost:5000/check?id=guest&password=guest``

서버가 실행하는 SQL:
```sql
SELECT * FROM users WHERE name = 'guest' AND password = 'guest'
```

SQL Injection을 이용한 요청:
``http://localhost:5000/check?id=admin' --&password=qwerqwr``

서버가 실행하는 SQL:
```sql
SELECT * FROM users WHERE name = 'admin' --' AND password = 'qwerqwr'
```

![서버가 실행하는 SQL](/assets/img/2024-05-17-what-is-sql-injection/sql.png)

이 경우, 주석(`--`)을 사용하여 비밀번호 검증 부분을 무력화시킨다. 따라서 비밀번호를 확인하지 않고 이름이 'admin'인 계정 정보가 반환되어 관리자 권한을 획득할 수 있다.

### Union Select를 이용한 SQL Injection

`UNION SELECT`는 두 개의 쿼리 결과를 하나로 결합하는 SQL 명령어다. 이를 이용해 공격자는 추가적인 데이터를 노출시킬 수 있다.

예를 들어, 다음과 같은 쿼리가 있다고 가정하자:
```sql
SELECT username, phone FROM users WHERE userid = 1;
```

공격자가 `UNION SELECT`를 이용해 다음과 같이 쿼리를 조작할 수 있다:
``http://localhost:5000/check?id=1 UNION SELECT username, password FROM admin--``

서버가 실행하는 SQL:
```sql
SELECT username, phone FROM users WHERE userid = 1 UNION SELECT username, password FROM admin--'
```

이 경우, 첫 번째 쿼리 결과와 `admin` 테이블의 `username`과 `password`를 결합하여 반환하게 된다. 이를 통해 공격자는 민감한 데이터를 획득할 수 있다.

SQL Injection은 심각한 보안 문제를 야기할 수 있으며, 이를 방지하기 위해서는 사용자 입력을 철저히 검증하고, 쿼리를 작성할 때 Prepared Statements를 사용하는 것이 중요하다.