# SQL Injection Vulnerability

## Agenda

- SQL Injection in a Nutshell. => (Let's Take a Look! :D)
  - What is SQL Injection?
  - How does SQL Injection work?
  - How to prevent SQL Injection?
- SQL Injection in Action => (Let's Hack It! ^\_^)
  - PortSwigger SQL Injection Labs with Automation
    - Writing a Python Script to automate the exploitation process
    - Using SQL Map to exploit the Vulnerability
  - MetaSpoitable 2
    - Security Level 0 => (No Protection) ==> Manual Exploitation
    - Security Level 1 => (Basic Protection) ==> Bypass Frontend Validation with **Zap Proxy**
    - Security Level 2 => (Advanced Protection) ==> Show the secure code
  - Solving CTF Challenges
    - PicoCTF SQL Injection
    - HackTheBox SQL Injection

---

### Description

SQL injection is a code injection technique, used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker). SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.

### Types of SQL Injection

- In-band SQL Injection
- Inferential SQL Injection
- Blind SQL Injection
- Error-based SQL Injection
- Union-based SQL Injection
- Boolean-based SQL Injection
- Time-based SQL Injection

---

### My Resources

- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- [PicoCTF SQL Injection](https://picoctf.org/practice-questions)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQL Map Docs](https://github.com/sqlmapproject/sqlmap)
- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
