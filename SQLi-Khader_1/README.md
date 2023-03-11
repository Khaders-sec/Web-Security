# SQL Injection Vulnerability

## Agenda

- SQL Injection in a Nutshell. => (Let's Take a Look! :D)
  - What is SQL Injection?
  - How does SQL Injection work?
  - How to prevent SQL Injection?
- SQL Injection in Action => (Let's Hack It! ^\_^)
  - PortSwigger SQL Injection Labs with Automation
  - MetaSpoitable 2 with Zap Proxy
    - Security Level 0 => (No Protection)
    - Security Level 1 => (Basic Protection)
    - Security Level 2 => (Advanced Protection)
  - SQL Map with PicoCTF

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

### My Resources

- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)
- [PicoCTF SQL Injection](https://picoctf.org/practice-questions)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
