# Secure Your PHP
This can help you to ensure a proper security level for your PHP installation.

## Installation
Download `security-check.php` into your website folder.

## Usage
Open it in your browser.
For example: `http://your-website.com/path/to/security-check.php`

Then, you can view a report of the security check on your PHP installation.
```
Loaded Extensions Core, date, ereg, libxml, openssl, pcre, sqlite3, zlib, ctype, curl, dom, fileinfo, filter, ftp, hash, iconv, json, mbstring, SPL, PDO, session, posix, Reflection, standard, SimpleXML, pdo_sqlite, Phar, tokenizer, xml, xmlreader, xmlwriter, mysqlnd, apache2handler, pdo_mysql, zip
Running platform Linux
safe_mode VULNERABLE
Can view /etc/passwd VULNERABLE
Can view /etc/shadow PASSED
Shell via "system" command VULNERABLE
Shell via "shell_exec" command VULNERABLE
Shell via "exec" command VULNERABLE
Shell via "passtrhu" command PASSED
Shell via "proc_open" command VULNERABLE
Shell via "popen" command VULNERABLE
```
