# SecretPictures

![01](./img/01.png)

![02](./img/02.png)

`DANGER.txt`

```
Dear User,

This text file is to warn you that the ZIP file contains software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise.Always handle such files in isolated, controlled, and secure environments.

It is strongly recommend you proceed by:

1 - Running the sample in a controlled environment, for example EP Pwnbox or an isolated virtual machine.
2 - Only unzip the software in this controlled environment, using the password provided.
3 - Unzip the file in the VM and enjoy analysing!

PLEASE EXERCISE EXTREME CAUTION!

The ZIP file containing the software is password-protected for your safety. The password is “&PD8LhraU1hx”. It is strongly recommended that you do NOT extract or execute the contents of this ZIP file unless you understand the risks involved.
By reading this file and using the provided password to unzip the file, you acknowledge and fully understand the risks as detailed in this warning.
```

La password per l'estrazione del contenuto di DANGEER.zip è **&PD8LhraU1hx**.

![03](./img/03.png)

```
secretPictures.exe: PE32+ executable (console) x86-64, for MS Windows
```

![04](./img/04.png)

### 1. What is the MD5 hash of the malware?

![05](./img/05.png)

### 2. What programming language is used to write the malware?

![06](./img/06.png)

Il malware è stato compilato con Go compiler 1.15.0, quindi, il linguaggio di programmazione utilizzato è Golang.

Con il seguente comando:
```
$ strings -t x secretPictures.exe | grep go
```

Si riesce anche a risalire alla versione di Golang, che in questo caso è la **1.23.1**.

![07](./img/07.png)

### 3. What is the name of the folder the malware copies itself to after the initial run?

Prima di eseguire l'applicazione si lancia Regshot.

![08](./img/08.png)

Si lancia il programma **secretpictures.exe** e lo si monitora con Process Explorer:

![09](./img/09.png)

L'unica cartella che è stata di recente modificata è la **C:\Systemlogs\\**.

### 4. What registry key does the malware modify to achieve persistence?

Si effettua un secondo snapshot dei registri con Regshot e si comparano le due versioni:

![10](./img/10.png)

Viene aggiunto un nuovo valore al HKEY_USERS (HKU) per l'utente corrente:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\HealthCheck
```

### 5. What FQDN does the malware attempt to connect to?

![11](./img/11.png)

Si lancia il malware **logscheck.exe** e si hanno degli errori con al risoluzione del FQDN **malware.invalid.com**.

### 6. Which Windows API function does the malware call to check drive types?

![12](./img/12.png)

```
GetDriveType
```

### 7. Which Go standard library function does the malware use to schedule periodic execution?

![13](./img/13.png)

Tra i packages vi è anche **time**. Il package standard time permette di definire cron-like task in diversi modi. Tra questi con il metodo **time.NewTicker**.

![14](./img/14.png)

> [/dev.to - Golang: Implementing Cron-Like Tasks/Executing Tasks at a Specific Time](https://dev.to/shrsv/golang-implementing-cron-like-tasks-executing-tasks-at-a-specific-time-11j)

```
NewTicker
```

### 8. What encoding does the malware use to decode server responses?

![15](./img/15.png)

```
base64
```

### 9. The malware communicates with a backend server via a POST request. What are the names of the fields in the request body, separated by commas and listed alphabetically?

![16](./img/16.png)

Il malware è il prodotto di questi file. Nel file **heist.go** sono presenti metodi per la raccolta di informazioni.

![17](./img/17.png)

Tra gli URL in memory e nell'eseguibile si trovano anche i parametri **name** e **version** per l'URL http://malware.invalid.com/heist.

> [https://www.joesandbox.com/analysis/1822990/0/html#6968FD46D178474F32F596641FF0F7BB337E](https://www.joesandbox.com/analysis/1822990/0/html#6968FD46D178474F32F596641FF0F7BB337E)

```
name,version
```

---
