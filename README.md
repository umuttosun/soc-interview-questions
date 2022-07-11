 # Contribute

Let's make this repository full of interview questions!

If you think any interview question is missing or incorrect, please feel free to submit a pull request (PR) to this repo. We will review the PR and merge if appropriate.

# SOC Interview Questions

- What to expect
	- Security Analyst
	- Incident Response
- Pre-preparing
- General
- Network
- Web Application Security
- Event Log Analysis
- Malware Analysis
- Web Application Security



## What to expect

https://www.tines.com/reports/voice-of-the-soc-analyst/

### Security Analyst

 - Network fundamentals
 - Operating system fundamentals
 - Basic terminologies
 - Malware analysis fundamentals
 - How to analyze attacks (phishing, malware...)

### Incident Responder

 - Incident Response Prosedure
 - How to detect specific kind of attacks (like golden ticket)

## Pre-preparing

https://www.tines.com/reports/voice-of-the-soc-analyst/

 - Do not tell your salary expectation. Answer like: "I think my salary expectations are within your scale. In case of positive progress, I am open to your suggestions at the proposal stage."
 - 

## General

### Explain vulnerability, risk and threat.

**Vulnerability:** Weakness in an information system, system security procedures, internal controls, or implementation that could be exploited or triggered by a threat source. (src: [NIST](https://csrc.nist.gov/glossary/term/vulnerability))

**Risk:** the level of impact on agency operations (including mission functions, image, or reputation), agency assets, or individuals resulting from the operation of an information system given the potential impact of a threat and the likelihood of that threat occurring. (src: [NIST](https://csrc.nist.gov/glossary/term/security_risk))

**Threat:** Any circumstance or event with the potential to adversely impact organizational operations, organizational assets, individuals, other organizations, or the Nation through a system via unauthorized access, destruction, disclosure, modification of information, and/or denial of service. (src: [NIST](https://csrc.nist.gov/glossary/term/cyber_threat))

For example let's assume there is a web application server that updates are turned off.

### Do you know any programming language?

While this question is up to you, having a basic understanding of programming languages can be a plus for the interview.

### Explain Security Misconfiguration

It is a security vulnerability caused by incomplete or incorrect misconfiguration.

### What are black hat, white hat and gray hat?

**Blat hat:** Black-Hat Hackers are those hackers who enter the system without taking owners’ permission. These hackers use vulnerabilities as entry points. They hack systems illegally. They use their skills to deceive and harm people. ([GeeksforGeeks](https://www.geeksforgeeks.org/what-are-white-hat-gray-hat-and-black-hat-hackers/))

**White hat:** White-Hat Hackers are also known as Ethical Hackers. They are certified hackers who learn hacking from courses. These are good hackers who try to secure our data, websites. With the rise of cyberattacks organizations and governments have come to understand that they need ethical hackers. ([GeeksforGeeks](https://www.geeksforgeeks.org/what-are-white-hat-gray-hat-and-black-hat-hackers/))

**Gray hat:** Gray-Hat Hackers are a mix of both black and white hat hackers. These types of hackers find vulnerabilities in systems without the permission of owners. They don’t have any malicious intent. However, this type of hacking is still considered illegal. But they never share information with black hat hackers. They find issues and report the owner, sometimes requesting a small amount of money to fix it. ([GeeksforGeeks](https://www.geeksforgeeks.org/what-are-white-hat-gray-hat-and-black-hat-hackers/))

### What is firewall?

Firewall is a device that allows or blocks the network traffic according to the rules.

### How do you keep yourself updated with information security?

 - Reading daily infosec news from different resources.
	 - [The Hacker News](https://thehackernews.com/)
	 - [Malwarebytes Labs](https://blog.malwarebytes.com/)
	 - [HackRead](https://www.hackread.com/)
	 - [ThreatPost](https://threatpost.com/)
 - By following infosec related social media accounts.
 - Telegram channels
 - Joining newsletter related to cyber security


### What is CIA triad?

The three letters in "CIA triad" stand for Confidentiality, Integrity, and Availability. The CIA triad is a common model that forms the basis for the development of security systems. They are used for finding vulnerabilities and methods for creating solutions. ([Fortinet](https://www.fortinet.com/resources/cyberglossary/cia-triad))

**Confidentiality:** Confidentiality involves the efforts of an organization to make sure data is kept secret or private. A key component of maintaining confidentiality is making sure that people without proper authorization are prevented from accessing assets important to your business.

**Integrity:** Integrity involves making sure your data is trustworthy and free from tampering. The integrity of your data is maintained only if the data is authentic, accurate, and reliable.

**Availability:** Systems, networks, and applications must be functioning as they should and when they should. Also, individuals with access to specific information must be able to consume it when they need to, and getting to the data should not take an inordinate amount of time.

### What are HIDS and NIDS?

**HIDS:** HIDS means Host Intrusion Detection System. HIDS is located on each host.

**NIDS:** NIDS means Network Intrusion Detection System. NIDS is located in the network.

### What is port scanning?

Port scanning is a method of determining which ports on a network are open and could be receiving or sending data. It is also a process for sending packets to specific ports on a host and analyzing responses to identify vulnerabilities. ([Avast](https://www.avast.com/business/resources/what-is-port-scanning))

### What is compliance?

Following the set of standards authorized by an organization, independent part, or government.

### Explain True Positive and  False Positive.

![_img source:towardsdatascience.com_](https://letsdefend.io/images/training/IMS/2/false-positive-true-positive.PNG)

**True Positive:**

If the situation to be detected and the detected (triggered alert) situation are the same, it is a True Positive alert. For example, let's say you had a PCR test to find out whether you are Covid19 positive and the test result came back positive. It is True Positive because the condition you want to detect (whether you have Covid19 disease) and the detected condition (being a Covid19 patient) are the same. This is a true positive alert. ([LetsDefend](https://app.letsdefend.io/training/lesson_detail/basic-definitions-about-incident-management))

Let’s suppose there is a rule to detect SQL Injection attacks and this rule has been triggered because of a request that was made to the following URL. The alert is indeed a “True Positive” as there was a real SQL Injection attack.

https://app.letsdefend.io/casemanagement/casedetail/115/src=' OR 1=1

**False Positive:**

In short, it is a false alarm. For example, there is a security camera in your house and if the camera alerts you due to your cat's movements, it is a false positive alert. ([LetsDefend](https://app.letsdefend.io/training/lesson_detail/basic-definitions-about-incident-management))

If we look at the URL example below, we see the SQL parameter "Union" keyword within this URL. If an SQL injection alert occurs for this URL, it will be a false positive alert because the “Union” keyword is used to mention a sports team here and not for an SQL injection attack.

https://www.google.com/search?q=FC+Union+Berlin


### How can you define Blue Team and Red Team basically?

Red team is attacker side, blue team is defender side.

### Do you have any project that we can look at?

If you do have any project to show, make sure that you prepare it before the interview.

### Could you share some general endpoint security product names?

 - Antivirus
 - EDR
 - XDR
 - DLP

### Explain 2FA.

2FA is an extra layer of security used to make sure that people trying to gain access to an online account are who they say they are. First, a user will enter their username and a password. Then, instead of immediately gaining access, they will be required to provide another piece of information. ([Authy](https://authy.com/what-is-2fa/))

### Explain salted hashes?

A salt is added to the hashing process to force their uniqueness, increase their complexity without increasing user requirements, and to mitigate password attacks like hash tables. ([Auth0](https://auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/))

### What is AAA?

**Authentication:** Authentication involves a user providing information about who they are. Users present login credentials that affirm they are who they claim. ([Fortinet](https://www.fortinet.com/resources/cyberglossary/aaa-security))

**Authorization:** Authorization follows authentication. During authorization, a user can be granted privileges to access certain areas of a network or system. ([Fortinet](https://www.fortinet.com/resources/cyberglossary/aaa-security))

**Accounting:** Accounting keeps track of user activity while users are logged in to a network by tracking information such as how long they were logged in, the data they sent or received, their Internet Protocol (IP) address, the Uniform Resource Identifier (URI) they used, and the different services they accessed. ([Fortinet](https://www.fortinet.com/resources/cyberglossary/aaa-security))

### What is Cyber Kill Chain?

Developed by Lockheed Martin,  **the Cyber Kill Chain®** framework is part of the **[Intelligence Driven Defense®](https://www.lockheedmartin.com/en-us/capabilities/cyber/intelligence-driven-defense.html)** model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.

The seven steps of the Cyber Kill Chain® enhance visibility into an attack and enrich an analyst’s understanding of an adversary’s tactics, techniques and procedures. ([Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html))

![enter image description here](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/photo/cyber/THE-CYBER-KILL-CHAIN-body.png.pc-adaptive.1920.medium.png)

### What is SIEM?

Security information and event management (SIEM), is a security solution that provides the real time logging of events in an environment. The actual purpose for event logging is to detect security threats.

In general, SIEM products have a number of features. The ones that interest us most as SOC analysts are: they filter the data that they collect and create alerts for any suspicious events. ([LetsDefend](https://app.letsdefend.io/training/lesson_detail/siem-and-analyst-relationship))

### What is MITRE ATT&CK?
MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community. ([MITRE ATT&CK](https://attack.mitre.org/))

## Network

### Could you share some general network security product names?

 - Firewall
 - IDS
 - IPS
 - WAF

### What is DHCP protocol?

The **Dynamic Host Configuration Protocol** (DHCP) is a network management protocol used on Internet Protocol (IP) networks for automatically assigning IP addresses and other communication parameters to devices connected to the network using a client–server architecture.

### How can you protect yourself from Man-in-the-middle attacks?

While answering this question vary different scenarios, encryption is the key point for being safe.

### What is OSI Model? Explain each layer.

The **Open Systems Interconnection model** (**OSI model**) is a conceptual model that describes the universal standard of communication functions of a telecommunication system or computing system, without any regard to the system's underlying internal technology and specific protocol suites. ([Wikipedia](https://en.wikipedia.org/wiki/OSI_model))

![OSI Model](https://miro.medium.com/max/478/1*xWrTDOjK8Rdog947Lf6wFg.png)

 1. **Physical layer:** The Physical Layer is responsible for the transmission and reception of unstructured raw data between a device, such as a network interface controller, Ethernet hub or network switch and a physical transmission medium. It converts the digital bits into electrical, radio, or optical signals.
 2. **Data link layer:** The  data link layer  provides node-to-node data transfer—a link between two directly connected nodes. It detects and possibly corrects errors that may occur in the physical layer. It defines the protocol to establish and terminate a connection between two physically connected devices. It also defines the protocol for flow control between them. IEEE 802 divides the data link layer into two sublayers:
	a. [Medium access control](https://en.wikipedia.org/wiki/Medium_access_control "Medium access control")  (MAC) layer – responsible for controlling how devices in a network gain access to a medium and permission to transmit data.
	b. [Logical link control](https://en.wikipedia.org/wiki/Logical_link_control "Logical link control")  (LLC) layer – responsible for identifying and encapsulating network layer protocols, and controls error checking and frame synchronization.
 3. **Network layer:** The network layer provides the functional and procedural means of transferring packets from one node to another connected in "different networks".
 4. **Transport layer:** The transport layer provides the functional and procedural means of transferring variable-length data sequences from a source host to a destination host from one application to another across a network, while maintaining the quality-of-service functions. Transport protocols may be connection-oriented or connectionless.
 5. **Session layer:** The Session Layer creates the setup, controls the connections, and ends the teardown, between two or more computers, which is called a "session". Since DNS and other Name Resolution Protocols operate in this part of the layer, common functions of the Session Layer include user logon (establishment), name lookup (management), and user logoff (termination) functions. Including this matter, authentication protocols are also built into most client software, such as FTP Client and NFS Client for Microsoft Networks. Therefore, the Session layer establishes, manages and terminates the connections between the local and remote application.
 6. **Presentation layer:** The Presentation Layer establishes data formatting and data translation into a format specified by the application layer during the encapsulation of outgoing messages while being passed down the protocol stack, and possibly reversed during the deencapsulation of incoming messages when being passed up the protocol stack. For this very reason, outgoing messages during encapsulation are converted into a format specified by the application layer, while the conversation for incoming messages during deencapsulation are reversed.
 7. **Application layer:** The application layer is the layer of the OSI model that is closest to the end user, which means both the OSI Application Layer and the user interact directly with software application that implements a component of communication between the client and server, such as File Explorer and Microsoft Word. Such application programs fall outside the scope of the OSI model unless they are directly integrated into the Application layer through the functions of communication, as is the case with applications such as Web Browsers and Email Programs. Other examples of software are Microsoft Network Software for File and Printer Sharing and Unix/Linux Network File System Client for access to shared file resources.

### What is three-way handshake?

![enter image description here](https://umuttosun.com/wp-content/uploads/2019/09/94_syn_fig1_lg.jpg)

TCP uses a  three-way handshake  to establish a reliable connection. The connection is full duplex, and both sides synchronize (SYN) and acknowledge (ACK) each other.

The client chooses an initial sequence number, set in the first SYN packet. The server also chooses its own initial sequence number, set in the SYN/ACK packet.

Each side acknowledges each other's sequence number by incrementing it; this is the acknowledgement number. The use of sequence and acknowledgment numbers allows both sides to detect missing or out-of-order segments.

Once a connection is established, ACKs typically follow for each segment. The connection will eventually end with a RST (reset or tear down the connection) or FIN (gracefully end the connection). ([ScienceDirect](https://www.sciencedirect.com/topics/computer-science/three-way-handshake))

### What is the key difference between IDS and IPS?

IDS only detect the traffic but IPS can prevent/block the traffic.

### What is ARP?

The **Address Resolution Protocol** (**ARP**) is a communication protocol used for discovering the link layer address, such as a MAC address, associated with a given internet layer address, typically an IPv4 address. This mapping is a critical function in the Internet protocol suite. ([Wikipedia](https://en.wikipedia.org/wiki/Address_Resolution_Protocol))


## Web Application Security

### Explain CSRF

Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker’s choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application. ([OWASP](https://owasp.org/www-community/attacks/csrf))

### What are the HTTP response codes?

**1XX:** Informational
**2XX:** Success
**3XX:** Redirection
**4XX:** Client-side error
**5XX:** Server-side error

For example, 404 is 'server cannot find the requested resource'.

### What is WAF?

A WAF or web application firewall helps protect web applications by filtering and monitoring HTTP traffic between a web application and the Internet. It typically protects web applications from attacks such as cross-site forgery, cross-site-scripting (XSS), file inclusion, and SQL injection, among others. A WAF is a protocol layer 7 defense (in the OSI model), and is not designed to defend against all types of attacks. ([Cloudflare](https://www.cloudflare.com/learning/ddos/glossary/web-application-firewall-waf/))

### What is XSS and how XSS can be prevented?

Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it. ([OWASP](https://owasp.org/www-community/attacks/xss/))

For XSS attacks to be successful, an attacker needs to insert and execute malicious content in a webpage. Each variable in a web application needs to be protected. Ensuring that  **all variables**  go through validation and are then escaped or sanitized is known as perfect injection resistance. Any variable that does not go through this process is a potential weakness. Frameworks make it easy to ensure variables are correctly validated and escaped or sanitised.

However, frameworks aren't perfect and security gaps still exist in popular frameworks like React and Angular. Output Encoding and HTML Sanitization help address those gaps.

### Explain CSRF.

Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker’s choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application. ([OWASP](https://owasp.org/www-community/attacks/csrf))

### Explain OWASP Top Ten.

The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications. ([OWASP](https://owasp.org/www-project-top-ten/))

![enter image description here](https://owasp.org/www-project-top-ten/assets/images/mapping.png)

### 

## Event Log Analysis

### 

### 


### 


### 


### 


### 


### 


## Cryptography

### What are encoding, hashing, encryption?

**Encoding:** Converts the data in the desired format required for exchange between different systems.

**Hashing:** Maintains the integrity of a message or data. Any change did any day could be noticed.

**Encryption:** Ensures that the data is secure and one needs a digital verification code or image in order to open it or access it.


### What is the  difference between hashing and encryption?

**Hashing:** Hashing is the process of converting the information into a key using a hash function. The original information cannot be retrieved from the hash key by any means. (src: [GeeksforGeeks](https://www.geeksforgeeks.org/difference-between-hashing-and-encryption/))

**Encryption:** Encryption is the process of converting a normal readable message known as plaintext into a garbage message or not readable message known as Ciphertext. The ciphertext obtained from the encryption can easily be transformed into plaintext using the encryption key. (src: [GeeksforGeeks](https://www.geeksforgeeks.org/difference-between-hashing-and-encryption/))

**Difference:** 

 - The hash function does not need a key to operate.
 - While the length of the output can variable in encryption algorithms, there is a fixed output length in hashing algorithms.
 - Encryption is a two-way function that includes encryption and decryption whilst hashing is a one-way function that changes a plain text to a unique digest that is irreversible.



### What are differences between SSL and TLS?



### 



## Malware Analysis

### What is the name of the software that compiles of the written codes?

Compiler

### What is the name of the software that translates machine codes into assembly language?

Disassembler

### What is the difference between static and dynamic malware analysis?

**Static Analysis:** It is the approach of analyzing malicious software by reverse engineering methods without running them. Generally, by decompile / disassemble the malware, each step that the malware will execute is analyzed, hence the behavior / capacity of the malware can be analyzed.

**Dynamic Analysis:** It is the approach that examines the behavior of malicious software on the system by running it. In dynamic analysis, applications that can examine registry, file, network and process events are installed in the system, and their behavior is examined by running malicious software.

![LetsDefend Malware Analysis Fundamentals Training](https://letsdefend.io/blog/wp-content/uploads/2022/05/static-analysis-vs-dynamic-analysis.png)

It should also be noted that using only one approach may not be sufficient to analyze malware. Using both approaches together will give you to best results!

### 
