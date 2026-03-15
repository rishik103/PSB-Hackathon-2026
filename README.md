#Introduction
In today’s digital world, organizations rely heavily on encryption to protect sensitive information such as financial data, personal records, and communication between systems. Websites, APIs, and enterprise servers use cryptographic protocols like TLS to secure these communications.
However, many organizations do not have a clear understanding of how secure their cryptographic systems actually are. Some systems may still use outdated protocols, weak encryption algorithms, or certificates that are close to expiration. In addition, the development of quantum computing poses a future threat to current encryption methods such as RSA and ECC.
This project presents an Enterprise Quantum-Proof Asset Scanner, a tool designed to analyze the cryptographic security of network assets and evaluate their readiness for the future era of quantum computing.

#Objective
The main objective of this project is to create a system that can:
•	Scan enterprise assets such as domains, servers, and APIs
•	Analyze their TLS and cryptographic configurations
•	Identify weak or outdated encryption mechanisms
•	Evaluate their readiness for post-quantum cryptography
•	Provide security recommendations for improvement
The tool helps organizations understand their current cryptographic posture and prepare for future cybersecurity challenges.

#System Overview
The system works by connecting securely to the given target (such as a website or API endpoint) and collecting information about its cryptographic configuration.
After gathering this information, the system analyzes the data and assigns a security score based on several factors such as protocol version, cipher strength, certificate details, and key size.
The results are displayed through a simple and interactive dashboard where users can easily view the security status of each asset.
Key Features
Asset Scanning
The scanner accepts a list of domains or IP addresses and analyzes them one by one. This allows organizations to quickly check the security status of multiple systems at once.
Example targets include websites, APIs, and other externally accessible services.

#TLS and Encryption Detection
The system connects to the target server using TLS and detects important security parameters such as:
•	TLS version used by the server
•	Cipher suite used for encryption
•	Secure communication settings
This helps identify whether the server is using modern encryption standards.

#Certificate Analysis
Each secure server uses a digital certificate to verify its identity.
The scanner extracts certificate information including:
•	Certificate subject and issuer
•	Certificate validity period
•	Public key algorithm
•	Key size
This information helps detect weak keys or certificates that may expire soon.

#Cipher Strength Evaluation
The scanner evaluates the strength of the encryption cipher used by the server. Strong ciphers such as AES-GCM and ChaCha20 are considered secure, while older ciphers such as RC4 or DES are classified as weak.
This helps identify systems that may be vulnerable to cryptographic attacks.

#Forward Secrecy Detection
Forward secrecy ensures that even if a server’s private key is compromised in the future, past encrypted communications cannot be decrypted.
The scanner checks whether the server supports forward secrecy algorithms such as ECDHE or DHE.

#Security Scoring System
To make the results easier to understand, each asset is given a security score from 0 to 100.
The score is calculated using factors such as:
•	TLS version
•	Cipher strength
•	Key size
•	Forward secrecy support
•	Certificate validity
Based on the score, the asset is categorized into a security level such as Elite, Strong, Standard, or Weak.

#Post-Quantum Cryptography Readiness
One of the main goals of this project is to check whether systems are ready for the future impact of quantum computing.
Quantum computers may be able to break traditional cryptographic algorithms such as RSA and ECC. The scanner checks whether systems support or are prepared for newer post-quantum cryptographic algorithms.
This helps organizations begin planning for the transition to quantum-resistant security systems.

#Security Recommendations
After analyzing the system, the scanner provides simple recommendations for improving security.
Examples include:
•	Upgrading to TLS 1.3
•	Enabling forward secrecy
•	Increasing RSA key size
•	Considering hybrid TLS with post-quantum algorithms
These suggestions help organizations improve their cryptographic security.

#Technologies Used
This project was developed using the following technologies:
•	Python for backend development
•	SSL and Socket libraries for secure connections
•	Cryptography library for certificate analysis
•	Pandas for handling data and results
•	Streamlit for building the interactive dashboard interface
These technologies were chosen because they provide powerful tools for network security analysis and data visualization.

#System Workflow
The overall workflow of the system can be summarized in the following steps:
1.	The user enters a list of domains or IP addresses.
2.	The system connects to each target using TLS.
3.	The server’s certificate and cryptographic configuration are extracted.
4.	The system analyzes encryption strength and protocol security.
5.	A security score is calculated.
6.	The results are displayed in a dashboard and a report can be downloaded.

#Advantages of the System
This system provides several benefits:
•	Automated detection of cryptographic weaknesses
•	Easy-to-understand security scoring system
•	Early identification of quantum-related risks
•	Interactive dashboard for visualization
•	Scalable scanning of multiple enterprise assets
It helps organizations gain better visibility into their cryptographic infrastructure.

##Conclusion
The Enterprise Quantum-Proof Asset Scanner is a tool designed to help organizations evaluate the security of their cryptographic systems. By analyzing TLS configurations, certificate details, and encryption strength, the system provides a clear picture of how secure an asset is.
In addition, the tool highlights the importance of preparing for the future impact of quantum computing on cybersecurity. By identifying potential risks early, organizations can begin transitioning toward stronger and more resilient cryptographic systems.
This project demonstrates how automated scanning tools can support better security practices and help protect digital infrastructure in an increasingly connected world.

