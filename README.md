## Download

You can run Cypher Offline as a standalone application.  
Download the Windows executable:

- [Cypher Offline](https://github.com/chrialonso/cypher-offline/releases/download/v1.0/Cypher.exe) – Double-click to run.

Download the '.exe' file.  
Place Cypher.exe in your desired folder.  
Double click to run.  
Your data remains local and encrypted.
## Features

- **Offline & Local** - Your passwords never leave your computer
- **AES-256-GCM Encryption** - Military-grade encryption standard
- **Envelope Encryption** - Double-layer security
- **SQLCipher Database** - Encrypted database storage
- **KDF-Based Key Derivation** - Secure password-based encryption keys
- **Password Generator** - Create strong, random passwords
- **Category Organization** - Organize credentials by type
- **Favorites Organization** - Organize credentials by favorites

## Security Design

- **Account Creation & Trust Based Access**  
  On first launch, Cypher detects whether its directory has user data.  
  If no user data exists, it displays a welcome page for creating the first account.  
  Once that initial account is created, new accounts **cannot** be added from the login screen, they must be added manually by the original user.  
  This prevents unauthorized users from creating accounts on someone else’s machine and accessing encrypted data.
  The GUI does not expose a way to view or access other users’ credentials, maintaining separation between accounts.
  
- **Independent Instances**  
  Cypher Offline is self-contained, meaning each Cypher folder maintains its own encrypted database and configuration files.  
  This allows multiple independent installations on the same computer. For example, separate Cypher folders for different users without sharing data or credentials between them.
  
- **Master Password–Derived Key**  
  Your master password is transformed into a cryptographic key using a key-derivation function (KDF) every time you log in. This derived key serves as the master key in the envelope encryption process described below.

- **Envelope Encryption**  
  Cypher uses two layers of encryption: your passwords are encrypted with a data key, 
  and that data key is encrypted with a master key derived from your password. This design provides 
  better key management and an additional layer of security.
  
## Screenshots

<div align="center">
  <img src="https://github.com/user-attachments/assets/52a9685d-3215-4e1a-bed2-a3ecdcad2343" alt="Welcome Screen" width="300"/>
  <p><em>First installation welcome screen</em></p>
</div>

<div align="center">
  <img src="https://github.com/user-attachments/assets/430920a6-878e-46e9-b6dd-2c33bf3a382c" alt="Categories View" width="310"/>
    <p><em>Show passwords organized by category</em></p>
  </div>

<div align="center">
<img width="312" alt="generator" src="https://github.com/user-attachments/assets/0c29bd0a-f9b2-4f73-b878-654bd524453d"/>
      <p><em>Generate strong, custom lengthed passwords</em></p>
</div>

<div align="center">
  <img src="https://github.com/user-attachments/assets/0f34d295-fcaa-47df-aaca-8483c7566f79" alt="Add New Login" width="311"/>
  <p><em>Add new credentials with custom fields</em></p>
</div>

## About This Project
This project was built to learn and explore python, encryption, database security, and GUI development.

## Disclaimer
This is a learning project. While it implements real security practices, it has not undergone professional security auditing.
