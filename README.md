# https-survey
Simple TSL/SSL scanner using OpenSSL. Can print information about TLS/SSL version of domain and X509 certificate. Did it for studying purposes.
## Installation
### Prerequisites
- Linux environment
- OpenSSL
- GNU Make
- GCC compiler

 **Install OpenSSL** (if not already installed):

   On Debian/Ubuntu:
   ```bash
   sudo apt install openssl
   ```
   On Arch:
   ```bash
   sudo pacman -S openssl
   ```
   Build:
   ```bash
   make
   ```
  System-wide installation (optional):
  ```bash
sudo make install
```
Run:
```bash
./https-survey
```
   
