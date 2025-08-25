# PyObfusPack

Multi-layer Python obfuscator & packer with marshal, zlib, AES-CTR/GCM, XOR, PBKDF2 key derivation, machine-lock binding, and fragmented Base64 loader for strong code protection.

---

##  Repository Structure

```
PyObfusPack/
├── obfuscate_pack.py        # Main interactive obfuscator script
├── README.md                # This README file
├── LICENSE                  # MIT License
└── example/
    ├── script.py            # Example source script
    └── script_obf.py        # Obfuscated result of script.py
```

- `obfuscate_pack.py`: main tool to obfuscate Python `.py` files using multiple configurable layers.
- `example/script.py`: simple demo input file.
- `example/script_obf.py`: an example obfuscated output for demonstration and testing.

---

##  Usage Guide

1. **Clone the repository**:

   ```bash
   git clone https://github.com/NyctophileXNIKA/PyObfusPack.git
   cd PyObfusPack
   ```

2. **Run obfuscator in interactive mode**:

   ```bash
   python obfuscate_pack.py
   ```

   Follow the wizard:
   - Enter the source filename (e.g. `example/script.py`)
   - Set options like encryption method (AES-GCM / AES-CTR / XOR), rounds, password, machine-lock, etc.

3. **Obfuscation Result**:

   The script generates `<basename>_obf.py` in the same directory. Example:

   ```
   example/script_obf.py
   ```

---

##  Example Directory Demonstration

Navigate to the `example` folder for a full example:

```
├── example/
│   ├── script.py
│   └── script_obf.py
```

### Example Source Before Obfuscation

`example/script.py`
```python
class hello:
    def print_hello(self):
        print(""" 
  Source Obfuscated with Chimera
       The lost Source - KEY
       
       """)
    
if __name__ == '__main__':
    obj = hello()
    from os import system as automation ; import sys
    automation('clear' if 'linux' in sys.platform.lower() else 'cls')
    obj.print_hello()
```

- `script_obf.py`: Obfuscated version produced by `obfuscate_pack.py`. To run it:

  - If password was **hardcoded**, simply run:
    ```bash
    python example/script_obf.py
    ```

  - If password was **not hardcoded**, follow the provided instructions in output:

    ```bash
    python example/script_obf.py <password>
    ```

    or set environment variable:

    ```bash
    export ZX_PW=<password>
    python example/script_obf.py
    ```

---

##  Features Overview

- **Multi-layer protection**: compress → encrypt (AES-CTR/GCM or XOR) → HMAC or auth → marshal → fragment → loader.
- **Flexible encryption**: choose between **AES-GCM** (authenticated), **AES-CTR with HMAC**, or fallback **XOR**.
- **PBKDF2 custom iterations**: modify key derivation strength for performance/security balance.
- **Machine-lock mode**: bind payload to specific machine fingerprint (`uname + Python version`).
- **Password options**:
  - Hardcoded into the loader (for convenience).
  - Prompted or auto-generated, with instructions to use CLI argument or environment variable.
- **Interactive wizard**: user-friendly command-line interface guiding each configuration.
- **Fragmented Base64 payload**: breaks pattern detection, making static analysis harder.

---

## 🔐 Security Recommendations

| Option             | Default Value | Secure (Recommended)     | Paranoid Mode (Maximum Security) |
|--------------------|---------------|--------------------------|----------------------------------|
| **Rounds**         | 1             | 3–5                      | ≥ 10                             |
| **Password**       | Auto-generate | Auto-generate (save it)  | Auto-generate (save it)          |
| **Hardcode PW**    | n (No)        | n (No)                   | n (No)                           |
| **AES-GCM**        | n (No)        | y (Yes)                  | y (Yes)                          |
| **AES-CTR**        | y (Yes)       | y (Yes) (fallback only)  | y (Yes) (fallback only)          |
| **XOR fallback**   | n (No)        | n (No)                   | n (No)                           |
| **KDF Iterations** | 200,000       | 200,000 – 300,000        | ≥ 500,000                        |
| **Chunks**         | 120           | 120–200                  | 200–300                          |
| **Var Prefix**     | zX            | Random custom prefix     | Random + long prefix             |
| **Machine Lock**   | n (No)        | Optional (y for single PC)| y (Yes, bind to machine)        |

### Notes
- **Default values** = balance between security & usability.  
- **Secure (Recommended)** = stronger settings for most real-world cases.  
- **Paranoid Mode** = maximum obfuscation & encryption, but can make execution **slower** and limit portability.  
- ⚠️ If you use **auto-generated password**, **copy & save it safely**. You will need it to run the obfuscated script.

---

##  How to Run the Example (step-by-step)

```bash
cd example
python ../obfuscate_pack.py
```

### 🔐 Example Secure Flow

Below is an example of recommended answers when using the interactive wizard.

```
[*] Masukkan nama file sumber (.py): example/script.py
[*] Berapa jumlah rounds/lapisan enkripsi? [default=1]: 3
[*] Masukkan password enkripsi (kosong = auto generate) [default=auto]: myStrongSecret123
[*] Hardcode password di loader? (y/n) [default=n]: n
[*] Gunakan AES-GCM? (y/n) [default=n]: y
[*] Gunakan AES-CTR (AES biasa)? (y/n) [default=y]: y
[*] Paksa pakai XOR fallback? (y/n) [default=n]: n
[*] Jumlah iterasi PBKDF2 (semakin besar semakin aman tapi lambat) [default=200000]: 200000
[*] Target panjang fragment base64 [default=120]: 120
[*] Prefix nama variabel fragment [default=zX]: zX
[*] Ikat password ke fingerprint mesin (machine-lock)? (y/n) [default=n]: n

--- Ringkasan pilihan ---
 Source       : example/script.py
 Rounds       : 3
 Use AES-CTR  : True
 Use AES-GCM  : True
 Force XOR    : False
 KDF iter     : 200000
 Chunks       : 120
 Var prefix   : zX
 Machine-lock : False
 Hardcode PW  : False
 Password     : (user provided)

[*] Lanjutkan proses obfuscation dengan pengaturan di atas? (y/n) [default=y]: y

[+] Wrote loader: example/script_obf.py (rounds=3, fragments=..., mode=AES-GCM, kdf_iter=200000, machine_lock=False)
```

### ▶️ Run the obfuscated script
```bash
python example/script_obf.py myStrongSecret123
```

---

##  License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

Visit the [example directory](https://github.com/https://github.com/NyctophileXNIKA/PyObfusPack/tree/main/example) in this repository to experiment with obfuscation in action!