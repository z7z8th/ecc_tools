# ecc_tools
Elliptic-curve cryptography tools


### Usage
* ECC raw keygen
  ```shell
  ecc_tools keygen pubkey_file privkey_file   # ECC-384 only, strong enough
  ```
* Hash gen
  ```shell
  dd if=/dev/urandom of=hash_file bs=1 count=48 status=none   # 48 Bytes = 384 bits, ECC-384
  # -- or --
  sha256sum filename.ext | cut -d ' ' -f 1 |  xxd -r -p > hash_file
  ```
* ECC Sign
  ```shell
  ecc_tools sign pubkey_file privkey_file hash_file signature_file
  ```
* ECC Verify
  ```
  ecc_tools verify pubkey_file hash_file signature_file
  ```
