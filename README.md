# edk
Encrypt/Decrypt using AWS KMS

## Create a KMS key via CLI

* Create the key

  ```bash
  aws kms create-key \ 
      --description "Default Key" \
      --region eu-west-1
  ``` 

* Create an alias fro the key

  ```bash
  aws kms create-alias \
      --alias-name alias/default_cmk \
      --region eu-west-1
  ```

## Usage

```bash
usage: edk.py [-h] -k <kms alias/id> {encrypt,decrypt} ...

Encrypt/Decrypt a string or a file using AWS KMS

options:
  -h, --help            show this help message and exit
  -k <kms alias/id>, --kms <kms alias/id>
                        KMS alias or id

commands:
  {encrypt,decrypt}     command to run
    encrypt             Encrypt a string or a file
    decrypt             Decrypt a string or a file
```

**encrypt** and **decrypt** commands have the same arguments.

### Encrypt

```bash
usage: edk.py encrypt [-h] [-s <string>] [-f <file>] [-o <output file>]

options:
  -h, --help            show this help message and exit
  -s <string>, --string <string>
                        String to encrypt/decrypt
  -f <file>, --file <file>
                        File to encrypt/decrypt
  -o <output file>      Output encrypted string or file to a different filei (default: .encrypted)
```

### Decrypt

```bash
usage: edk.py decrypt [-h] [-s <string>] [-f <file>] [-o <output file>]

options:
  -h, --help            show this help message and exit
  -s <string>, --string <string>
                        String to encrypt/decrypt
  -f <file>, --file <file>
                        File to encrypt/decrypt
  -o <output file>      Output encrypted string or file to a different filei (default: .encrypted)
```

## Examples

I reccommend to use pipenv.

* Install dependencies
```bash
# Install dependencies
pipenv install
```

* Encrypt

```bash
pipenv run python src/edk.py -k "alias/default_cmk" encrypt -s "stringtoencrypt"
```
