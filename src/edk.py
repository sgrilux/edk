import argparse
import base64
import json
import logging

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

AWS_REGION = 'eu-west-1'

# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s: %(levelname)s: %(message)s')


def parse_input_arguments():

    arg_parser = argparse.ArgumentParser(
        description="Encrypt/Decrypt a string or a file using AWS KMS")

    subparsers = arg_parser.add_subparsers(title="commands",
                                           help="command to run",
                                           required=True,
                                           dest='command')

    arg_parser.add_argument("-k",
                            "--kms",
                            required=True,
                            dest='kms',
                            metavar="<kms alias/id>",
                            help="KMS alias or id")

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('-s',
                               '--string',
                               type=str,
                               dest='string',
                               metavar="<string>",
                               help="String to encrypt/decrypt")

    parent_parser.add_argument('-f',
                               '--file',
                               type=str,
                               dest='file',
                               metavar="<file>",
                               help="File to encrypt/decrypt")

    parent_parser.add_argument('-o',
                               type=str,
                               dest='output',
                               metavar="<output file>",
                               help="Output encrypted string or file to a different file")

    encrypt = subparsers.add_parser(
        'encrypt',
        parents=[parent_parser],
        help="Encrypt a string or a file")
    decrypt = subparsers.add_parser(
        'decrypt',
        parents=[parent_parser],
        help="Decrypt a string or a file")

    args = arg_parser.parse_args()

    return args


def encrypt_string(string, kms):
    client = boto3.client("kms", region_name=AWS_REGION)

    try:
        cipher_text = client.encrypt(
            KeyId=kms,
            Plaintext=bytes(string, encoding='utf8')
        )
    except ClientError as err:
        raise Exception(
            "An error occurred during encryption of %s: %s", string, err)
    else:
        return base64.b64encode(cipher_text["CiphertextBlob"])

def _get_data_key(key_id):
    key_spec = 'AES_256'

    client = boto3.client("kms", region_name=AWS_REGION)

    try:
        data_key = client.generate_data_key(KeyId=key_id,
                                        KeySpec=key_spec)
    
    except ClientError as err:
        raise Exception("Error generating data key:\n%s", err)
    
    data_key_encrypted = data_key['CiphertextBlob']
    data_key_plaintext = base64.b64encode(data_key['Plaintext']) 

    return data_key_encrypted, data_key_plaintext

def encrypt_file(file, kms):
    try:
        with open(file, "rb") as f:
            file_contents = f.read()

        data_key_encrypted,data_key_plaintext = _get_data_key(kms)

        if data_key_encrypted is None:
            raise Exception("Encrypted data key is None")

        f = Fernet(data_key_plaintext)
        encrypted_file_contents = f.encrypt(file_contents)

    except IOError as err:
        raise Exception("Error reading file %s\n%s", err)
    except Exception as ex:
        raise Exception("Error encrypting file %s", file)

    return encrypted_file_contents


def decrypt_string(string, kms):
    client = boto3.client("kms", region_name=AWS_REGION)

    try:
        plain_text = client.decrypt(
            KeyId=kms,
            CiphertextBlob=bytes(base64.b64decode(string))
        )
    except ClientError as err:
        raise Exception(
            "An error occurred during decryption of %s\n%s", string, err)
    else:
        return plain_text["Plaintext"]


def decrypt_file(file, kms):
    try:
        with open(file, "rb") as f:
            file_contents = f.read()

        data_key_encrypted, data_key_plaintext = _get_data_key(kms)

        if data_key_encrypted is None:
            raise Exception("Encrypted data key is None")

        f = Fernet(data_key_plaintext)
        decrypted_file_contents = f.decrypt(file_contents)
    
    except IOError as err:
        raise Exception("Error reading file %s\n%s", err)
    except Exception as err:
        raise Exception("Error decrypting file :%s", file)

    return decrypted_file_contents


def main(args):
    try:
        if args.command == 'encrypt':
            encrypted = None
            if args.string:
                encrypted = encrypt_string(args.string, args.kms)
            if args.file:
                encrypted_file = encrypt_file(
                    args.file, args.kms)
                if args.output:
                    with open(args.output, 'wb') as output_file:
                        output_file.write(encrypted_file)
                else:
                    print(encrypted_file)

        if args.command == 'decrypt':
            if args.string:
                decrypted = decrypt_string(
                    args.string, args.kms).decode('utf8')
                print(decrypted)
            if args.file:
                decrypted_file = decrypt_file(args.file, args.kms)
                if args.output:
                    with open(args.output, 'wb') as output_file:
                        output_file.write(decrypted_file)
                else:
                    print(decrypted_file)

    except Exception as ex:
        logger.exception(ex)


if __name__ == '__main__':
    args = parse_input_arguments()
    main(args)
