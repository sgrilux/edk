import argparse
import base64
import json
import logging

import boto3
from botocore.exceptions import ClientError


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
                               type=argparse.FileType('r'),
                               dest='file',
                               metavar="<file>",
                               help="File to encrypt/decrypt")

    parent_parser.add_argument('-o',
                               type=argparse.FileType('w'),
                               dest='output',
                               metavar="<output file>",
                               help="Output encrypted string or file to a different filei (default: .encrypted)")

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


def encrypt_file(file, kms):
    return "Not implemented yet!"


def decrypt_string(string, kms):
    client = boto3.client("kms", region_name=AWS_REGION)

    try:
        plain_text = client.decrypt(
            KeyId=kms,
            CiphertextBlob=bytes(base64.b64decode(string))
        )
    except ClientError as err:
        raise Exception(
            "An error occurred during decryption of %s: %s", string, err)
    else:
        return plain_text["Plaintext"]


def decrypt_file(file, kms):
    return "Not implemented yet!"


def main(args):
    try:
        if args.command == 'encrypt':
            encrypted = ""
            if args.string:
                encrypted = encrypt_string(args.string, args.kms)
            if args.file:
                encrypted = encrypt_file(args.file, args.kms)

            print(encrypted)

        if args.command == 'decrypt':
            decrypted = ""
            if args.string:
                decrypted = decrypt_string(
                    args.string, args.kms).decode('utf8')
            if args.file:
                decrypted = decrypt_file(args.file, args.kms)

            print(decrypted)
    except Exception as ex:
        logger.exception(ex)


if __name__ == '__main__':
    args = parse_input_arguments()
    main(args)
