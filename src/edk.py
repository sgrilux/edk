import argparse
import logging
import json

import boto3
from botocore.exceptions import ClientError


AWS_REGION = 'eu-west-1'

# logger config
logger = logging.getLogger()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s: %(levelname)s: %(message)s')

kms_client = boto3.client("kms", region_name=AWS_REGION)


def parse_input_arguments():

    arg_parser = argparse.ArgumentParser(
        description="Encrypt/Decrypt a string or a file using AWS KMS")

    subparser = arg_parser.add_subparsers(title="commands",
                                          help="command to run",
                                          required=True,
                                          dest='command')
    encrypt = subparser.add_parser(
        'encrypt', help="Encrypt a string or a file")
    decrypt = subparser.add_parser(
        'decrypt', help="Decrypt a string or a file")

    arg_parser.add_argument("-k",
                            "--kms",
                            required=True,
                            metavar="<kms alias/id>",
                            help="KMS alias or id")

    arg_parser.add_argument('-s',
                            '--string',
                            type=str,
                            metavar="<string>",
                            help="String to encrypt/decrypt")

    arg_parser.add_argument('-f',
                            '--file',
                            type=argparse.FileType('r'),
                            metavar="<file>",
                            help="File to encrypt/decrypt")

    arg_parser.add_argument('-o',
                            type=argparse.FileType('w'),
                            metavar="<output file>",
                            help="Output encrypted string or file to a different filei (default: .encrypted)")

    args = arg_parser.parse_args()

    return args


def encrypt_string(string, kms, output):
    pass


def encrypt_file(file, kms, output):
    pass


def decrypt_string(string, kms, output):
    pass


def decrypt_file(file, kms, output):
    pass


def main(args):
    if args.command == 'encrypt':
        if args.string:
            encrypted = encrypt_string(args.string, args.kms, args.output)
        if args.file:
            encrypted = encrypt_file(args.file, args.kms, args.output)

    if args.command == 'decrypt':
        if args.string:
            decrypted = decrypt_string(args.string, args.kms, args.output)
        if args.file:
            decrypted = decrypt_file(args.file, args.kms, args.output)


if __name__ == '__main__':
    args = parse_input_arguments()
    main(args)
