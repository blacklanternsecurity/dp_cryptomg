#!/usr/bin/env python3

import sys
import logging
import binascii
import urllib.parse
from base64 import b64encode, b64decode
from argparse import ArgumentParser

log = None


def init_logging(log_level):
    formatter = logging.Formatter(fmt="%(levelname)s - %(module)s - %(msg)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(log_level)

    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    logger.addHandler(handler)

    logger.debug("Logging initialized")
    return logger


class ConfigParameter:
    key = None
    is_array = None
    param_type = None
    _value = None
    encoded = None

    def __init__(self, params=None):
        if params is not None:
            p = params.split(b",")
            self.key = p[0].decode()
            self.is_array = p[1] == b"True"
            self.param_type = int(p[2])
            self.encoded = False
            if self.param_type == 0:
                try:
                    self._value = b64decode(p[3])
                    self.encoded = True
                except binascii.Error:
                    self._value = p[3]
            else:
                self._value = p[3]

    @property
    def value(self):
        if self.encoded == True:
            return b64encode(self._value)
        return self._value

    @property
    def value_raw(self):
        return self._value

    def __str__(self):
        val = self.value
        if self.param_type == 0:
            val = val.decode()

        return f"{self.key},{self.is_array},{self.param_type},{self.value.decode()}"


def repeated_key_xor(pt, key):
    len_key = len(key)
    encoded = []
    for i in range(0, len(pt)):
        encoded.append(pt[i] ^ key[i % len_key])
    return bytes(encoded)


class DecryptError(binascii.Error):
    pass


def set_params(orig_params, new_params):
    for p in new_params:
        if p.key in orig_params.keys():
            log.debug(f"Replacing existing parameter {p.key}")
        else:
            log.debug(f"Adding new parameter {p.key}")
        orig_params[p.key] = p
    return orig_params


def encrypt_params(params, hexkey):
    param_str = ";".join([str(params[p]) for p in params.keys()])
    log.debug("Encrypting params:")
    for p in params.values():
        log.debug(f"  {p}")

    new_ciphertext = b64encode(repeated_key_xor(b64encode(param_str.encode()), hexkey))
    newl = ""
    newl = log.level
    return f"{newl}{urllib.parse.quote(new_ciphertext.decode())}"


def decrypt_params(enc_params, hexkey):
    params = {}
    plaintext = bytes(repeated_key_xor(b64decode(urllib.parse.unquote(enc_params)), hexkey))
    try:
        decrypted_params = b64decode(plaintext).split(b";")
        log.debug("Decrypted parameters:")
        for p in decrypted_params:
            param = ConfigParameter(p)
            params[param.key] = param
            log.debug(f"  {p.decode()}")

        if not len(params):
            raise DecryptError

        print(f"{b64decode(plaintext).decode()}")

        return params
    except binascii.Error:
        log.warning("Could not decrypt parameters. Incorrect key?")
        return {}


def init_parser():
    key = "663@aae)0d-7(b8@5-46#2*2-83$0a-fb&830^0de7~73b"
    parser = ArgumentParser(__file__, description="Description")
    parser.add_argument("-v", action="store_true", dest="verbose", help="Enable verbose logging")
    parser.add_argument("-d", "--decrypt", metavar="B64", help="Decrypt Base64-encoded block using the specified key")
    parser.add_argument("-e", "--encrypt", metavar="RAW", help="Plaintext string to encrypt")
    parser.add_argument("-k", "--key", default=key, help=f"Encryption key (default: {key})")
    parser.add_argument("-s", "--set", nargs="+", metavar="PARAM", help="Add a parameter")
    return parser


def main():
    global log
    parser = init_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    log = init_logging(log_level)

    hexkey = args.key.encode()
    if args.decrypt:
        params = decrypt_params(args.decrypt, hexkey)

        if args.set:
            new_params = set_params(params, [ConfigParameter(p.encode()) for p in args.set])
            encrypted = encrypt_params(new_params, hexkey)
            print(encrypted)

    elif args.encrypt:
        log.debug(f"Encrypting string {args.encrypt}")
        params = {}
        for p in args.encrypt.split(";"):
            param = ConfigParameter(p.encode())
            params[param.key] = param
        encrypted = encrypt_params(params, hexkey)

        if args.set:
            new_params = set_params(params, [ConfigParameter(p.encode()) for p in args.set])
            encrypted = encrypt_params(new_params, hexkey)

        print(encrypted)

    return 0


if __name__ == "__main__":
    sys.exit(main())
else:
    log = init_logging(logging.ERROR)
