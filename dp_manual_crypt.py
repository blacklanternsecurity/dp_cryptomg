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
    foo = None
    param_type = None
    _value = None
    encoded = None

    def __init__(self, params=None):
        if params is not None:
            p = params.split(b",")
            self.key = p[0].decode()
            self.foo = p[1] == b"True"
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

    def __str__(self):
        val = self.value
        if self.param_type == 0:
            val = val.decode()

        return f"{self.key},{self.foo},{self.param_type},{self.value.decode()}"


def repeated_key_xor(pt, key):
    len_key = len(key)
    encoded = []
    for i in range(0, len(pt)):
        encoded.append(pt[i] ^ key[i % len_key])
    return bytes(encoded)


def main():
    global log
    key = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    parser = ArgumentParser(__file__, description="Description")
    parser.add_argument("-v", action="store_true", dest="verbose", help="Enable verbose logging")
    parser.add_argument("-d", "--decrypt", metavar="B64", help="String to decrypt to Base64")
    parser.add_argument("-D", "--decrypt-raw", metavar="B64", help="String to decrypt to plaintext")
    parser.add_argument("-e", "--encrypt", metavar="RAW", help="Plaintext string to encrypt")
    parser.add_argument("-E", "--encrypt-b64", metavar="B64", help="Base64 string to encrypt")
    parser.add_argument("-k", "--key", default=key, help=f"Encryption key (default: {key})")
    parser.add_argument("--set", nargs="+", metavar="PARAM", help="Add a parameter")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    log = init_logging(log_level)

    hexkey = args.key.encode()
    if args.decrypt:
        params = {}
        plaintext = bytes(repeated_key_xor(b64decode(urllib.parse.unquote(args.decrypt)), hexkey))
        decrypted_params = b64decode(plaintext).split(b";")
        for p in decrypted_params:
            param = ConfigParameter(p)
            params[param.key] = param

        log.info(f"Decrypted string: {b64decode(plaintext)}")
        if args.set:
            for a in args.set:
                new_param = ConfigParameter(a.encode())
                params[new_param.key] = new_param
                log.debug(f"Added parameter: {str(new_param)}")

        param_str = ";".join([str(params[p]) for p in params.keys()])
        log.debug("Encrypting params:")
        for p in params.values():
            log.debug(f"  {p}")

        new_ciphertext = b64encode(repeated_key_xor(b64encode(param_str.encode()), hexkey))
        print(f"\n{urllib.parse.quote(new_ciphertext.decode())}")

    elif args.encrypt:
        log.debug(f"Encrypting string {args.encrypt}")
        ciphertext = b64encode(repeated_key_xor(args.encrypt.encode(), hexkey)).decode()
        log.debug(f"Base64 encoded: {ciphertext}")
        print(f"\n{urllib.parse.quote(ciphertext)}")

    elif args.encrypt_b64:
        log.debug(f"Encrypting string {args.encrypt_b64}")
        plaintext = b64decode(args.encrypt_b64)
        ciphertext = b64encode(repeated_key_xor(plaintext, hexkey)).decode()
        log.debug(f"Base64 encoded: {ciphertext}")
        print(f"\n{urllib.parse.quote(ciphertext)}")

    elif args.decrypt_raw:
        ciphertext = urllib.parse.unquote(args.decrypt_raw)
        log.debug(f"Decrypting string {ciphertext}")
        plaintext = repeated_key_xor(b64decode(ciphertext), hexkey)
        print(f"\n{plaintext.decode()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
