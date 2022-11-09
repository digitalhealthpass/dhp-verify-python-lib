#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

import json
import base64
import base45

from jwt import algorithms

from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from cryptography.hazmat.primitives import serialization

from multi_cred_verifier_python.verifier.verification_result import VerificationResult


def base45_decode(base45_encoded_str):
    """
    decode base45 encoded string
    Returns:
        decoded string
    """
    return base45.b45decode(base45_encoded_str)


def base64_bytes_decode(base64_encoded_byte_str):
    """
    decode base64 encoded byte string
    Returns:
        decoded string
    """
    return base64.b64encode(base64_encoded_byte_str).decode("utf-8")


def base64_url_decode(base64_encoded_str):
    """
    decode base64 encoded string
    Returns:
        decoded string
    """
    decoded_bytes = base64.urlsafe_b64decode(base64_encoded_str + '===')
    decoded_str = decoded_bytes.decode('utf-8')
    return decoded_str


def base64_url_decode_bytes(base64_encoded_str):
    """
    decode base64 encoded string
    Returns:
        decoded bytes
    """
    decoded_bytes = base64.urlsafe_b64decode(base64_encoded_str + '===')
    return decoded_bytes

def decode_public_key(public_key):
    """
    Decode base64 encoded public key
    Args:
        public key: base64 encoded string
    Returns:
        python dict/ str
    """
    if type(public_key) is dict:
        return public_key
    try:
        return json.loads(public_key)
    except Exception as e:
        pass

    try:
        return base64_url_decode(public_key)
    except Exception as e:
        pass

    return public_key


def decode_signature(signature):
    """
    Decode base64 encoded signature
    Args:
        signature: base64 encoded string
    Returns:
        byte string
    """
    return base64_url_decode_bytes(signature)


def get_public_key_pem_from_json(jwk_key):
    """
    Creates public key in PEM format from json
    Args:
        jwk_key: dict
    Returns:
        public key in PEM format
    """
    public_key = algorithms.ECAlgorithm.from_jwk(json.dumps(jwk_key))
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem

def verify_signature(public_key_jwk, message, base64_encoded_signature):
    """
    Verifies signature given message and public key
    Args:
        public_key_jwk: dict
        message: message string
        base64_encoded_signature :  base64 encoded string
    Returns:
        True/False
    """
    try:
        # convert JSON formatted string to PEM formatted public key
        public_key_pem = get_public_key_pem_from_json(public_key_jwk)

        # Create key
        key = ECC.import_key(public_key_pem)

        # decode signature
        decoded_signature = decode_signature(base64_encoded_signature)

        encoding = "binary"
        if len(decoded_signature) != 64:
            encoding = "der"

        # encrypt message
        h = SHA256.new(message.encode("utf-8"))

    except Exception as e:
        return False

    try:
        # verify signature
        verifier = DSS.new(key, 'fips-186-3', encoding=encoding)

        verifier.verify(h, decoded_signature)
        return True
    except ValueError:
        return False


def verify_mac(message, secret, hmac):
    """
    Verifies hmac given message and secret
    Args:
        message: message string
        secret: base64 encoded string
        hmac: base64 encoded string
    Returns:
        True/False
    """
    secret = base64_url_decode_bytes(secret)
    message = message.encode("utf-8")
    h = HMAC.new(secret, digestmod=SHA256)
    tag = h.update(message).hexdigest()
    hmac = base64_url_decode_bytes(hmac).hex()
    return tag == hmac


def check_obfuscation(credential):
    """
    Check obfuscation in given credential
    Args:
        credential: dict
    Returns:
        True/False
    """

    if "obfuscation" not in credential:
        return VerificationResult(True, "Credential has no obfuscation attached")

    for obfuscation in credential["obfuscation"]:
        value = obfuscation["val"]
        nonce = obfuscation["nonce"]
        path = obfuscation["path"]

        hmac_code = credential["credentialSubject"]
        for key in path.split("."):
            try:
                hmac_code = hmac_code[key]
            except Exception as e:
                return VerificationResult(False, "Obfuscation check failed, field {0} doesn't exist".format(path),
                                          None, None)

        if not verify_mac(value, nonce, hmac_code):
            return VerificationResult(False, "Obfuscation check failed for field {0}".format(path))

    return VerificationResult(True, "Obfuscation check is successful")
