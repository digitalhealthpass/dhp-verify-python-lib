#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

from enum import Enum

class CredType(Enum):
    """Type definition for Credential Type"""
    IDHP = 'IDHP'
    GHP = 'GHP'
    VC = 'VC'
    SHC = 'SHC'
    DCC = 'DCC'
    DIVOC = 'DIVOC'
    UNKNOWN = 'UNKNOWN'


class EUCredKeys(Enum):
    """Type definition for Credential Keys"""
    ISSUING_COUNTRY = 1
    CREDENTIAL = -260
    ISSUANCEDATE = 6
    EXPIRATIONDATE = 4

HEALTHPASS_PATH = '/api/v1/hpass'
METERING_PATH = '/api/v1/metering'
VERIFIER_CONFIG_PATH = '/api/v1/verifier/config/api/v1'

ISSUER_ID = "hpass.issuer1"

PAGE_SIZE = 100

VERIFIER_CRED_EXPIRATION_WARNING_PERCENT = .50
CACHE_EXPIRATION_WARNING_PERCENT = .50

SCANS_BEFORE_SENDING_METERING = 100
SECONDS_BEFORE_SENDING_METERING = 3600 # One hour
RETRY_SECONDS_SENDING_METERING = 60 # One minute
