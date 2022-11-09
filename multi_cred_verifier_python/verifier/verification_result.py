#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0


class VerificationResult:
    def __init__(
        self,
        success,
        message,
        cred_type = None,
        credential = None,
        warnings = None,
        error = None
    ):
        self.success = success
        self.message = message
        self.cred_type = cred_type
        self.credential = credential
        self.warnings = warnings
        self.error = error
        self.metadata = None
        self.category = None

    def clean_result(self):
        if self.cred_type == None:
            del self.cred_type
        if  self.credential == None:
            del self.credential
        if self.warnings == None:
            del self.warnings
        if self.error == None:
            del self.error
        if self.metadata == None:
            del self.metadata
        if self.category == None:
            del self.category
        return self
