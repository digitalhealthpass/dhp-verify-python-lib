#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0


class CredentialVerifierParams:
    """ Class that holds parameters required by credential verifier during credential verification
        process. Parameters are set by CredentialVerifierBuilder class."""
    def __init__(self):
        self._credential = None
        self._verifier_credential = None
        self._verifier_credential_decoded = None
        self._healthpass_host_url = None
        self._return_credential = False
        self._return_metadata = False
        self._use_cache_ind = True
        self._display_language = 'en'
        self._extras = None
        self._specification_configuration = None
        self._network_timeout_seconds = 30

    def set_credential(self, credential):
        self._credential = credential

    def set_verifier_credential(self, verifier_credential):
        self._verifier_credential = verifier_credential

    def set_verifier_credential_decoded(self, verifier_credential_decoded):
        self._verifier_credential_decoded = verifier_credential_decoded

    def set_healthpass_host_url(self, healthpass_api_url):
        self._healthpass_host_url = healthpass_api_url

    def set_return_credential(self, return_credential):
        self._return_credential = return_credential

    def set_return_metadata(self, return_metadata):
        self._return_metadata = return_metadata

    def set_metadata_language(self, display_language):
        self._display_language = display_language

    def set_network_timeout(self, seconds):
        self._network_timeout_seconds = seconds

    def set_extras(self, extras):
        self._extras = extras

    def set_specification_configuration(self, specification_configuration):
        self._specification_configuration = specification_configuration

    def get_credential(self):
        return self._credential

    def get_verifier_credential(self):
        return self._verifier_credential

    def get_verifier_credential_decoded(self):
        return self._verifier_credential_decoded

    def get_healthpass_host_url(self):
        return self._healthpass_host_url

    def get_return_credential(self):
        return self._return_credential

    def get_return_metadata(self):
        return self._return_metadata

    def get_metadata_language(self):
        return self._display_language

    def get_network_timeout(self):
        return self._network_timeout_seconds

    def get_extras(self):
        return self._extras

    def get_specification_configuration(self):
        return self._specification_configuration
