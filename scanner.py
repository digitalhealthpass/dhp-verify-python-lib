#
# (c) Copyright Merative US L.P. and others 2020-2022 
#
# SPDX-Licence-Identifier: Apache 2.0

import tkinter as tk
from tkinter import scrolledtext
from tkinter import filedialog
from PIL import Image
from pyzbar.pyzbar import decode
import jsonpickle
import base64
import traceback

from multi_cred_verifier_python.verifier.credential_verifier_builder import CredentialVerifierBuilder
from multi_cred_verifier_python.verifier.verification_result import VerificationResult

builder = None

window = tk.Tk()
window.geometry("800x600")

from tkinter.ttk import *

host_label = Label( window, text = "Healthpass Host" )
host_label.place(x = 150, y = 5)

default_host_url= tk.StringVar(value = "https://sandbox1.wh-hpass.dev.acme.com")
host_url_entry = Entry(window, textvariable=default_host_url, width = 50)
host_url_entry.place( x = 275, y = 5 )

default_metadata_language = tk.StringVar(value = "en")
metadata_language_entry  = Entry(window, textvariable=default_metadata_language, width = 2)
metadata_language_entry.place( x = 275, y = 35 )

host_label = Label( window, text = "Metadata Language" )
host_label.place(x = 150, y = 35)

output = scrolledtext.ScrolledText(window, 
                                      wrap = tk.WORD, 
                                      width = 120, 
                                      height = 35, 
                                      font = ("Times New Roman", 12))  
output.place(x = 5, y = 75)

def scan():
    global builder

    output.delete('0.0', tk.END)
    
    file_path = filedialog.askopenfilename()

    if not file_path:
        output.insert(tk.INSERT, 'No credential selected')
        return

    img = Image.open(file_path)
    result = decode(img)

    decoded = result[0].data.decode("utf-8")

    try:
        if is_verifier_credential(decoded):
            verify_response: VerificationResult = get_builder(decoded, True).init()
            if not verify_response.success:
                verify_result = jsonpickle.encode(verify_response, unpicklable=False, indent=2)
            else:
                verify_result = "Initialized"
        else:
            verify_result = get_builder(decoded) \
                .set_credential(decoded) \
                .set_metadata_language(metadata_language_entry.get()) \
                .build() \
                .verify()
            verify_result = jsonpickle.encode(verify_result, unpicklable=False, indent=2)
    except Exception as e:
        traceback.print_exc()
        verify_result = str(e)
    output.insert(tk.INSERT, verify_result)

def get_builder(credential, new_instance = False): 
    global builder

    if builder is None or new_instance:
        builder = CredentialVerifierBuilder() \
            .set_healthpass_host_url(host_url_entry.get()) \
            .set_verifier_credential(credential) \
            .set_return_credential(True) \
            .set_return_metadata(True)
    return builder

def is_verifier_credential(credential):
    if "VerifierCredential" in credential:
        return True
    try:
        decoded = str(base64.b64decode(credential))
        if "VerifierCredential" in decoded:
            return True
    except Exception as e:
        pass
    return False

scan_button = Button(window, text = 'Scan', command = scan)
# scan_button.config(height = 100)
scan_button.place(x = 5, y = 5)

window.mainloop()
