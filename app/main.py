import sys
import os
import tempfile
import posixpath
from PyQt6.QtWidgets import QApplication, QMainWindow, QDialog, QFileDialog, QMessageBox
#from PyQt6 import uic
from simple_gui import Ui_simple_tool
import subprocess


"""helps to deal with paths that appear when using Pyinstaller"""
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


"""helps to initialise our dll and load it in our application|DEPRECATED
def OSSL_dll_init():
    dll_path = resource_path("OpensslGOST_cms_wrapper.dll")
    return cts.windll.LoadLibrary(dll_path)"""


"""
encrypts any content in cms format
cert - is the pathname of the certificate (pubkey) we use to encrypt with
in_file - is the pathname of the file we want to encrypt
ciphername - is the name of the ciphers, but rn it works only with GOST (russian standard cryptography) ciphers|DEPRECATED
def OSSL_dll_cms_encrypt(cert: bytes, in_file: bytes, ciphername: bytes):
    #get pointer to dll itself
    rev_crypto = OSSL_dll_init()
    #in dll there is a variardic function called operations_handler, we now explicitly set which arguments it gets
    rev_crypto.operations_handler.argtypes = [cts.c_int, cts.c_void_p, cts.c_int, cts.c_void_p, cts.c_void_p,
                                              cts.c_void_p]
    #we set the return type of a fucntion
    rev_crypto.operations_handler.restype = cts.c_int
    #number of arguments in variardic functions (excluding argnum itself)
    argnum = cts.c_int(5)
    #path to config file for openssl dll which we call ossl.cnf
    cnf_path = cts.c_char_p(resource_path("ossl.cnf").encode("utf-8"))
    print(f"IN ENCRYPT HANDLER:path to conf = {resource_path('ossl.cnf')}")
    #cmd name is the number of command. 1 - cms_encrypt, 2 - decrypt, 3 - show_available_tls_ciphers
    #Look up code for my dll to look all available options
    cmd_name = cts.c_int(1) #cms_encrypt
    #cast python strings to c_types char pointer
    p1 = cts.c_char_p(cert)
    p2 = cts.c_char_p(in_file)
    p3 = cts.c_char_p(ciphername)
    #now cast char pointers to void pointers and pass it onto dll function
    cts.cast(cnf_path, cts.c_void_p)
    cts.cast(p1, cts.c_void_p)
    cts.cast(p2, cts.c_void_p)
    cts.cast(p3, cts.c_void_p)
    return rev_crypto.operations_handler(argnum, cnf_path, cmd_name, p1, p2, p3)"""


"""
decrypts any content in cms format
pkey - is the pathname of the private key we use to decrypt encrypted cms with pubkey
in_file - is the pathname of the file we want to decrypt|DEPRECATED
def OSSL_dll_cms_decrypt(pkey: bytes, in_file: bytes):
    #if you want to understand how dll works look up comments in def OSSL_dll_cms_encrypt(cert, in_file, ciphername):
    rev_crypto = OSSL_dll_init()
    print("PYTHON:IN DECRYPT HANDLER")
    rev_crypto.operations_handler.argtypes = [cts.c_int, cts.c_void_p, cts.c_int, cts.c_void_p, cts.c_void_p]
    rev_crypto.operations_handler.restype = cts.c_int
    argnum = cts.c_int(4)
    cnf_path = cts.c_char_p(resource_path("ossl.cnf").encode("utf-8"))
    print(f"path to ossl_conf = {resource_path('ossl.cnf')}")
    cmd_name = cts.c_int(2) #cms_decrypt
    p1 = cts.c_char_p(pkey)
    p2 = cts.c_char_p(in_file)
    cts.cast(cnf_path, cts.c_void_p)
    cts.cast(p1, cts.c_void_p)
    cts.cast(p2, cts.c_void_p)
    return rev_crypto.operations_handler(argnum, cnf_path, cmd_name, p1, p2)"""


"""shows all available tls_ciphers|DEPRECATED
def OSSL_dll_show_tls_ciphers():
    # if you want to understand how dll works look up comments in def OSSL_dll_cms_encrypt(cert, in_file, ciphername):
    rev_crypto = OSSL_dll_init()
    rev_crypto.operations_handler.argtypes = [cts.c_int, cts.c_void_p, cts.c_int]
    rev_crypto.operations_handler.restype = cts.c_int
    argnum = cts.c_int(2)
    cnf_path = cts.c_char_p(bytes(resource_path("ossl.cnf"), "utf-8"))
    cmd_name = cts.c_int(3)  # show_tls_ciphers
    cts.cast(cnf_path, cts.c_void_p)
    return rev_crypto.operations_handler(argnum, cnf_path, cmd_name)"""

"""Fill file with zeroes, to secure keys from leaking"""
def zero_fill(filename):
    with open(filename, "r+") as file:
        old = file.read()
        file.seek(0)
        for line in old.splitlines():
            file.write("0" * len(line))



"""
Class for main application in portable mode, "ready to use"
Here Private key, certificate and cipher is already hardcoded
"""
class Encryptor(QDialog, Ui_simple_tool):
    chosen_file = "From_Dato_With_Love"
    #created using gost2012_256
    PRIVATE_KEY_AS_STRING = "-----BEGIN PRIVATE KEY-----\n\
MEYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEIHRapkdXQDVM\n\
40WTP7nk4hAADorBGeF6ZygU6H2nWyM2\n\
-----END PRIVATE KEY-----\n\
"
    CERTIFICATE_AS_STRING = "-----BEGIN CERTIFICATE-----\n\
MIICITCCAcygAwIBAgIUKQT02fYjQOslDsLOJXQDO/UoCjgwDAYIKoUDBwEBAwIF\n\
ADBhMQswCQYDVQQGEwJHRzELMAkGA1UECAwCR0cxCzAJBgNVBAcMAkdHMQswCQYD\n\
VQQKDAJHRzELMAkGA1UECwwCR0cxCzAJBgNVBAMMAkdHMREwDwYJKoZIhvcNAQkB\n\
FgJHRzAeFw0yMzA3MTMxMjA2MjhaFw0yMzA4MTIxMjA2MjhaMGExCzAJBgNVBAYT\n\
AkdHMQswCQYDVQQIDAJHRzELMAkGA1UEBwwCR0cxCzAJBgNVBAoMAkdHMQswCQYD\n\
VQQLDAJHRzELMAkGA1UEAwwCR0cxETAPBgkqhkiG9w0BCQEWAkdHMGYwHwYIKoUD\n\
BwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIDQwAEQBoSZiIAIV8C2NK8fjatwFp9\n\
OIhRNykOgVvKdKTS2Yux+OuWdIrxzY9QW7PfTTF2Oz/OUNpA4I7JRzXlcEJnFcOj\n\
UzBRMB0GA1UdDgQWBBTtpztXS59WAcoplUcJT6vM2ioQpDAfBgNVHSMEGDAWgBTt\n\
pztXS59WAcoplUcJT6vM2ioQpDAPBgNVHRMBAf8EBTADAQH/MAwGCCqFAwcBAQMC\n\
BQADQQDB+OqkeMQbH2TlStkrKoYBhjqsTLVUVJKGFZCiYnYBLvBSsc/81zhyxTfj\n\
k7UofpbqnKBen6YihqkpFdtIKV4R\n\
-----END CERTIFICATE-----\n\
"

    def __init__(self):
        #init ui
        QDialog.__init__(self)
        self.setupUi(self)
        #init buttons and their clicked events
        self.label_execute.setEnabled(False)
        self.label_choose.clicked.connect(self.browsefiles)
        self.label_execute.clicked.connect(self.execution)
        #make openssl.exe load OUR config
        os.environ["OPENSSL_CONF"] = resource_path("ossl.cnf")
        #show ui
        self.show()

    """browse and choose files to encrypt or decrypt"""
    def browsefiles(self):
        dialog = QFileDialog()#opens up browse file dialog
        fname = dialog.getOpenFileName(self, 'Select file')#gets selected file from the dialog
        self.label_filename.setText(fname[0])
        self.chosen_file = fname[0]
        if self.chosen_file.rfind(".enc") > 0:
            self.label_execute.setText("Расшифровать")
        else:
            self.label_execute.setText("Зашифровать")
        self.label_execute.setEnabled(True)

    """execute encryption or decryption"""
    def execution(self):
        pathname = str(self.chosen_file)
        if pathname.rfind(".enc") > 0:
            try:
                pkey = tempfile.NamedTemporaryFile(suffix='.pem', prefix='RVZ', mode="w+t", delete=False)
                pkey.write(self.PRIVATE_KEY_AS_STRING)
                pkey.flush()
                pkey.close()
                pkeypath = str(pkey.name).replace(os.sep, posixpath.sep)
                cipher = "gost89"#name of the symmetric cipher, there are others in GOST-engine
                ossl_exe = resource_path("OpenSSL/bin/openssl.exe")
                proc = subprocess.getstatusoutput(f"{ossl_exe} cms -decrypt -in {pathname} -{cipher} -out {pathname + '.dec'} -inform PEM -inkey {pkeypath} -binary")
                print("Process  output: ", str(proc[1]))
                exitcode = proc[0]
                if exitcode == 0:
                    QMessageBox.information(self, 'DECRYPTED', "SUCCESS")
                else:
                    QMessageBox.information(self, 'Error', "Something went wrong while decrypting")
                zero_fill(pkey.name)
                os.unlink(pkey.name)
            except Exception as exc:
                print("Some exception has occured, try to make sure the files are fine and they exist."
                      "Exeption: ", exc)
        else:
            try:
                cert = tempfile.NamedTemporaryFile(suffix='.pem', prefix='RVZ', mode="w+t", delete=False)
                cert.write(self.CERTIFICATE_AS_STRING)
                cert.flush()
                cert.close()
                certpath = str(cert.name).replace(os.sep, posixpath.sep)
                cipher = "gost89"
                ossl_exe = resource_path("OpenSSL/bin/openssl.exe")
                proc = subprocess.getstatusoutput(f"{ossl_exe} cms -encrypt -in {pathname} -{cipher} -out {pathname + '.enc'} -inform PEM -recip {certpath} -outform PEM -binary")
                print("Process  output: ", str(proc[1]))
                exitcode = proc[0]
                if exitcode == 0:
                    QMessageBox.information(self, 'ENCRYPTED', "SUCCESS")
                else:
                    QMessageBox.information(self, 'Error', "Something went wrong while encrypting")
                zero_fill(cert.name)
                os.unlink(cert.name)
            except Exception as exc:
                print("Some exception has occured, try to make sure the files are fine and they exist."
                      "Exeption: ", exc)
        self.chosen_file = ""
        self.label_execute.setEnabled(False)

'''class EncryptorEXT(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = uic.loadUi('based.ui', self)

        # authenticate when the login button is clicked
        #self.ui.btn_login.clicked.connect(self.authenticate)

        self.show()

        def authenticate(self):
        email = self.email_line_edit.text()
        password = self.password_line_edit.text()

        if email == 'john@test.com' and password == '123456':
            QMessageBox.information(self, 'Success', "You're logged in!")
        else:
            QMessageBox.critical(self, 'Error', "Invalid email or password.")'''


if __name__ == '__main__':
    print("Python {:s} {:03d}bit on {:s}\n".format(" ".join(elem.strip() for elem in sys.version.split("\n")),
                                                   64 if sys.maxsize > 0x100000000 else 32, sys.platform))
    app = QApplication(sys.argv)#Get system arguments and init QT_class
    if "-extended" in sys.argv:
        pass
        #extended_window = EncryptorEXT()
    else:
        encryptor_window = Encryptor()
    sys.exit(app.exec())



