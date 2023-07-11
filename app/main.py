import ctypes as cts
import sys
import os
import tempfile
from PyQt6.QtWidgets import QApplication, QMainWindow, QDialog, QFileDialog, QMessageBox
#from PyQt6 import uic
from simple_gui import Ui_simple_tool


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def OSSL_dll_init():
    dll_path = resource_path("OpensslGOST_cms_wrapper.dll")
    LIBCRYPTO = dll_path
    rev_crypto = cts.windll.LoadLibrary(LIBCRYPTO)
    return rev_crypto


def OSSL_dll_cms_encrypt(cert, in_file, ciphername):
    rev_crypto = OSSL_dll_init()
    rev_crypto.cms_encrypt.argtypes = [cts.c_void_p, cts.c_void_p, cts.c_void_p]
    rev_crypto.cms_encrypt.restype = cts.c_int
    p1 = cts.c_char_p(bytes(cert, "utf-8"))
    p2 = cts.c_char_p(bytes(in_file, "utf-8"))
    cts.cast(p1, cts.c_void_p)
    cts.cast(p2, cts.c_void_p)
    return rev_crypto.cms_encrypt(p1, p2, "ciphername")


def OSSL_dll_cms_decrypt(pkey, in_file):
    rev_crypto = OSSL_dll_init()
    rev_crypto.cms_decrypt.argtypes = [cts.c_void_p, cts.c_void_p]
    rev_crypto.cms_decrypt.restype = cts.c_int
    p1 = cts.c_char_p(bytes(pkey, "utf-8"))
    p2 = cts.c_char_p(bytes(in_file, "utf-8"))
    cts.cast(p1, cts.c_void_p)
    cts.cast(p2, cts.c_void_p)
    return rev_crypto.cms_decrypt(p1, p2)


class Encryptor(QDialog, Ui_simple_tool):
    chosen_file = ""
    PRIVATE_KEY_AS_STRING = "-----BEGIN PRIVATE KEY-----\n\
MEYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIEIDFgA7CXw2gN\n\
boA824Zdj3PalWzVEO9IKFNkXnWZ736r\n\
-----END PRIVATE KEY-----\n\
"
    CERTIFICATE_AS_STRING = "-----BEGIN CERTIFICATE-----\n\
MIICFjCCAcGgAwIBAgIJAICCAucev9drMAwGCCqFAwcBAQMCBQAwYTELMAkGA1UE\n\
BhMCR0UxCzAJBgNVBAgMAkdFMQswCQYDVQQHDAJHRTELMAkGA1UECgwCR0UxCzAJ\n\
BgNVBAsMAkdFMQswCQYDVQQDDAJHRTERMA8GCSqGSIb3DQEJARYCR0UwHhcNMjMw\n\
NTMwMTUyNjE5WhcNMjQwNTI5MTUyNjE5WjBhMQswCQYDVQQGEwJHRTELMAkGA1UE\n\
CAwCR0UxCzAJBgNVBAcMAkdFMQswCQYDVQQKDAJHRTELMAkGA1UECwwCR0UxCzAJ\n\
BgNVBAMMAkdFMREwDwYJKoZIhvcNAQkBFgJHRTBmMB8GCCqFAwcBAQEBMBMGByqF\n\
AwICIwEGCCqFAwcBAQICA0MABEA1ZLPyVB1NNQxg0nxd+PIPEJQSkx9Pv1qIYy1s\n\
viRb/etHFyFeHtUNlQ4anQX9o1iRYVB/6eXZR9xiZb6a4+k5o1MwUTAdBgNVHQ4E\n\
FgQUitmQNrU0ioO1fYr31tmKpC4Am/YwHwYDVR0jBBgwFoAUitmQNrU0ioO1fYr3\n\
1tmKpC4Am/YwDwYDVR0TAQH/BAUwAwEB/zAMBggqhQMHAQEDAgUAA0EAsysfTh0U\n\
JMP9p5j+G1/2cMjbDVNQSm03HqEA3x4CL6vIwXTClKTFzneN+m35FaviAygI5mnl\n\
9FYtbH0UUEKn+w==\n\
-----END CERTIFICATE-----\n\
"
    RSA_KEY = "-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDkGj0TEz9Oafi4\n\
dehP5X2n7rpinNtb+GWdqqTQBwkiCg0IJ5MwZsV7+szmrlGz1cExyqMvrWuq9Fwb\n\
8M5ImR3cmLqkJZDgw+36r1SFMwOC6FZhE8kPhb4nM165DH1fhUL/FYp8e6AFrfjx\n\
5Z9GtaWZkE/JR75ufZ+3XDpy+cW7cOzkMLTaLR9PZiQ1+iPA/DlAqsoh9urzVE4m\n\
7M2g7nN3cSXYmvnFoBokxIBohG7eud79MNsA4SXw/h9tecKM1wY5SoTl7KOOM8YO\n\
RKdyi4CY8eDnKkjoV3LKcXBYEWdYJ787ljkoHk4AajYwjrUwPWnikHQ4zklDxndW\n\
wNHJxuGdAgMBAAECggEADPzPeGwSoTDYeAxCl3X+IxctJps+xCxPANyr+KpF41nG\n\
Jy41q75WRTpg+0t2nHIxx1d91iOeK0QxkGe0Hx8Uu7A4hEsdRibxwGHGQrVGYGhB\n\
LtLVElyvmITMwmWLJ+qrB2IfGfpiAKDIuWE1Ie4KyUUVveSnW5wsgWCvdUdycjse\n\
xIvrEU8RVAGImOsq8cg+GkBH/WesoY1m60o4+8aghxI2oqc5Q2o7r0sjyamrGPQE\n\
X5b2vH3lGLWec7hW2G5KJ3PePFWDEs6V96OGJdC/qO8OYSmPxlJVxFf4OjrZXzig\n\
pK/pUmgxBZNHe68bDRs6VLM2TVIbziHiAvRZkByZkQKBgQD0/99MzHcW212MEQPD\n\
IHFf+Nn39zeemFlk8PCTvaQmh+nOkcYywHTIagHfEHvGnx3cD6ZXIJPPENk5imum\n\
fYshEaJXmmB0LdwmgDgkBCY9zUuAtfct9Rqk2qKS/9MX78Jyke3BX+70Eqgzpnis\n\
lOWfLZkhX2XNmk1xmd+C0totRQKBgQDuWCUdMJZli5vh5e4wQ5HR8LH3aCM4GfCw\n\
1q7a53eyQHdXfdy1AHhSWFu3jRpW6KUCtvoUOXIJe1kyxR+Qq4BE8gGXPemY50cS\n\
E2IueY0Nt4il8td0AfIfJyf6URGkKiL3tT+jfvK1kR7LWV7OuU3h+A8YXHM2C6sG\n\
kn3dOEtMeQKBgQDpYXh4Mulal5qUG30m+hel4WrZH+EWrW+yjSXOxr7AiYW6ZfiU\n\
TeqxIvInaA9QVDBgeXPt2TWT8SvL+US0szC+TosDwiYRZcIp1sgj3uQCyTYcJLqS\n\
R8KauT5Wo2WVjqn+8221YEpCrCcYFIMteyUFLa2KMdLLOSp+haJ5f5uftQKBgQCd\n\
GTJVXBo1kmDL898cptztkQXsuhJEvyxbkxWrqdfGgSFoZMhd8ZJdTGofwPy0fiGN\n\
eYe6XubggxIXGcElfTVNvGn6A0/+farlqisT0QB9IxUJtNf4WfP6PrfmERtcpn1n\n\
4mqw3FMkBCRVCnIoNhG0uOlSOFWkMOqoqVQWxS00mQKBgQDoIX20DgpXlFjcsgXx\n\
bXQLOESwdz62Q6LWqg6y3uZXsoNRF36Ga0hVilUgJ6cn/zrFYLkKtMFvvZjuz1zm\n\
dM0qZRQIUykRFmoKo6HOJdM2aCT/6eeFkvqLmvVBsMfCAUUrEdSsWxoLR7yhnWNk\n\
fZOAUth5xCpkNjaZNZmRzemqig==\n\
-----END PRIVATE KEY-----\n\
"
    RSA_CERT = "-----BEGIN CERTIFICATE-----\n\
MIIDcTCCAlmgAwIBAgIULDoJUnqmWqa4MhNIcdxHdL9RmYYwDQYJKoZIhvcNAQEL\n\
BQAwYTELMAkGA1UEBhMCQVUxCzAJBgNVBAgMAkFVMQswCQYDVQQHDAJBVTELMAkG\n\
A1UECgwCQVUxCzAJBgNVBAsMAkFVMQswCQYDVQQDDAJBVTERMA8GCSqGSIb3DQEJ\n\
ARYCQVUwHhcNMjMwNzA3MTMwNDMzWhcNMjQwNzA2MTMwNDMzWjBhMQswCQYDVQQG\n\
EwJBVTELMAkGA1UECAwCQVUxCzAJBgNVBAcMAkFVMQswCQYDVQQKDAJBVTELMAkG\n\
A1UECwwCQVUxCzAJBgNVBAMMAkFVMREwDwYJKoZIhvcNAQkBFgJBVTCCASIwDQYJ\n\
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOQaPRMTP05p+Lh16E/lfafuumKc21v4\n\
ZZ2qpNAHCSIKDQgnkzBmxXv6zOauUbPVwTHKoy+ta6r0XBvwzkiZHdyYuqQlkODD\n\
7fqvVIUzA4LoVmETyQ+FviczXrkMfV+FQv8Vinx7oAWt+PHln0a1pZmQT8lHvm59\n\
n7dcOnL5xbtw7OQwtNotH09mJDX6I8D8OUCqyiH26vNUTibszaDuc3dxJdia+cWg\n\
GiTEgGiEbt653v0w2wDhJfD+H215wozXBjlKhOXso44zxg5Ep3KLgJjx4OcqSOhX\n\
cspxcFgRZ1gnvzuWOSgeTgBqNjCOtTA9aeKQdDjOSUPGd1bA0cnG4Z0CAwEAAaMh\n\
MB8wHQYDVR0OBBYEFFHbErm+RrAfE7WrZKU3xdqzxjVNMA0GCSqGSIb3DQEBCwUA\n\
A4IBAQA9wM4egFjhlD/8q2S86ilGG9fJUJdLiwe8t/NT6jAjY7ukRVIBL25/UeHs\n\
ZwTCVYx2+vJX8Mz/3+sWsCCK1OiXHOsRq0nmybhR60tgqDVLi53xJ/1oJvfDZT3V\n\
s7D16jn0+9UjQmKSKV2BBP5QBmkgwsV498Dhhov64ZpkaLxeKBXYFdw/LuBiBn81\n\
diYgxAlMzmqwUTEX9P/Hknwg+kPJ+hjD4YDqDLYO6xNJCWE6Qw1eQ73P+dZIDRVU\n\
pOXrBKQvP10ogoWtVzC1e7AyfAZNOJTyWSttRdMnpUWqWdcEq2OIR9xdQjl6VOqY\n\
2L+Bmr3cdl28Ic4w8ojpNuLV01CU\n\
-----END CERTIFICATE-----\n\
"

    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
        self.label_choose.clicked.connect(self.browsefiles)
        self.label_execute.clicked.connect(self.execution)
        self.show()

    def browsefiles(self):
        dialog = QFileDialog()
        fname = dialog.getOpenFileName(self, 'Select file')
        self.label_filename.setText(fname[0])
        self.chosen_file = fname[0]
        if self.chosen_file.rfind(".enc") > 0:
            self.label_execute.setText("Расшифровать")
        else:
            self.label_execute.setText("Зашифровать")

    def execution(self):
        pathname = str(self.chosen_file)
        if pathname.rfind(".enc") > 0:
            pkey = tempfile.NamedTemporaryFile(delete=False)
            pkey.write(bytes(self.RSA_KEY, "utf-8"))
            pkey.close()
            res = OSSL_dll_cms_decrypt(pkey.name, pathname)
            if res == 0:
                QMessageBox.information(self, 'DECRYPTED', "SUCCESS")
            else:
                QMessageBox.information(self, 'Error', "Something went wrong while decrypting")
            os.unlink(pkey.name)
        else:
            cert = tempfile.NamedTemporaryFile(delete=False)
            cert.write(bytes(self.RSA_CERT, "utf-8"))
            cert.close()
            res = OSSL_dll_cms_encrypt(cert.name, pathname, "ciphername")
            if res == 0:
                QMessageBox.information(self, 'ENCRYPTED', "SUCCESS")
            else:
                QMessageBox.information(self, 'Error', "Something went wrong while encrypting")
            os.unlink(cert.name)


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
    cts.windll.kernel32.SetDllDirectoryW(None)
    app = QApplication(sys.argv)
    if "-extended" in sys.argv:
        pass
        #extended_window = EncryptorEXT()
    else:
        encryptor_window = Encryptor()
    sys.exit(app.exec())
