#pragma once
#define _CRT_SECURE_NO_WARNINGS // to silence warnings like: use _sscanf instead of scanf
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING //to silence warning about less than C++17 standart
#define OPENSSL_SUPPRESS_DEPRECATED //to silence 90% of warnings in this library
#pragma comment(lib, "libssl.lib") //i have no idea how this works and what it does
#pragma comment(lib, "libcrypto.lib") //same here

#include <windows.h>
#include <stdio.h>
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <functional>
#include <experimental/filesystem> //this lib helps to deal with non-english path names
#include <sys/stat.h>
#include <sys/types.h>
#include <algorithm>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <share.h>
#include <io.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
