#include "OpenSSL.h"

//consider using smart pointers in future
/*using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;*/

//This is entry point to dll when it loads
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        std::cout << "OSSLGost_wrapper.dll was loaded" << std::endl;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
//junk function
extern "C" __declspec (dllexport) bool example()
{
    MessageBoxA(NULL, "Loaded", "test", NULL);
    return true;
}
