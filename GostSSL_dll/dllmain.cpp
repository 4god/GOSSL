﻿#include <windows.h>
#include <string>
std::string test = "not Loaded";
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    test = "loaded"; //You also change on this location the value of a variable
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "OSSLGOSTWrapper", "DLL loaded succesfully", NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
extern "C" __declspec (dllexport) bool example()
{
    MessageBoxA(NULL, test.c_str(), "test", NULL);
    return true;
}