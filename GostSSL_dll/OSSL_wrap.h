#pragma once
//no idea again what it does or how it works
#ifdef RVZ_EXPORTS
#define RVZ_API __declspec( dllexport )
#else
#define RVZ_API __declspec( dllimport ) 
#endif


extern "C"
{
	//this is my only exported function that does everything when passed correct arguments
	RVZ_API int operations_handler(int argnum, ...);
}

enum class Command_names;
int new_cms_encrypt(void* cert, void* plaintext, void* cipher);
int cms_encrypt(void* cert, void* plaintext, void* cipher);
int cms_decrypt(void* pkey, void* in_file);
void show_tls_ciphers(void);