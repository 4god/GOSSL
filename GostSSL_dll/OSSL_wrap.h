#pragma once
#ifdef RVZ_EXPORTS
#define RVZ_API __declspec( dllexport )
#else
#define RVZ_API __declspec( dllimport ) 
#endif

//class C
//{
//public:
//	// Encrypt cms message using Gost_Tools
//	static int cms_encrypt(void* cert, void* plaintext, void* cipher);
//	// Decrypt cms message using Gost_Tools
//	static int cms_decrypt(void* pkey, void* ciphertext, void* in_file);
//};

extern "C"
{
	RVZ_API int cms_encrypt(void* cert, void* plaintext, void* cipher);
	RVZ_API int cms_decrypt(void* pkey, void* in_file);
}
