#include "OSSL_wrap.h"
#include "OpenSSL.h"
#define CHUNK_SIZE 390 * 1024 * 1024 //to split large files into chunks

// Here is the list of all available operations
enum class Command_names { cms_encrypt = 1, cms_decrypt = 2, show_tls_ciphers = 3};
int sizeofFile(const std::string& address);
/*
This is exported function. It should be called by python executable and it recieves
variardic arguments and it handles all available operations.
argnum - number of following arguments
... - arguments for available functions like cms_encrypt/decrypt etc.
*/
int operations_handler(int argnum, ...)
{
    int ret = EXIT_FAILURE, cmd_num = -1, split_file = 0, file_size = -1, chunks_num = -1;
    Command_names cmd_name;
    const char* ossl_conf_path = NULL;
    va_list args;
    va_start(args, argnum);
    std::string temp_name, filenameAsm("OPENSSL_CONF="), tmpfilenames("RVZ_TMP_CHUNK_");;
    //get path passed via python executable (also supports Cyrillyc path)
    temp_name = va_arg(args, const char*);
    std::cout << "DEBUG: temp_path = " << temp_name << std::endl;
    std::experimental::filesystem::path ossl_path = temp_name.c_str();
    std::cout << "DEBUG: excremental_path = " << ossl_path << std::endl;
    filenameAsm.append(ossl_path.string());
    //set OSSL_CONF env for openssl
    _putenv(filenameAsm.c_str());
    filenameAsm = "ENGINESDIR=";
    filenameAsm.append(ossl_path.string().append("\gost\gost.dll").c_str());
    _putenv(filenameAsm.c_str());
    OPENSSL_config(ossl_path.string().c_str());
    OPENSSL_add_all_algorithms_conf();
    std::cout << "DEBUG: environ = " << filenameAsm.c_str() << std::endl;
    //load engines and algorithms
    ENGINE* E = ENGINE_by_id("gost");
    if (!E)
    {
        fprintf(stderr, "Couldn't load gost engine\n");
        fprintf(stderr, "Path to config from environ: ");
        fprintf(stderr, filenameAsm.c_str());
        fprintf(stderr, "\n");
        return -1;
    }
    std::cout << "DEBUG: engine = " << E << std::endl;
    ENGINE_free(E);
    cmd_num = va_arg(args, int);
    const char* cert_or_key = va_arg(args, const char*);
    const char* plain_or_ciphered = va_arg(args, const char*);
    file_size = sizeofFile(plain_or_ciphered);
    if (file_size > CHUNK_SIZE)//if file is over 400MB
    {
        split_file = 1;
        chunks_num = (file_size / CHUNK_SIZE) + 1;
        std::cout << "GIGACHAD" << std::endl;
    }
    else
    {
        std::cout << "smol pp" << std::endl;
    }
    switch (cmd_num)
    {
    case 1:
    {
        cmd_name = Command_names::cms_encrypt;
        break;
    }
    case 2:
    {
        cmd_name = Command_names::cms_decrypt;
        break;
    }
    case 3:
    {
        cmd_name = Command_names::show_tls_ciphers;
        break;
    }
    default:
    {
        std::cout << "The number of command " << cmd_num << " is shit" << std::endl;
        return ret;
    }
    }
    switch (cmd_name)
    {
    case Command_names::cms_encrypt:
    {
        const char* ciphername = va_arg(args, const char*);
        /*if (split_file)
        {
            std::string begin("-----BEGIN CMS-----");
            std::string end("-----END CMS-----");
            std::ifstream bigFile(plain_or_ciphered);
            constexpr size_t bufferSize = CHUNK_SIZE;
            std::unique_ptr<char[]> buffer(new char[bufferSize]);
            int ciphered_rows_num = 0, longest_row = 0, last_row = 0;
            for (int i = 0; i < chunks_num; i++)
            {
                int row_num = 1;
                std::string tmp = tmpfilenames.append(std::to_string(i)), temp;
                std::ofstream f(tmp);
                bigFile.read(buffer.get(), bufferSize);
                //создать файлы, ЗАПИСАТЬ В ФАЙЛЫ, выполнить для каждого енкрипт, удалить в первой итерации конец, в последней итерации начало, в остальных оба
                f.write(buffer.get(), sizeof(buffer.get()));
                f.close();
                cms_encrypt((void*)cert_or_key, (void*)tmp.c_str(), (void*)ciphername);
                std::string enc_filename = tmp.append(".enc").c_str();
                std::ifstream enc_file(enc_filename);
                std::ofstream new_enc_file("");
                if (i == 0)
                {
                    int j = 0;
                    while (enc_file >> temp)
                    {
                        j++;
                        if (j > 1)
                            longest_row = temp.length() > longest_row ? temp.length() : longest_row;
                    }
                    
                    ciphered_rows_num = j;
                    j = 0; 
                    enc_file.clear();
                    enc_file.seekg(0);
                    while (enc_file >> temp)
                    {
                        j++;
                        if (j < 3)
                            continue;
                        else if (j > ciphered_rows_num - 2)
                            break;
                        new_enc_file << temp;
                    }
                    enc_file.close();
                    new_enc_file.close();
                    remove(enc_filename.c_str());
                    if (rename(enc_filename.append(".modified").c_str(), enc_filename.c_str()) != 0)
                    {
                        std::cout << "file не переименовался" << std::endl;
                        return -1;
                    }
                    std::ifstream new_efile(enc_filename.c_str());
                    new_efile.clear();
                    new_efile.seekg(0);
                    j = 0;
                    std::cout << "before reading from new file" << std::endl;
                    while (new_efile >> temp)
                    {
                        j++;
                        std::cout << j << " ";
                        std::cout << temp << std::endl;
                    }
                    new_efile.close();
                    return -1;
                }
            }
            break;
        }*/
        //ret = cms_encrypt((void*)cert_or_key, (void*)plain_or_ciphered, (void*)ciphername);        
        ret = new_cms_encrypt((void*)cert_or_key, (void*)plain_or_ciphered, (void*)ciphername);
        break;
    }
    case Command_names::cms_decrypt:
    {
        ret = cms_decrypt((void*)cert_or_key, (void*)plain_or_ciphered);
        break;
    }
    case Command_names::show_tls_ciphers:
    {
        show_tls_ciphers();
        ret = EXIT_SUCCESS;
        break;
    }
    default:
    {
        std::cout << "There is no command name as whatever you passed here" << std::endl;
        break;
    }
    }
    va_end(args);
    return ret;
}

/*
Function that displays available ciphers
*/
void show_tls_ciphers(void)
{
    SSL_CTX* ctx;
    SSL* ssl;
    int i;
    const char* cipher_name;
    int priority = 0;
    //if we change TLS_method() to something else it will probably show other ciphers but idk
    ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
    }

    STACK_OF(SSL_CIPHER)* sk = SSL_get_ciphers(ssl);
    if (!sk) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        SSL_free(ssl);
        return;
    }

    for (i = 0; i < sk_SSL_CIPHER_num(sk); ++i) {
        std::cout << SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)) << std::endl;;
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

/*
encrypts any content in cms with the support of GOST (russian standard cryptography)
cert - path of certificate file, that we use to encrypt the message and get pubkey from it
plaintext - path of plain file that we wish to encrypt
cipher - name of cipher in russian GOST
*/
int new_cms_encrypt(void* cert, void* plaintext, void* cipher)
{
    /* converting inputs from void* to normal types */
    const char* icert = (const char*)cert;
    const char* ifile = (const char*)plaintext;
    const char* cipher_name = (const char*)cipher;
    std::string encoded_file = "";
    encoded_file = ifile;
    encoded_file.append(".enc");
    int err_code = 0, ret = EXIT_FAILURE, flags = PKCS7_BINARY | PKCS7_STREAM ;
    /* start initialising variables for openssl */
    struct _stat sb;
    off_t len;
    void* p;
    int fd;
    const EVP_CIPHER* symmetric_gost = EVP_get_cipherbyname(cipher_name);
    if (!symmetric_gost)
    {
        fprintf(stderr, "Couldn't fetch that cipher: ");
        fprintf(stderr, cipher_name);
        fprintf(stderr, "\n");
        err_code++;
    }
    BIO* in_file = NULL, * bio = NULL, * out = NULL;
    X509* rcert = NULL;
    PKCS7* cms = PKCS7_new();
    CMS_RecipientInfo* ri = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    auto recips = sk_X509_new_null();

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    bio = BIO_new_file(icert, "r");

    if (!bio)
        goto err;

    rcert = PEM_read_bio_X509(bio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /*
     * sk_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    in_file = BIO_new_file(ifile, "r");

    if (!in_file)
        goto err;

    /* encrypt content */
    cms = PKCS7_encrypt(recips, in_file, symmetric_gost, flags);

    if (!cms)
        goto err;

    out = BIO_new_file(encoded_file.c_str(), "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_PKCS7(out, cms, in_file, flags))
        goto err;

    ret = 0;

err:

    if (ret) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    PKCS7_free(cms);
    //CMS_ContentInfo_free(cms);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(in_file);
    BIO_free(out);
    BIO_free(bio);
    return ret;
}

int cms_encrypt(void* cert, void* plaintext, void* cipher) {
    /* converting inputs from void* to normal types */
    const char* icert = (const char*)cert;
    const char* ifile = (const char*)plaintext;
    const char* cipher_name = (const char*)cipher;
    std::string encoded_file = "";
    encoded_file = ifile;
    encoded_file.append(".enc");
    int err_code = 0, ret = EXIT_FAILURE, flags = CMS_BINARY | CMS_PARTIAL;// | CMS_STREAM;
    /* start initialising variables for openssl */
    struct _stat sb;
    off_t len;
    void* p;
    int fd;
    const EVP_CIPHER* symmetric_gost = EVP_get_cipherbyname(cipher_name);
    if (!symmetric_gost)
    {
        fprintf(stderr, "Couldn't fetch that cipher: ");
        fprintf(stderr, cipher_name);
        fprintf(stderr, "\n");
        err_code++;
    }
    BIO* in_file = NULL, *bio = NULL, *out = NULL;
    X509* rcert = NULL;
    CMS_ContentInfo* cms = CMS_ContentInfo_new();
    CMS_RecipientInfo* ri = NULL;
    EVP_PKEY_CTX* pctx = NULL;

    std::cout << "DEBUG: cipher_name = " << cipher_name << std::endl;
    /* Read in file and create BIO sructure from it */
    bio = BIO_new_file(icert, "r");
    if (!bio) 
    {
        fprintf(stderr, "Couldn't read recipient certificate\n");
        err_code++;
    }

    std::cout << "DEBUG: icert = " << icert << std::endl;
    std::cout << "DEBUG: BIO_icert = " << bio << std::endl;

    /* Read in recipient certificate from BIO */
    rcert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!rcert)
    {
        fprintf(stderr, "Bad certificate\n");
        err_code++;
    }
    std::cout << "DEBUG: READ X509 = " << rcert << std::endl;

    /* Open plaintext file and create BIO structure from it 
    _sopen_s(&fd, ifile, _O_RDONLY, _SH_DENYWR, _S_IREAD);
    if (fd == -1)
    {
        fprintf(stderr, "cant sopens input file\n");
        err_code++;
    }
    _fstat(fd, &sb);
    _close(fd);

    in_file = BIO_new_file(ifile, "r");
    if (!in_file)
    {
        fprintf(stderr, "Can't open input file\n");
        err_code++;
    }
    */
    std::cout << "DEBUG: ifile = " << ifile << std::endl;
    std::cout << "DEBUG: BIO_in_file = " << in_file << std::endl;
    /* Create outpur file and create BIO from it */
    out = BIO_new_file(encoded_file.c_str(), "w");
    if (!out)
    {
        fprintf(stderr, "Can't create output file\n");
        err_code++;
    }

    /* Partially start cms encryption.
    in - is our BIO file with plaintext
    symmetric_gost - is a symmetric cipher from russian standarts GOST, you need gost engine for this to work (gost engine was initialised in dllmain.cpp)
    flags - CMS_BINARY and CMS_PARTIAL */
    cms = CMS_encrypt(NULL, in_file, symmetric_gost, flags);
    if (!cms)
    {
        fprintf(stderr, "Couldn't create pkcs7EnvelopedData\n");
        err_code++;
    }

    /* Read recipient info from certificate */
    ri = CMS_add1_recipient_cert(cms, rcert, flags | CMS_KEY_PARAM);
    if (!ri)
    {
        fprintf(stderr, "Couldn't read recipient info from cert\n");
        err_code++;
    }

    /* Read in public key from certificate */
    pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (!pctx)
    {
        fprintf(stderr, "Couldn't read pubkey from cert\n");
        err_code++;
    }

    /* Pass arguments for russian gost89 and other ciphers. There are different paramsets (A,B,C) */
    EVP_PKEY_CTX_ctrl_str(pctx, "paramset", "A");

    /* Finalize cms manipulations */
    CMS_final(cms, in_file, NULL, flags);

    /* Write out ?PEM or DER? message */
    /*if (!i2d_CMS_bio_stream(out, cms, in_file, flags))
    {
        fprintf(stderr, "Can't CMS to output file\n");
        goto err;
    }*/
    /* Write out ?PEM or DER? message */
    std::cout << "DEBUG: CMS = " << cms << std::endl;
    if (!PEM_write_bio_CMS(out, cms))
    {
        fprintf(stderr, "Can't write CMS_pem to output file\n");
        err_code++;
    }
    std::cout << "DEBUG: BIO_out = " << out << std::endl;
    if (rcert)
        X509_free(rcert);
    if (in_file)
        BIO_free(in_file);
    if (out)
        BIO_free(out);
    if (bio)
        BIO_free(bio);
    if (cms)
        CMS_ContentInfo_free(cms);
    /*if (pctx)
        EVP_PKEY_CTX_free(pctx);*/
    if (err_code > 0)
    {
        fprintf(stderr, "Error Encrypting Data\n");
        fprintf(stderr, "There was ");
        fprintf(stderr, (const char*)err_code);
        fprintf(stderr, " errors\n");
        ERR_print_errors_fp(stderr);
        return ret;
    }
    ret = EXIT_SUCCESS;
    return ret;
}

/*
decrypts any content in cms with the support of GOST (russian standard cryptography)
prkey - path of private key file. Note that private key should be the one, that was used in creating certificate (pubkey) on which cms was encrypted
cmsfile - path of cms file that we wish to decrypt
*/
int cms_decrypt(void* prkey, void* cmsfile) {
    /* converting inputs from void* to normal types */
    const char* pkeypath = (const char*)prkey;
    const char* cmspath = (const char*)cmsfile;
    std::string decoded_file = "";
    decoded_file = cmspath;
    decoded_file.append(".dec");
    int err_code = 0, ret = EXIT_FAILURE, flags = CMS_BINARY;
    std::cout << "DEBUG: cmspath = " << cmspath << std::endl;
    std::cout << "DEBUG: pkeypath = " << pkeypath << std::endl;
    /* start initialising variables for openssl */
    BIO* in_file = NULL, *out = NULL, *bio = NULL;
    EVP_PKEY* privkey = NULL;
    CMS_ContentInfo* cms = NULL;

    /* Read in file and create BIO sructure from it */
    bio = BIO_new_file(pkeypath, "r");
    if (!bio)
    {
        fprintf(stderr, "Couldn't read PRIVATE key\n");
        err_code++;
    }
    std::cout << "DEBUG: bio = " << bio << std::endl;
    /* Read in private key and create BIO sructure from it */
    privkey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    if (!privkey)
    {
        fprintf(stderr, "Bad private key\n");
        err_code++;
    }
    std::cout << "DEBUG: privkey = " << privkey << std::endl;
    /* Open cms_encrypted file and create BIO structure from it */
    in_file = BIO_new_file(cmspath, "r");
    if (!in_file)
    {
        fprintf(stderr, "Can't open input file\n");
        err_code++;
    }
    std::cout << "DEBUG: in_file = " << in_file << std::endl;

    /* Parse PEM content as cms */
    cms = PEM_read_bio_CMS(in_file, NULL, 0, NULL);
    if (!cms)
    {
        fprintf(stderr, "Can't read PEM from file\n");
        err_code++;
    }

    /* Create file containing cms content */
    out = BIO_new_file(decoded_file.data(), "w");
    if (!out)
    {
        fprintf(stderr, "Can't create output file\n");
        err_code++;
    }
    std::cout << "DEBUG: out = " << out << std::endl;
    /* Decrypt message */
    if (!CMS_decrypt(cms, privkey, NULL, NULL, out, flags))
    {
        fprintf(stderr, "Can't cms_decrypt\n");
        err_code++;
    }
    std::cout << "DEBUG: cms = " << cms << std::endl;
    if (privkey)
        EVP_PKEY_free(privkey);
    if (in_file)
        BIO_free(in_file);
    if (out)
        BIO_free(out);
    if (bio)
        BIO_free(bio);
    /*if (cms)
            CMS_ContentInfo_free(cms);*/
    if (err_code > 0)
    {
        fprintf(stderr, "Error Decrypting Data\n");
        fprintf(stderr, "There was ");
        fprintf(stderr, (const char*)err_code);
        fprintf(stderr, " errors\n");
        ERR_print_errors_fp(stderr);
        return ret;
    }
    ret = EXIT_SUCCESS;
    return ret;
}

int sizeofFile(const std::string& address) {
    std::fstream motd(address.c_str(), std::ios::binary | std::ios::in | std::ios::ate);
    if (motd) {
        std::fstream::pos_type size = motd.tellg();
        return (int)size;
    }
    else {
        perror(address.c_str());
        return -1;
    }
}
