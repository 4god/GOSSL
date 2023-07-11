#define _CRT_SECURE_NO_WARNINGS
#include "OSSL_wrap.h"
#include "OpenSSL.h"
#include <openssl/applink.c>


int cms_encrypt(void* cert, void* plaintext, void* cipher) {
    /* converting inputs */
    const char* in_cert = (const char*)cert;
    const char* in_file = (const char*)plaintext;
    const char* cipher_name = (const char*)cipher;
    std::string encoded_file = "";
    encoded_file = in_file;
    encoded_file.append(".enc");
    int err_code = 0;
    if (err_code != 0)
        return -1;
    /**/

    BIO* in = NULL, *tbio = NULL, *out = NULL;
    X509* rcert = NULL;
    STACK_OF(X509)* recips = NULL;
    CMS_ContentInfo* cms = NULL;
    int ret = EXIT_FAILURE;
    /*
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    int flags = CMS_BINARY;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    /* Read in recipient certificate */
    tbio = BIO_new_file(in_cert, "r");

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /* sk_X509_pop_free will free up recipient STACK and its contents
     * so set rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    in = BIO_new_file(in_file, "r");

    if (!in)
        goto err;

    out = BIO_new_file(encoded_file.c_str(), "w");
    if (!out)
        goto err;

    /* encrypt content, cipher = des_ede3_cbc */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!cms)
        goto err;

    if (!out)
        goto err;

    /* Write out PEM message */
    if (!PEM_write_bio_CMS_stream(out, cms, in, flags))
    {
        goto err;
    }
    ret = EXIT_SUCCESS;

err:

    if (ret != EXIT_SUCCESS)
    {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    if (cms)
        CMS_ContentInfo_free(cms);
    if (rcert)
        X509_free(rcert);
    if (recips)
        sk_X509_pop_free(recips, X509_free);

    if (in)
        BIO_free(in);
    if (out)
        BIO_free(out);
    if (tbio)
        BIO_free(tbio);
    return ret;
}

int cms_decrypt(void* prkey, void* in_file) {
        /* conversions */
        const char* pkeypath = (const char*)prkey;
        const char* cmspath = (const char*)in_file;
        std::string decoded_file = "";
        decoded_file = cmspath;
        decoded_file.append(".dec");
        /**/
        BIO* in = NULL, * out = NULL, * tbio = NULL;
        EVP_PKEY* rkey = NULL;
        CMS_ContentInfo* cms = NULL;
        int ret = EXIT_FAILURE;

        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        /* Read in recipient certificate and private key */
        tbio = BIO_new_file(pkeypath, "r");

        if (!tbio)
            goto err;

        rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

        if (!rkey)
            goto err;

        /* Open PEM file containing enveloped data */

        in = BIO_new_file(cmspath, "r");

        if (!in)
            goto err;

        /* Parse PEM content */
        cms = PEM_read_bio_CMS(in, NULL, 0, NULL);

        if (!cms)
            goto err;

        /* Open file containing detached content */

        if (!in)
            goto err;

        out = BIO_new_file(decoded_file.data(), "w");
        if (!out)
            goto err;

        /* Decrypt S/MIME message */
        if (!CMS_decrypt(cms, rkey, NULL, NULL, out, 0))
            goto err;

        ret = EXIT_SUCCESS;

    err:

        if (ret != EXIT_SUCCESS) {
            fprintf(stderr, "Error Decrypting Data\n");
            ERR_print_errors_fp(stderr);
        }

        CMS_ContentInfo_free(cms);
        EVP_PKEY_free(rkey);
        BIO_free(in);
        BIO_free(out);
        BIO_free(tbio);
        return ret;
    }