/* 
 * File:   sign_test.cpp
 * Author: alex
 *
 * Created on July 14, 2016, 6:50 PM
 */

#include <cstdlib>
#include <cstdio>
#include <climits>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "staticlib/config/assert.hpp"

#include "staticlib/crypto/crypto_utils.hpp"

namespace cr = staticlib::crypto;

// https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying

class EVP_PKEY_Deleter {
public:
    void operator()(EVP_PKEY* key) {
        EVP_PKEY_free(key);
    }
};

class EVP_MD_CTX_Deleter {
public:
    void operator()(EVP_MD_CTX* ctx) {
        EVP_MD_CTX_destroy(ctx);
    }
};

class BIO_Deleter {
public:
    void operator()(BIO* bio) {
        BIO_free_all(bio);
    }
};

class X509_Deleter {
public:
    void operator()(X509* cert) {
        X509_free(cert);
    }
};


//ERR_get_error()

using byte = unsigned char;

std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> load_private_key() {
    auto bio = std::unique_ptr<BIO, BIO_Deleter>(BIO_new(BIO_s_file()), BIO_Deleter());
    auto ret = BIO_read_filename(bio.get(), "../test/certificate/test.key");
    slassert(1 == ret);
    std::string pwd = "test";
    void* pwdvoid = static_cast<void*> (std::addressof(pwd.front()));
    auto key = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, pwdvoid),
                EVP_PKEY_Deleter());
    slassert(nullptr != key.get());
    return key;
}

std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> load_public_key() {
    auto bio = std::unique_ptr<BIO, BIO_Deleter>(BIO_new(BIO_s_file()), BIO_Deleter());
    auto ret = BIO_read_filename(bio.get(), "../test/certificate/test.cer");
    slassert(1 == ret);
    auto cert = std::unique_ptr<X509, X509_Deleter>(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_Deleter());
    slassert(nullptr != cert.get());
    auto key = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(X509_get_pubkey(cert.get()), EVP_PKEY_Deleter());
    slassert(nullptr != key.get());
    return key;
}

std::string sign_it(const std::string& msg, EVP_PKEY* pkey, const std::string& digest_name) {
    auto ctx = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>(EVP_MD_CTX_create(), EVP_MD_CTX_Deleter());
    slassert(nullptr != ctx.get());
    const EVP_MD* md = EVP_get_digestbyname(digest_name.c_str());
    slassert(nullptr != md);
    int rc = EVP_DigestInit_ex(ctx.get(), md, nullptr);
    slassert(rc == 1);
    rc = EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, pkey);
    slassert(rc == 1);
    rc = EVP_DigestSignUpdate(ctx.get(), reinterpret_cast<const unsigned char*> (msg.c_str()), msg.length());
    slassert(rc == 1);

    size_t req = 0;
    rc = EVP_DigestSignFinal(ctx.get(), nullptr, &req);
    slassert(rc == 1);
    slassert(req > 0);

    std::string sig;
    sig.resize(req);
    size_t slen = req;

    rc = EVP_DigestSignFinal(ctx.get(), reinterpret_cast<unsigned char*> (std::addressof(sig.front())),
            std::addressof(slen));
    slassert(rc == 1);
    slassert(req == slen);

    return sig;
}

bool verify_it(const std::string& msg, std::string& sig, EVP_PKEY* pkey, const std::string& digest_name) {
    auto ctx = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>(EVP_MD_CTX_create(), EVP_MD_CTX_Deleter());
    slassert(nullptr != ctx.get());
    const EVP_MD* md = EVP_get_digestbyname(digest_name.c_str());
    slassert(md != nullptr);
    int rc = EVP_DigestInit_ex(ctx.get(), md, nullptr);
    slassert(rc == 1);
    rc = EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, pkey);
    slassert(rc == 1);
    rc = EVP_DigestVerifyUpdate(ctx.get(), reinterpret_cast<const unsigned char*> (msg.c_str()), msg.length());
    slassert(rc == 1);

    /* Clear any errors for the call below */
    ERR_clear_error();
    rc = EVP_DigestVerifyFinal(ctx.get(), reinterpret_cast<unsigned char*> (std::addressof(sig.front())),
            sig.length());
    return rc == 1;
}


int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* Sign and Verify HMAC keys */
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> skey = load_private_key();
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> vkey = load_public_key();

    std::string msg = "foo bar baz";

    std::string sig = sign_it(msg, skey.get(), "SHA256");

    std::cout << cr::to_hex(sig) << std::endl;

    bool valid = verify_it(msg, sig, vkey.get(), "SHA256");
    std::cout << "Verification result: [" << valid << "]" << std::endl;

    EVP_cleanup();
    return 0;
}


