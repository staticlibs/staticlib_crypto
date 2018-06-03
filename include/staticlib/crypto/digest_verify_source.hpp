/*
 * Copyright 2016, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * File:   digest_verify_source.hpp
 * Author: alex
 *
 * Created on July 15, 2016, 5:36 PM
 */

#ifndef STATICLIB_CRYPTO_DIGEST_VERIFY_SOURCE_HPP
#define STATICLIB_CRYPTO_DIGEST_VERIFY_SOURCE_HPP

#include <ios>
#include <memory>
#include <string>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "staticlib/config.hpp"
#include "staticlib/support.hpp"
#include "staticlib/io.hpp"

#include "staticlib/crypto/crypto_exception.hpp"

namespace staticlib {
namespace crypto {

/**
 * Source wrapper that computes digest signature of the data read through it
 */
template<typename Source>
class digest_verify_source {
    /**
     * Input source
     */
    Source src;
    /**
     * Signature to verify
     */
    std::string signature;
    /**
     * Verify computation context
     */
    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> ctx;
    /**
     * Signature valid flag
     */
    sl::support::tribool signature_valid = sl::support::indeterminate;

public:

    /**
     * Constructor,
     * created source wrapper will own specified source
     * 
     * @param src input source
     */
    digest_verify_source(Source&& src, const std::string& cert_path, const std::string& signature_hex,
            const std::string& digest_name = "SHA256") :
    src(std::move(src)),
    signature(sl::io::string_from_hex(signature_hex)) {
        ctx = std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>>(EVP_MD_CTX_create(),
                [] (EVP_MD_CTX* ctx) {
                    EVP_MD_CTX_destroy(ctx);
                });
        if (nullptr == ctx.get()) throw crypto_exception(TRACEMSG(
                "'EVP_MD_CTX_create' error"));
        auto md = EVP_get_digestbyname(digest_name.c_str());
        if (nullptr == md) throw crypto_exception(TRACEMSG(
                "'EVP_get_digestbyname' error, name: [" + digest_name + "]"));
        auto err_digest_init = EVP_DigestInit_ex(ctx.get(), md, nullptr);
        if (1 != err_digest_init) throw crypto_exception(TRACEMSG(
                "'EVP_DigestInit_ex' error, name: [" + digest_name + "]," + 
                " code: [" + sl::support::to_string(err_digest_init) + "]"));
        // load cert
        auto bio = BIO_new(BIO_s_file());
        if (nullptr == bio) throw crypto_exception(TRACEMSG(
                "'BIO_new(BIO_s_file)' error"));
        auto deferred_bio = sl::support::defer([bio]() STATICLIB_NOEXCEPT {
            BIO_free_all(bio);
        });
        auto err_read_filename = BIO_read_filename(bio, cert_path.c_str());
        if (1 != err_read_filename) throw crypto_exception(TRACEMSG(
                "'BIO_read_filename' error, path: [" + cert_path + "]," +
                " code: [" + sl::support::to_string(err_read_filename) + "]"));

        auto cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (nullptr == cert) throw crypto_exception(TRACEMSG(
                "'PEM_read_bio_X509' error, path: [" + cert_path + "]"));
        auto deferred_cert = sl::support::defer([cert]() STATICLIB_NOEXCEPT {
            X509_free(cert);
        });
        auto key = X509_get_pubkey(cert);
        if (nullptr == key) throw crypto_exception(TRACEMSG(
                "'X509_get_pubkey' error, path: [" + cert_path + "]"));
        auto deferred_key = sl::support::defer([key]() STATICLIB_NOEXCEPT {
            EVP_PKEY_free(key);
        });
        auto err_init = EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, key);
        if(1 != err_init) throw crypto_exception(TRACEMSG(
                "'EVP_DigestVerifyInit' error, code: [" + sl::support::to_string(err_init) + "]"));
    }

    /**
     * Deleted copy constructor
     * 
     * @param other instance
     */
    digest_verify_source(const digest_verify_source&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    digest_verify_source& operator=(const digest_verify_source&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    digest_verify_source(digest_verify_source&& other) :
    src(std::move(other.src)),
    signature(std::move(other.signature)),
    ctx(std::move(other.ctx)),
    signature_valid(other.signature_valid) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    digest_verify_source& operator=(digest_verify_source&& other) {
        src = std::move(other.src);
        signature = std::move(other.signature);
        ctx = std::move(other.ctx);
        signature_valid = other.signature_valid;
        return *this;
    }

    /**
     * Counting read implementation
     * 
     * @param buffer output buffer
     * @param length number of bytes to process
     * @return number of bytes processed
     */
    std::streamsize read(sl::io::span<char> span) {
        std::streamsize res = src.read(span);
        if (res > 0) {
            auto err = EVP_DigestVerifyUpdate(ctx.get(),
                    reinterpret_cast<const unsigned char*> (span.data()), 
                    static_cast<size_t> (res));
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'EVP_DigestVerifyUpdate' error, code: [" + sl::support::to_string(err) + "]"));
        }
        return res;
    }

    /**
     * Returns whether signature is valid
     * 
     * @return whether signature is valid
     */
    bool is_signature_valid() {
        if (sl::support::indeterminate(signature_valid)) {
            ERR_clear_error();
            auto err = EVP_DigestVerifyFinal(ctx.get(), 
                    reinterpret_cast<unsigned char*> (std::addressof(signature.front())),
                    signature.length());
            signature_valid = (err == 1);
        }
        return true == signature_valid;
    }

    /**
     * Underlying source accessor
     * 
     * @return underlying source reference
     */
    Source& get_source() {
        return src;
    }

};

/**
 * Factory function for creating digest_verify sources,
 * created source wrapper will own specified source
 * 
 * @param source input source
 * @return digest_verify source
 */
template <typename Source,
class = typename std::enable_if<!std::is_lvalue_reference<Source>::value>::type>
digest_verify_source<Source> make_digest_verify_source(Source&& source, const std::string& cert_path, 
        const std::string& signature, const std::string& digest_name = "SHA256") {
    return digest_verify_source<Source>(std::move(source), cert_path, signature, digest_name);
}

/**
 * Factory function for creating digest_verify sources,
 * created source wrapper will NOT own specified source
 * 
 * @param source input source
 * @return digest_verify source
 */
template <typename Source>
digest_verify_source<staticlib::io::reference_source<Source>> make_digest_verify_source(Source& source,
        const std::string& cert_path, const std::string& signature,
        const std::string& digest_name = "SHA256") {
    return digest_verify_source<staticlib::io::reference_source<Source>> (
            staticlib::io::make_reference_source(source), cert_path, signature, digest_name);
}

} // namespace
}


#endif /* STATICLIB_CRYPTO_DIGEST_VERIFY_SOURCE_HPP */

