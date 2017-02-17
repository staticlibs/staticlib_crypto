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
#define	STATICLIB_CRYPTO_DIGEST_VERIFY_SOURCE_HPP

#include <ios>
#include <memory>
#include <string>

#include "openssl/bio.h"
#include <openssl/err.h>
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "staticlib/config/span.hpp"
#include "staticlib/io/reference_source.hpp"

#include "staticlib/crypto/crypto_utils.hpp"

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
    std::unique_ptr<EVP_MD_CTX, detail::EVP_MD_CTX_Deleter> ctx;
    /**
     * OpenSSL error code
     */
    int error;
    /**
     * Signature valid flag
     */
    bool signature_valid = false;

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
    signature(from_hex(signature_hex)) {
        ctx = std::unique_ptr<EVP_MD_CTX, detail::EVP_MD_CTX_Deleter>(EVP_MD_CTX_create(), detail::EVP_MD_CTX_Deleter());
        if (nullptr == ctx.get()) {
            error = -1;
            return;
        }
        auto md = EVP_get_digestbyname(digest_name.c_str());
        if (nullptr == md) {
            error = -1;
            return;
        }
        error = EVP_DigestInit_ex(ctx.get(), md, nullptr);
        if (1 != error) return;
        // load cert
        auto bio = std::unique_ptr<BIO, detail::BIO_Deleter>(BIO_new(BIO_s_file()), detail::BIO_Deleter());
        error = BIO_read_filename(bio.get(), cert_path.c_str());
        if (1 != error) return;

        auto cert = std::unique_ptr<X509, detail::X509_Deleter>(PEM_read_bio_X509(bio.get(), 
                nullptr, nullptr, nullptr), detail::X509_Deleter());
        if (nullptr == cert.get()) {
            error = -1;
            return;
        }
        auto key = std::unique_ptr<EVP_PKEY, detail::EVP_PKEY_Deleter>(X509_get_pubkey(cert.get()), 
                detail::EVP_PKEY_Deleter());
        if (nullptr == key.get()) {
            error = -1;
            return;
        }
        error = EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, key.get());
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
    error(other.error),
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
        error = other.error;
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
    std::streamsize read(staticlib::config::span<char> span) {
        if (1 == error) {
            std::streamsize res = src.read(span);
            if (res > 0) {
                error = EVP_DigestVerifyUpdate(ctx.get(),
                        reinterpret_cast<const unsigned char*> (span.data()), 
                        static_cast<size_t> (res));
            }
            return 1 == error ? res : std::char_traits<char>::eof();
        } else {
            return std::char_traits<char>::eof();
        }
    }

    /**
     * Returns whether signature is valid
     * 
     * @return whether signature is valid
     */
    bool is_signature_valid() {
        if (1 == error && !signature_valid) {
            ERR_clear_error();
            error = EVP_DigestVerifyFinal(ctx.get(), 
                    reinterpret_cast<unsigned char*> (std::addressof(signature.front())),
                    signature.length());
            signature_valid = (error == 1);
        }
        return signature_valid;
    }

    /**
     * Underlying source accessor
     * 
     * @return underlying source reference
     */
    Source& get_source() {
        return src;
    }

    /**
     * Whether error happened during processing
     * 
     * @return whether error happened during processing
     */
    bool is_bogus() {
        return 1 != error;
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


#endif	/* STATICLIB_CRYPTO_DIGEST_VERIFY_SOURCE_HPP */

