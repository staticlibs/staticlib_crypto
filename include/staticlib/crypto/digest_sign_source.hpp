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
 * File:   digest_sign_source.hpp
 * Author: alex
 *
 * Created on July 15, 2016, 5:37 PM
 */

#ifndef STATICLIB_CRYPTO_DIGEST_SIGN_SOURCE_HPP
#define STATICLIB_CRYPTO_DIGEST_SIGN_SOURCE_HPP

#include <functional>
#include <ios>
#include <memory>
#include <string>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"
#include "staticlib/support.hpp"

#include "staticlib/crypto/crypto_exception.hpp"

namespace staticlib {
namespace crypto {

/**
 * Source wrapper that computes digest signature of the data read through it
 */
template<typename Source>
class digest_sign_source {
    /**
     * Input source
     */
    Source src;
    /**
     * Signature computation context
     */
    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> ctx;
    /**
     * Computed hash
     */
    std::string signature;

public:
    /**
     * Constructor,
     * created source wrapper will own specified source
     * 
     * @param src input source
     */
    digest_sign_source(Source&& src, const std::string& key_path, const std::string& key_pwd, 
            const std::string& digest_name = "SHA256") :
    src(std::move(src)) {
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
        // load key
        auto bio = BIO_new(BIO_s_file());
        if (nullptr == bio) throw crypto_exception(TRACEMSG(
                "'BIO_new(BIO_s_file)' error"));
        auto deferred_bio = sl::support::defer([bio]() STATICLIB_NOEXCEPT {
            BIO_free_all(bio);
        });
        auto err_read_filename = BIO_read_filename(bio, key_path.c_str());
        if (1 != err_read_filename) throw crypto_exception(TRACEMSG(
                "'BIO_read_filename' error, path: [" + key_path + "]," +
                " code: [" + sl::support::to_string(err_read_filename) + "]"));
        auto pwd = std::string(key_pwd.data(), key_pwd.length());
        void* pwdvoid = static_cast<void*> (std::addressof(pwd.front()));
        auto key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, pwdvoid);
        if (nullptr == key) throw crypto_exception(TRACEMSG(
                "'PEM_read_bio_PrivateKey' error, path: [" + key_path + "]"));
        auto deferred_key = sl::support::defer([key]() STATICLIB_NOEXCEPT {
            EVP_PKEY_free(key);
        });
        auto err_init = EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, key);
        if(1 != err_init) throw crypto_exception(TRACEMSG(
                "'EVP_DigestSignInit' error, code: [" + sl::support::to_string(err_init) + "]"));
    }

    /**
     * Deleted copy constructor
     * 
     * @param other instance
     */
    digest_sign_source(const digest_sign_source&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    digest_sign_source& operator=(const digest_sign_source&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    digest_sign_source(digest_sign_source&& other) :
    src(std::move(other.src)),
    ctx(std::move(other.ctx)),
    signature(std::move(other.signature)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    digest_sign_source& operator=(digest_sign_source&& other) {
        src = std::move(other.src);
        ctx = std::move(other.ctx);
        signature = std::move(other.signature);
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
            auto err = EVP_DigestSignUpdate(ctx.get(), 
                    reinterpret_cast<const unsigned char*> (span.data()), 
                    static_cast<size_t> (res));
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'EVP_DigestSignUpdate' error, code: [" + sl::support::to_string(err) + "]"));
        }
        return res;
    }

    /**
     * Returns computed signature
     * 
     * @return computed signature
     */
    const std::string& get_signature() {
        if (signature.empty()) {
            size_t req = 0;
            auto err_req = EVP_DigestSignFinal(ctx.get(), nullptr, std::addressof(req));
            if (1 != err_req || req <= 0) throw crypto_exception(TRACEMSG(
                    "'EVP_DigestSignFinal' req error, code: [" + sl::support::to_string(err_req) + "]," +
                    " req: [" + sl::support::to_string(req) + "]"));
            std::string sig;
            sig.resize(req);
            size_t slen = req;
            auto err = EVP_DigestSignFinal(ctx.get(), reinterpret_cast<unsigned char*>(std::addressof(sig.front())),
                    std::addressof(slen));
            if (1 != err || req != slen) throw crypto_exception(TRACEMSG(
                    "'EVP_DigestSignFinal' error, code: [" + sl::support::to_string(err) + "]," +
                    " req: [" + sl::support::to_string(req) + "]," +
                    " slen: [" + sl::support::to_string(slen) + "]"));
            signature = sl::io::string_to_hex(sig);
        }
        return signature;
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
 * Factory function for creating digest_sign sources,
 * created source wrapper will own specified source
 * 
 * @param source input source
 * @return digest_sign source
 */
template <typename Source,
class = typename std::enable_if<!std::is_lvalue_reference<Source>::value>::type>
digest_sign_source<Source> make_digest_sign_source(Source&& source, const std::string& key_path, 
        const std::string& key_pwd, const std::string& digest_name = "SHA256") {
    return digest_sign_source<Source>(std::move(source), key_path, key_pwd, digest_name);
}

/**
 * Factory function for creating digest_sign sources,
 * created source wrapper will NOT own specified source
 * 
 * @param source input source
 * @return digest_sign source
 */
template <typename Source>
digest_sign_source<staticlib::io::reference_source<Source>> make_digest_sign_source(Source& source,
        const std::string& key_path, const std::string& key_pwd, 
        const std::string& digest_name = "SHA256") {
    return digest_sign_source<staticlib::io::reference_source<Source>> (
            staticlib::io::make_reference_source(source), key_path, key_pwd, digest_name);
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_DIGEST_SIGN_SOURCE_HPP */

