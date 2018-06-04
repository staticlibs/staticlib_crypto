/*
 * Copyright 2018, alex at staticlibs.net
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
 * File:   decrypt_source.hpp
 * Author: alex
 *
 * Created on June 3, 2018, 4:59 PM
 */

#ifndef STATICLIB_CRYPTO_DECRYPT_SOURCE_HPP
#define STATICLIB_CRYPTO_DECRYPT_SOURCE_HPP

#include <array>
#include <ios>
#include <functional>
#include <memory>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"
#include "staticlib/support.hpp"

#include "staticlib/crypto/crypto_exception.hpp"

namespace staticlib {
namespace crypto {

/**
 * Source wrapper that decrypts data read through it
 */
template<typename Source, size_t buffer_size=4096>
class decrypt_source {
    /**
     * Input source
     */
    Source src;
    /**
     * Read buffer
     */
    std::array<char, buffer_size> buf;
    /**
     * OpenSSL machinery
     */
    std::unique_ptr<BIO, std::function<void(BIO*)>> decrypter;
    std::unique_ptr<BIO, std::function<void(BIO*)>> bsrc;
    std::unique_ptr<BIO, std::function<void(BIO*)>> bsink;

public:
    /**
     * Constructor,
     * created source wrapper will own specified source
     * 
     * @param src input source
     */
    decrypt_source(Source&& src, const EVP_CIPHER* cipher, const std::string& key, const std::string& iv) :
    src(std::move(src)),
    decrypter(BIO_new(BIO_f_cipher()), [](BIO* bio) { BIO_free(bio); }),
    bsrc(BIO_new(BIO_s_bio()), [](BIO* bio) { BIO_free(bio); }),
    bsink(BIO_new(BIO_s_bio()), [](BIO* bio) { BIO_free(bio); }) {
        if (nullptr == decrypter.get()) throw crypto_exception(TRACEMSG(
                "'BIO_new(BIO_f_cipher)' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        if (nullptr == bsrc.get() || nullptr == bsink.get()) throw crypto_exception(TRACEMSG(
                "'BIO_new(BIO_s_bio)' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        BIO_set_cipher(decrypter.get(), cipher, reinterpret_cast<const unsigned char*>(key.c_str()),
                reinterpret_cast<const unsigned char*>(iv.c_str()), 0 /* decrypt */);
        EVP_CIPHER_CTX* pctx = nullptr;
        auto err_ctx = BIO_get_cipher_ctx(decrypter.get(), std::addressof(pctx));
        if (1 != err_ctx || nullptr == pctx) throw crypto_exception(TRACEMSG(
                "'BIO_set_cipher' error, code: [" + sl::support::to_string(ERR_get_error()) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        // source
        int err_src_buf_size = BIO_set_write_buf_size(bsrc.get(), buffer_size);
        if(1 != err_src_buf_size) throw crypto_exception(TRACEMSG(
                "'BIO_set_write_buf_size' error, size: [" + sl::support::to_string(buffer_size) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        // sink
        int err_sink_buf_size = BIO_set_write_buf_size(bsink.get(), buffer_size);
        if(1 != err_sink_buf_size) throw crypto_exception(TRACEMSG(
                "'BIO_set_write_buf_size' error, size: [" + sl::support::to_string(buffer_size) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        // chain
        BIO* pushed = BIO_push(decrypter.get(), bsink.get());
        if(pushed != decrypter.get()) throw crypto_exception(TRACEMSG(
                "'BIO_push' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        // pair, BIO_s_mem may be used instead
        int err_pair = BIO_make_bio_pair(bsrc.get(), bsink.get());
        if (1 != err_pair) throw crypto_exception(TRACEMSG(
                "'BIO_make_bio_pair' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
    }

    /**
     * Deleted copy constructor
     * 
     * @param other instance
     */
    decrypt_source(const decrypt_source&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    decrypt_source& operator=(const decrypt_source&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    decrypt_source(decrypt_source&& other) STATICLIB_NOEXCEPT :
    src(std::move(other.src)),
    buf(std::move(other.buf)),
    decrypter(std::move(other.decrypter)),
    bsrc(std::move(other.bsrc)),
    bsink(std::move(other.bsink)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    decrypt_source& operator=(decrypt_source&& other) STATICLIB_NOEXCEPT {
        src = std::move(other.src);
        buf = std::move(other.buf);
        decrypter = std::move(other.decrypter);
        bsrc = std::move(other.bsrc);
        bsink = std::move(other.bsink);
        return *this;
    }

    /**
     * Decrypting read implementation
     * 
     * @param buffer output buffer
     * @param length number of bytes to process
     * @return number of bytes processed
     */
    std::streamsize read(sl::io::span<char> span) {
        // read buffered
        int read_buffered = BIO_read(decrypter.get(), span.data(), static_cast<int>(span.size_signed()));
        if (read_buffered > 0) {
            return static_cast<std::streamsize>(read_buffered);
        }
        if (read_buffered < -1) throw crypto_exception(TRACEMSG(
                "'BIO_read' buffered error, return: [" + sl::support::to_string(read_buffered) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        // decode more data
        auto allowed = BIO_get_write_guarantee(bsrc.get());
        if (allowed <= 0) throw crypto_exception(TRACEMSG(
                "'BIO_get_write_guarantee' write buffer overflow," +
                " allowed: [" + sl::support::to_string(allowed) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        auto uallowed = static_cast<size_t>(allowed);
        size_t to_decode = uallowed <= buf.size() ? uallowed : buf.size();
        size_t read_from_src = sl::io::read_all(src, {buf.data(), to_decode});
        if (0 == read_from_src) {
            // source exhausted
            auto err_flush = BIO_flush(bsrc.get());
            if (1 != err_flush) throw crypto_exception(TRACEMSG(
                    "'BIO_flush' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            unsigned char eof = static_cast<unsigned char>(-1);
            auto written = BIO_write(bsrc.get(), std::addressof(eof), 1);
            if (written <= 0) throw crypto_exception(TRACEMSG(
                    "'BIO_write' eof error, to_write: [" + sl::support::to_string(read_from_src) + "]," +
                    " written: [" + sl::support::to_string(written) + "]," +
                    " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            // read and return
            int read_flushed = BIO_read(decrypter.get(), span.data(), static_cast<int>(span.size_signed()));
            if (read_flushed < -1) throw crypto_exception(TRACEMSG(
                    "'BIO_read' error, read: [" + sl::support::to_string(read_flushed) + "]," +
                    " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            int read_status = BIO_get_cipher_status(decrypter.get());
            if (1 != read_status) throw crypto_exception(TRACEMSG(
                    "'BIO_get_cipher_status' error, read: [" + sl::support::to_string(read_flushed) + "]," +
                    " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            return read_flushed >= 0 ? static_cast<std::streamsize>(read_flushed) : std::char_traits<char>::eof();
        }
        auto written = BIO_write(bsrc.get(), buf.data(), static_cast<int>(read_from_src));
        if (written <= 0) throw crypto_exception(TRACEMSG(
                "'BIO_write' error, to_write: [" + sl::support::to_string(read_from_src) + "]," +
                " written: [" + sl::support::to_string(written) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        if (read_from_src < to_decode) {
            // source exhausted
            auto err_flush = BIO_flush(bsrc.get());
            if (1 != err_flush) throw crypto_exception(TRACEMSG(
                    "'BIO_flush' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            unsigned char eof = static_cast<unsigned char>(-1);
            auto written = BIO_write(bsrc.get(), std::addressof(eof), 1);
            if (written <= 0) throw crypto_exception(TRACEMSG(
                    "'BIO_write' eof error, to_write: [" + sl::support::to_string(read_from_src) + "]," +
                    " written: [" + sl::support::to_string(written) + "]," +
                    " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        }
        // read and return
        int read_decoded = BIO_read(decrypter.get(), span.data(), static_cast<int>(span.size_signed()));
        if (read_decoded < -1) throw crypto_exception(TRACEMSG(
                "'BIO_read' error, return: [" + sl::support::to_string(read_decoded) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        int read_status = BIO_get_cipher_status(decrypter.get());
        if (1 != read_status) throw crypto_exception(TRACEMSG(
                "'BIO_get_cipher_status' error, read: [" + sl::support::to_string(read_decoded) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        return read_decoded >= 0 ? static_cast<std::streamsize>(read_decoded) : 0;
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
 * Factory function for creating decrypt sources,
 * created source wrapper will own specified source
 * 
 * @param source input source
 * @return decrypt source
 */
template <typename Source,
class = typename std::enable_if<!std::is_lvalue_reference<Source>::value>::type>
decrypt_source<Source> make_decrypt_source(Source&& source, const EVP_CIPHER* cipher,
        const std::string& key, const std::string& iv) {
    return decrypt_source<Source>(std::move(source), cipher, key, iv);
}

/**
 * Factory function for creating decrypt sources,
 * created source wrapper will NOT own specified source
 * 
 * @param source input source
 * @return decrypt source
 */
template <typename Source>
decrypt_source<staticlib::io::reference_source<Source>> make_decrypt_source(Source& source,
        const EVP_CIPHER* cipher, const std::string& key, const std::string& iv) {
    return decrypt_source<staticlib::io::reference_source<Source>>(
            staticlib::io::make_reference_source(source), cipher, key, iv);
}

} // namespace
}


#endif /* STATICLIB_CRYPTO_DECRYPT_SOURCE_HPP */

