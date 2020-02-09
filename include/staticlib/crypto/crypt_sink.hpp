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
 * File:   crypt_sink.hpp
 * Author: alex
 *
 * Created on June 3, 2018, 4:59 PM
 */

#ifndef STATICLIB_CRYPTO_CRYPT_SINK_HPP
#define STATICLIB_CRYPTO_CRYPT_SINK_HPP

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
 * Sink wrapper that encrypts or decrypts data with a specified cipher,
 * should be used in conjunction with buffered sink.
 */
template<typename Sink, size_t buffer_size=4096>
class crypt_sink {
    /**
     * Destination sink
     */
    Sink sink;
    /**
     * Read buffer
     */
    std::array<char, buffer_size> buf;
    /**
     * OpenSSL machinery
     */
    std::unique_ptr<BIO, std::function<void(BIO*)>> encrypter;
    std::unique_ptr<BIO, std::function<void(BIO*)>> bsrc;
    std::unique_ptr<BIO, std::function<void(BIO*)>> bsink;

public:
    /**
     * Constructor,
     * created sink wrapper will own specified sink
     * 
     * @param sink destination sink
     */
    crypt_sink(Sink&& sink, const EVP_CIPHER* cipher, const std::string& key, const std::string& iv,
            bool encrypt) :
    sink(std::move(sink)),
    encrypter(BIO_new(BIO_f_cipher()), [](BIO* bio) { BIO_free(bio); }),
    bsrc(BIO_new(BIO_s_bio()), [](BIO* bio) { BIO_free(bio); }),
    bsink(BIO_new(BIO_s_bio()), [](BIO* bio) { BIO_free(bio); }) {
        if (nullptr == encrypter.get()) throw crypto_exception(TRACEMSG(
                "'BIO_new(BIO_f_cipher)' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        if (nullptr == bsrc.get() || nullptr == bsink.get()) throw crypto_exception(TRACEMSG(
                "'BIO_new(BIO_s_bio)' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        BIO_set_cipher(encrypter.get(), cipher, reinterpret_cast<const unsigned char*>(key.c_str()),
                reinterpret_cast<const unsigned char*>(iv.c_str()), encrypt ? 1 : 0);
        EVP_CIPHER_CTX* pctx = nullptr;
        auto err_ctx = BIO_get_cipher_ctx(encrypter.get(), std::addressof(pctx));
        if (1 != err_ctx || nullptr == pctx) throw crypto_exception(TRACEMSG(
                "'BIO_set_cipher' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
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
        BIO* pushed = BIO_push(encrypter.get(), bsrc.get());
        if(pushed != encrypter.get()) throw crypto_exception(TRACEMSG(
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
    crypt_sink(const crypt_sink&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    crypt_sink& operator=(const crypt_sink&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    crypt_sink(crypt_sink&& other) STATICLIB_NOEXCEPT :
    sink(std::move(other.sink)),
    buf(std::move(other.buf)),
    encrypter(std::move(other.encrypter)),
    bsrc(std::move(other.bsrc)),
    bsink(std::move(other.bsink)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    crypt_sink& operator=(crypt_sink&& other) STATICLIB_NOEXCEPT {
        sink = std::move(other.sink);
        buf = std::move(other.buf);
        encrypter = std::move(other.encrypter);
        bsrc = std::move(other.bsrc);
        bsink = std::move(other.bsink);
        return *this;
    }

    /**
     * Destructor, flushes the stream before destroy
     */
    ~crypt_sink() STATICLIB_NOEXCEPT {
        try {
            flush();
        } catch(...) {
            // ignore
        }
    }

    /**
     * Encrypting write implementation
     * 
     * @param span buffer span
     * @return number of bytes processed
     */
    std::streamsize write(sl::io::span<const char> span) {
        size_t written = 0;
        while (written < span.size()) {
            // write
            auto allowed = BIO_get_write_guarantee(encrypter.get());
            if (allowed <= 0) throw crypto_exception(TRACEMSG(
                    "'BIO_get_write_guarantee' write buffer overflow," +
                    " allowed: [" + sl::support::to_string(allowed) + "]," +
                    " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            auto uallowed = static_cast<size_t>(allowed);
            auto avail = span.size() - written;
            size_t to_write = avail <= uallowed ? avail : uallowed;
            auto wr = BIO_write(encrypter.get(), span.data() + written, static_cast<int>(to_write));
            if (wr <= 0) throw crypto_exception(TRACEMSG(
                    "'BIO_write' error, to_write: [" + sl::support::to_string(to_write) + "]," +
                    " written: [" + sl::support::to_string(wr) + "]," +
                    " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            written += static_cast<size_t>(wr);
            // read and write to sink
            int read = 0;
            while ((read = (BIO_read(bsink.get(), buf.data(), static_cast<int>(buf.size())))) > 0) {
                sl::io::write_all(sink, {buf.data(), static_cast<size_t>(read)});
            }
            if (read < -1) throw crypto_exception(TRACEMSG(
                    "'BIO_read' error, return: [" + sl::support::to_string(read) + "]," +
                    " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        }
        return span.size_signed();
    }

    /**
     * Flushes encrypt encoder and a destination sink
     * 
     * @return number of bytes flushed
     */
    std::streamsize flush() {
        auto err = BIO_flush(encrypter.get());
        if (1 != err) throw crypto_exception(TRACEMSG(
                "'BIO_flush' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        // read and write to sink
        std::streamsize written = 0;
        int read = 0;
        while ((read = (BIO_read(bsink.get(), buf.data(), static_cast<int>(buf.size())))) > 0) {
            written += read;
            sl::io::write_all(sink, {buf.data(), static_cast<size_t>(read)});
        }
        if (read < -1) throw crypto_exception(TRACEMSG(
                "'BIO_read' error, return: [" + sl::support::to_string(read) + "]," +
                " code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        sink.flush();
        return written;
    }

    /**
     * Underlying sink accessor
     * 
     * @return underlying sink reference
     */
    Sink& get_sink() {
        return sink;
    }

};

/**
 * Factory function for creating encrypt sinks,
 * created sink wrapper will own specified sink
 * 
 * @param sink destination sink
 * @return encrypt sink
 */
template <typename Sink,
        class = typename std::enable_if<!std::is_lvalue_reference<Sink>::value>::type>
crypt_sink<Sink> make_encrypt_sink(Sink&& sink, const EVP_CIPHER* cipher,
        const std::string& key, const std::string& iv) {
    return crypt_sink<Sink>(std::move(sink), cipher, key, iv, true);
}

/**
 * Factory function for creating encrypt sinks,
 * created sink wrapper will NOT own specified sink
 * 
 * @param sink destination sink
 * @return encrypt sink
 */
template <typename Sink>
crypt_sink<sl::io::reference_sink<Sink>> make_encrypt_sink(Sink& sink, const EVP_CIPHER* cipher,
        const std::string& key, const std::string& iv) {
    return crypt_sink<sl::io::reference_sink<Sink>>(
            sl::io::make_reference_sink(sink), cipher, key, iv, true);
}

/**
 * Factory function for creating decrypt sinks,
 * created sink wrapper will own specified sink
 * 
 * @param sink destination sink
 * @return encrypt sink
 */
template <typename Sink,
        class = typename std::enable_if<!std::is_lvalue_reference<Sink>::value>::type>
crypt_sink<Sink> make_decrypt_sink(Sink&& sink, const EVP_CIPHER* cipher,
        const std::string& key, const std::string& iv) {
    return crypt_sink<Sink>(std::move(sink), cipher, key, iv, false);
}

/**
 * Factory function for creating decrypt sinks,
 * created sink wrapper will NOT own specified sink
 * 
 * @param sink destination sink
 * @return encrypt sink
 */
template <typename Sink>
crypt_sink<sl::io::reference_sink<Sink>> make_decrypt_sink(Sink& sink, const EVP_CIPHER* cipher,
        const std::string& key, const std::string& iv) {
    return crypt_sink<sl::io::reference_sink<Sink>>(
            sl::io::make_reference_sink(sink), cipher, key, iv, false);
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_CRYPT_SINK_HPP */

