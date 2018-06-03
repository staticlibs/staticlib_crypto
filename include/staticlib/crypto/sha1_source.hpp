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
 * File:   sha1_source.hpp
 * Author: alex
 *
 * Created on June 3, 2018, 4:46 PM
 */

#ifndef STATICLIB_CRYPTO_SHA1_SOURCE_HPP
#define STATICLIB_CRYPTO_SHA1_SOURCE_HPP

#include <array>
#include <ios>
#include <memory>
#include <string>

#include "openssl/sha.h"

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"
#include "staticlib/support.hpp"

#include "staticlib/crypto/crypto_exception.hpp"

namespace staticlib {
namespace crypto {

/**
 * Source wrapper that computes SHA-1 hash sum of the data read through it
 */
template<typename Source>
class sha1_source {
    /**
     * Input source
     */
    Source src;
    /**
     * Hash sum computation context
     */
    std::unique_ptr<SHA_CTX> ctx;
    /**
     * Computed hash
     */
    std::string hash;

public:
    /**
     * Constructor,
     * created source wrapper will own specified source
     * 
     * @param src input source
     */
    sha1_source(Source&& src) :
    src(std::move(src)) {
        ctx = std::unique_ptr<SHA_CTX>(new SHA_CTX());
        auto err = SHA1_Init(ctx.get());
        if (1 != err) throw crypto_exception(TRACEMSG(
                "'SHA1_Init' error, code: [" + sl::support::to_string(err) + "]"));
    }

    /**
     * Deleted copy constructor
     * 
     * @param other instance
     */
    sha1_source(const sha1_source&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    sha1_source& operator=(const sha1_source&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    sha1_source(sha1_source&& other) :
    src(std::move(other.src)),
    ctx(std::move(other.ctx)),
    hash(std::move(other.hash)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    sha1_source& operator=(sha1_source&& other) {
        src = std::move(other.src);
        ctx = std::move(other.ctx);
        hash = std::move(other.hash);
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
            auto err = SHA1_Update(ctx.get(), span.data(), static_cast<size_t>(res));
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'SHA1_Update' error, code: [" + sl::support::to_string(err) + "]"));
        }
        return res;
    }

    /**
     * Returns computed hash sum
     * 
     * @return computed hash sum
     */
    const std::string& get_hash() {
        if (hash.empty()) {
            std::array<unsigned char, SHA_DIGEST_LENGTH> buf;
            auto err = SHA1_Final(buf.data(), ctx.get());
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'SHA1_Final' error, code: [" + sl::support::to_string(err) + "]"));
            auto src = sl::io::array_source(reinterpret_cast<const char*>(buf.data()), buf.size());
            auto dest = sl::io::string_sink();
            auto sink = sl::io::make_hex_sink(dest);
            sl::io::copy_all(src, sink);
            hash = std::move(dest.get_string());
        }
        return hash;
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
 * Factory function for creating SHA-1 sources,
 * created source wrapper will own specified source
 * 
 * @param source input source
 * @return SHA-1 source
 */
template <typename Source,
class = typename std::enable_if<!std::is_lvalue_reference<Source>::value>::type>
sha1_source<Source> make_sha1_source(Source&& source) {
    return sha1_source<Source>(std::move(source));
}

/**
 * Factory function for creating SHA-1 sources,
 * created source wrapper will NOT own specified source
 * 
 * @param source input source
 * @return SHA-1 source
 */
template <typename Source>
sha1_source<staticlib::io::reference_source<Source>> make_sha1_source(Source& source) {
    return sha1_source<staticlib::io::reference_source<Source>>(
            staticlib::io::make_reference_source(source));
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_SHA1_SOURCE_HPP */

