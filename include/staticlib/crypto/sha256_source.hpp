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
 * File:   sha256_source.hpp
 * Author: alex
 *
 * Created on February 6, 2016, 6:45 PM
 */

#ifndef STATICLIB_CRYPTO_SHA256_SOURCE_HPP
#define	STATICLIB_CRYPTO_SHA256_SOURCE_HPP

#include <array>
#include <ios>
#include <memory>
#include <string>

#include "openssl/sha.h"

#include "staticlib/io/reference_source.hpp"

#include "staticlib/crypto/crypto_utils.hpp"

namespace staticlib {
namespace crypto {

/**
 * Source wrapper that computer SHA-256 hash sum of the data read through it
 */
template<typename Source>
class sha256_source {
    /**
     * Input source
     */
    Source src;
    /**
     * Hash sum computation context
     */
    std::unique_ptr<SHA256_CTX> ctx;
    /**
     * Computed hash    
     */
    std::string hash{""};

public:

    /**
     * Constructor,
     * created source wrapper will own specified source
     * 
     * @param src input source
     */
    sha256_source(Source&& src) :
    src(std::move(src)),
    ctx(create_ctx()) { }

    /**
     * Deleted copy constructor
     * 
     * @param other instance
     */
    sha256_source(const sha256_source&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    sha256_source& operator=(const sha256_source&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    sha256_source(sha256_source&& other) :
    src(std::move(other.src)),
    ctx(std::move(other.ctx)),
    hash(std::move(other.hash)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    sha256_source& operator=(sha256_source&& other) {
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
    std::streamsize read(char* buffer, std::streamsize length) {
        std::streamsize res = src.read(buffer, length);
        if (res > 0) {
            SHA256_Update(ctx.get(), buffer, res);
        }
        return res;
    }

    /**
     * Returns number of bytes read through this instance
     * 
     * @return number of bytes read through this instance
     */
    std::string get_hash() {
        if (hash.empty()) {
            std::array<unsigned char, SHA256_DIGEST_LENGTH> buf;
            SHA256_Final(buf.data(), ctx.get());
            hash = to_hex(buf.data(), buf.size());
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

private:

    static std::unique_ptr<SHA256_CTX> create_ctx() {
        std::unique_ptr<SHA256_CTX> ctx{new SHA256_CTX};
        SHA256_Init(ctx.get());
        return ctx;
    }    
    
};

/**
 * Factory function for creating counting sources,
 * created source wrapper will own specified source
 * 
 * @param source input source
 * @return counting source
 */
template <typename Source,
class = typename std::enable_if<!std::is_lvalue_reference<Source>::value>::type>
sha256_source<Source> make_sha256_source(Source&& source) {
    return sha256_source<Source>(std::move(source));
}

/**
 * Factory function for creating counting sources,
 * created source wrapper will NOT own specified source
 * 
 * @param source input source
 * @return counting source
 */
template <typename Source>
sha256_source<staticlib::io::reference_source<Source>> make_sha256_source(Source& source) {
    return sha256_source<staticlib::io::reference_source<Source>>(
            staticlib::io::make_reference_source(source));
}

} // namespace
}

#endif	/* STATICLIB_CRYPTO_SHA256_SOURCE_HPP */

