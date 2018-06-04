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
 * File:   sha256_sink.hpp
 * Author: alex
 *
 * Created on February 6, 2016, 6:45 PM
 */

#ifndef STATICLIB_CRYPTO_SHA256_SINK_HPP
#define STATICLIB_CRYPTO_SHA256_SINK_HPP

#include <array>
#include <ios>
#include <memory>
#include <string>

#include "openssl/err.h"
#include "openssl/sha.h"

#include "staticlib/config.hpp"
#include "staticlib/io.hpp"
#include "staticlib/support.hpp"

#include "staticlib/crypto/crypto_exception.hpp"

namespace staticlib {
namespace crypto {

/**
 * Sink wrapper that computer SHA-256 hash sum of the data written through it
 */
template<typename Sink>
class sha256_sink {
    /**
     * Destination sink
     */
    Sink sink;
    /**
     * Hash sum computation context
     */
    std::unique_ptr<SHA256_CTX> ctx;
    /**
     * Computed hash
     */
    std::string hash;

public:

    /**
     * Constructor,
     * created sink wrapper will own specified sink
     * 
     * @param sink destination sink
     */
    sha256_sink(Sink&& sink) :
    sink(std::move(sink)) {
        ctx = std::unique_ptr<SHA256_CTX>(new SHA256_CTX());
        auto err = SHA256_Init(ctx.get());
        if (1 != err) throw crypto_exception(TRACEMSG(
                "'SHA256_Init' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
    }

    /**
     * Deleted copy constructor
     * 
     * @param other instance
     */
    sha256_sink(const sha256_sink&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    sha256_sink& operator=(const sha256_sink&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    sha256_sink(sha256_sink&& other) :
    sink(std::move(other.sink)),
    ctx(std::move(other.ctx)),
    hash(std::move(other.hash)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    sha256_sink& operator=(sha256_sink&& other) {
        sink = std::move(other.sink);
        ctx = std::move(other.ctx);
        hash = std::move(other.hash);
        return *this;
    }

    /**
     * Counting write implementation
     * 
     * @param buffer source buffer
     * @param length number of bytes to process
     * @return number of bytes processed
     */
    std::streamsize write(sl::io::span<const char> span) {
        std::streamsize res = sink.write(span);
        if (res > 0) {
            auto err = SHA256_Update(ctx.get(), span.data(), static_cast<size_t>(res));
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'SHA256_Update' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
        }
        return res;
    }

    /**
     * Flushes destination sink
     * 
     * @return number of bytes flushed
     */
    std::streamsize flush() {
        return sink.flush();
    }

    /**
     * Returns computed hash sum
     * 
     * @return computed hash sum
     */
    const std::string& get_hash() {
        if (hash.empty()) {
            std::array<unsigned char, SHA256_DIGEST_LENGTH> buf;
            auto err = SHA256_Final(buf.data(), ctx.get());
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'SHA256_Final' error, code: [" + sl::support::to_string(ERR_get_error()) + "]"));
            auto dest = sl::io::string_sink();
            {
                auto src = sl::io::array_source(reinterpret_cast<const char*>(buf.data()), buf.size());
                auto hex = sl::io::make_hex_sink(dest);
                sl::io::copy_all(src, hex);
            }
            hash = std::move(dest.get_string());
        }
        return hash;
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
 * Factory function for creating SHA-256 sinks,
 * created sink wrapper will own specified sink
 * 
 * @param sink destination sink
 * @return SHA-256 sink
 */
template <typename Sink,
class = typename std::enable_if<!std::is_lvalue_reference<Sink>::value>::type>
sha256_sink<Sink> make_sha256_sink(Sink&& sink) {
    return sha256_sink<Sink>(std::move(sink));
}

/**
 * Factory function for creating SHA-256 sinks,
 * created sink wrapper will NOT own specified sink
 * 
 * @param sink destination sink
 * @return SHA-256 sink
 */
template <typename Sink>
sha256_sink<staticlib::io::reference_sink<Sink>> make_sha256_sink(Sink& sink) {
    return sha256_sink<staticlib::io::reference_sink<Sink>>(
            staticlib::io::make_reference_sink(sink));
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_SHA256_SINK_HPP */

