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

#include "openssl/sha.h"

#include "staticlib/config.hpp"
#include "staticlib/io/span.hpp"
#include "staticlib/io/reference_sink.hpp"

#include "staticlib/crypto/crypto_utils.hpp"

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
     * OpenSSL error code
     */
    int error;
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
        ctx = std::unique_ptr<SHA256_CTX>(new SHA256_CTX);
        error = SHA256_Init(ctx.get());
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
    error(other.error),
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
        error = other.error;
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
        if (1 == error) {
            std::streamsize res = sink.write(span);
            if (res > 0) {
                SHA256_Update(ctx.get(), span.data(), static_cast<size_t>(res));
            }
            return res;
        } else {
            return span.size_signed();
        }
    }

    /**
     * Flushes destination sink
     * 
     * @return number of bytes flushed
     */
    std::streamsize flush() {       
        if (1 == error) {
            return sink.flush();
        } else {
            return 0;
        }
    }

    /**
     * Returns computed hash sum
     * 
     * @return computed hash sum
     */
    const std::string& get_hash() {
        if (1 == error && hash.empty()) {
            std::array<unsigned char, SHA256_DIGEST_LENGTH> buf;
            SHA256_Final(buf.data(), ctx.get());
            hash = to_hex(buf.data(), buf.size());
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
 * Factory function for creating counting sinks,
 * created sink wrapper will own specified sink
 * 
 * @param sink destination sink
 * @return counting sink
 */
template <typename Sink,
class = typename std::enable_if<!std::is_lvalue_reference<Sink>::value>::type>
sha256_sink<Sink> make_sha256_sink(Sink&& sink) {
    return sha256_sink<Sink>(std::move(sink));
}

/**
 * Factory function for creating counting sinks,
 * created sink wrapper will NOT own specified sink
 * 
 * @param sink destination sink
 * @return counting sink
 */
template <typename Sink>
sha256_sink<staticlib::io::reference_sink<Sink>> make_sha256_sink(Sink& sink) {
    return sha256_sink<staticlib::io::reference_sink<Sink>>(
            staticlib::io::make_reference_sink(sink));
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_SHA256_SINK_HPP */

