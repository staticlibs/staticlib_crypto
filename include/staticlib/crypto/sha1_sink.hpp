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
 * File:   sha1_sink.hpp
 * Author: alex
 *
 * Created on June 3, 2018, 4:43 PM
 */

#ifndef STATICLIB_CRYPTO_SHA1_SINK_HPP
#define STATICLIB_CRYPTO_SHA1_SINK_HPP

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
 * Sink wrapper that computer SHA-1 hash sum of the data written through it
 */
template<typename Sink>
class sha1_sink {
    /**
     * Destination sink
     */
    Sink sink;
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
     * created sink wrapper will own specified sink
     * 
     * @param sink destination sink
     */
    sha1_sink(Sink&& sink) :
    sink(std::move(sink)) {
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
    sha1_sink(const sha1_sink&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    sha1_sink& operator=(const sha1_sink&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    sha1_sink(sha1_sink&& other) :
    sink(std::move(other.sink)),
    ctx(std::move(other.ctx)),
    hash(std::move(other.hash)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    sha1_sink& operator=(sha1_sink&& other) {
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
            auto err = SHA1_Update(ctx.get(), span.data(), static_cast<size_t>(res));
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'SHA1_Update' error, code: [" + sl::support::to_string(err) + "]"));
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
            std::array<unsigned char, SHA_DIGEST_LENGTH> buf;
            auto err = SHA1_Final(buf.data(), ctx.get());
            if (1 != err) throw crypto_exception(TRACEMSG(
                    "'SHA1_Final' error, code: [" + sl::support::to_string(err) + "]"));
            auto dest = sl::io::string_sink();
            {
                auto src = sl::io::array_source(reinterpret_cast<const char*>(buf.data()), buf.size());
                auto sink = sl::io::make_hex_sink(dest);
                sl::io::copy_all(src, sink);
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
 * Factory function for creating SHA-1 sinks,
 * created sink wrapper will own specified sink
 * 
 * @param sink destination sink
 * @return SHA-1 sink
 */
template <typename Sink,
class = typename std::enable_if<!std::is_lvalue_reference<Sink>::value>::type>
sha1_sink<Sink> make_sha1_sink(Sink&& sink) {
    return sha1_sink<Sink>(std::move(sink));
}

/**
 * Factory function for creating SHA-1 sinks,
 * created sink wrapper will NOT own specified sink
 * 
 * @param sink destination sink
 * @return SHA-1 sink
 */
template <typename Sink>
sha1_sink<staticlib::io::reference_sink<Sink>> make_sha1_sink(Sink& sink) {
    return sha1_sink<staticlib::io::reference_sink<Sink>>(
            staticlib::io::make_reference_sink(sink));
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_SHA1_SINK_HPP */

