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
 * File:   base64_sink.hpp
 * Author: alex
 *
 * Created on June 3, 2018, 4:58 PM
 */

#ifndef STATICLIB_CRYPTO_BASE64_SINK_HPP
#define STATICLIB_CRYPTO_BASE64_SINK_HPP

#include <ios>
#include <functional>
#include <memory>

#include "openssl/bio.h"

#include "staticlib/config.hpp"

#include "staticlib/io.hpp"

namespace staticlib {
namespace crypto {

/**
 * Sink wrapper that encodes data into Hexadecimal,
 * should be used in conjunction with buffered sink.
 */
template<typename Sink, size_t buffer_size=4096>
class base64_sink {
    /**
     * Destination sink
     */
    Sink sink;
    /**
     * OpenSSL machinery
     */
    std::unique_ptr<BIO, std::function<void(BIO*)>> b64;
    std::unique_ptr<BIO, std::function<void(BIO*)>> bsrc;
    std::unique_ptr<BIO, std::function<void(BIO*)>> bsink;

public:
    /**
     * Constructor,
     * created sink wrapper will own specified sink
     * 
     * @param sink destination sink
     */
    explicit base64_sink(Sink&& sink) :
    sink(std::move(sink)),
    b64(BIO_new(BIO_f_base64()), [](BIO* bio) { BIO_free(bio) }),
    bsrc(BIO_new(BIO_s_bio()), [](BIO* bio) { BIO_free(bio) }),
    bfilter(BIO_new(BIO_s_bio()), [](BIO* bio) { BIO_free(bio) }) {
        // base64 format
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        // source buf
        int err_src_buf_size = BIO_set_write_buf_size(src, 4096);
        slassert(1 == err_src_buf_size);
    }

    /**
     * Deleted copy constructor
     * 
     * @param other instance
     */
    base64_sink(const base64_sink&) = delete;

    /**
     * Deleted copy assignment operator
     * 
     * @param other instance
     * @return this instance 
     */
    base64_sink& operator=(const base64_sink&) = delete;

    /**
     * Move constructor
     * 
     * @param other other instance
     */
    base64_sink(base64_sink&& other) STATICLIB_NOEXCEPT :
    sink(std::move(other.sink)),
    hbuf(std::move(other.hbuf)) { }

    /**
     * Move assignment operator
     * 
     * @param other other instance
     * @return this instance
     */
    base64_sink& operator=(base64_sink&& other) STATICLIB_NOEXCEPT {
        sink = std::move(other.sink);
        hbuf = std::move(other.hbuf);
        return *this;
    }

    /**
     * Hex encoding write implementation
     * 
     * @param span buffer span
     * @return number of bytes processed
     */
    std::streamsize write(span<const char> span) {
        for (size_t i = 0; i < span.size(); i++) {
            char ch = span.data()[i];
            // http://stackoverflow.com/a/18025541/314015
            unsigned char uch = static_cast<unsigned char>(ch);
            hbuf[0] = base64_sink_detail::symbols[static_cast<size_t>(uch >> 4)];
            hbuf[1] = base64_sink_detail::symbols[static_cast<size_t>(uch & 0x0f)];
            sl::io::write_all(sink, {hbuf.data(), hbuf.size()});
        }
        return span.size_signed();
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
     * Underlying sink accessor
     * 
     * @return underlying sink reference
     */
    Sink& get_sink() {
        return sink;
    }

};

/**
 * Factory function for creating hex sinks,
 * created sink wrapper will own specified sink
 * 
 * @param sink destination sink
 * @return counting sink
 */
template <typename Sink,
        class = typename std::enable_if<!std::is_lvalue_reference<Sink>::value>::type>
base64_sink<Sink> make_base64_sink(Sink&& sink) {
    return base64_sink<Sink>(std::move(sink));
}

/**
 * Factory function for creating hex sinks,
 * created sink wrapper will NOT own specified sink
 * 
 * @param sink destination sink
 * @return counting sink
 */
template <typename Sink>
base64_sink<reference_sink<Sink>> make_base64_sink(Sink& sink) {
    return base64_sink<reference_sink<Sink>>(make_reference_sink(sink));
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_BASE64_SINK_HPP */

