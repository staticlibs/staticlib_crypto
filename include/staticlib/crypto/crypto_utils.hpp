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
 * File:   crypto_utils.hpp
 * Author: alex
 *
 * Created on February 6, 2016, 7:54 PM
 */

#ifndef STATICLIB_CRYPTO_CRYPTO_UTILS_HPP
#define STATICLIB_CRYPTO_CRYPTO_UTILS_HPP

#include <string>
#include <utility>
#include <cstdint>

#include "staticlib/io.hpp"

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"

namespace staticlib {
namespace crypto {

namespace detail {

class EVP_PKEY_Deleter {
public:
    void operator()(EVP_PKEY* key) {
        EVP_PKEY_free(key);
    }
};

class EVP_MD_CTX_Deleter {
public:
    void operator()(EVP_MD_CTX* ctx) {
        EVP_MD_CTX_destroy(ctx);
    }
};

class BIO_Deleter {
public:
    void operator()(BIO* bio) {
        BIO_free_all(bio);
    }
};

class X509_Deleter {
public:
    void operator()(X509* cert) {
        X509_free(cert);
    }
};

} // namespace

/**
 * Converts specified buffer into hex format
 * 
 * @param buf binary data
 * @param len length of specified buffer
 * @return data in hex format
 */
inline std::string to_hex(const unsigned char* buf, size_t len) {
    const char* sbuf = reinterpret_cast<const char*>(buf);
    auto src = sl::io::array_source(sbuf, len);
    auto sink = sl::io::string_sink();
    sl::io::copy_to_hex(src, sink);
    return sink.get_string();
}

/**
 * Converts specified string with binary data into hex format
 * 
 * @param data string with binary data
 * @return data in hex format
 */
inline std::string to_hex(const std::string& data) {
    auto src = sl::io::string_source(data);
    auto sink = sl::io::string_sink();
    sl::io::copy_to_hex(src, sink);
    return sink.get_string();
}

/**
 * Converts specified string with hex data into binary format
 * 
 * @param hex_data string with hex data
 * @return data in binary format
 */

inline std::string from_hex(const std::string& hex_data) {
    size_t offset = 0;
    if (hex_data.length() > 2 && '0' == hex_data[0] &&
            ('x' == hex_data[1] || 'X' == hex_data[1])) {
        offset += 2;
    }
    auto src = sl::io::array_source(hex_data.data() + offset, hex_data.size() - offset);
    auto sink = sl::io::string_sink();
    sl::io::copy_from_hex(src, sink);
    return sink.get_string();
}

} // namespace
}

#endif /* STATICLIB_CRYPTO_CRYPTO_UTILS_HPP */

