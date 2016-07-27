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
#define	STATICLIB_CRYPTO_CRYPTO_UTILS_HPP

#include <array>
#include <string>
#include <utility>
#include <cerrno>
#include <cstdint>

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
    // http://stackoverflow.com/a/18025541/314015
    std::array<char, 16> symbols = {{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}};
    std::string res{};
    res.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        int idx = buf[i] >> 4;
        res[2 * i] = symbols[idx];
        idx = buf[i] & 0x0f;
        res[2 * i + 1] = symbols[idx];
    }
    return res;
}

/**
 * Converts specified string with binary data into hex format
 * 
 * @param data string with binary data
 * @return data in hex format
 */
inline std::string to_hex(const std::string& data) {
    return to_hex(reinterpret_cast<const unsigned char*> (data.c_str()), data.length());
}

/**
 * Converts specified string with hex data into binary format
 * 
 * @param hex_data string with hex data
 * @return data in binary format
 */

inline std::string from_hex(const std::string& hex_data) {
    std::string res;
    std::array<char, 3> buf;
    buf[2] = '\0';
    size_t i = 0;
    if (hex_data.length() > 2 && '0' == hex_data[0] &&
            ('x' == hex_data[1] || 'X' == hex_data[1])) {
        i += 2;
    }
    for (; i < hex_data.length(); i += 2) {
        buf[0] = hex_data[i];
        buf[1] = hex_data[i + 1];
        char* end = nullptr;
        errno = 0;
        char byte = static_cast<char> (strtol(buf.data(), std::addressof(end), 16));
        if (errno == ERANGE || end != buf.data() + 2) {
            res = "";
            break;
        }
        res.push_back(byte);
    }
    return res;
}

} // namespace
}

#endif	/* STATICLIB_CRYPTO_CRYPTO_UTILS_HPP */

