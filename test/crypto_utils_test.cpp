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
 * File:   crypto_utils_test.cpp
 * Author: alex
 *
 * Created on July 16, 2016, 1:43 PM
 */

#include <iostream>

#include "openssl/bio.h"
#include "openssl/evp.h"

#include "staticlib/config/assert.hpp"

void test_base64() {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* src = BIO_new(BIO_s_bio());
    int err_src_buf_size = BIO_set_write_buf_size(src, 4096);
    slassert(1 == err_src_buf_size);

    BIO* pushed_bio = BIO_push(b64, src);
    slassert(pushed_bio == b64);
    
    BIO* sink = BIO_new(BIO_s_bio());
    int err_sink_buf_size = BIO_set_write_buf_size(sink, 4096);
    slassert(1 == err_sink_buf_size);

    int err_make_pair = BIO_make_bio_pair(src, sink);
    slassert(1 == err_make_pair);

    auto data = std::string("foobar\n");
    for (size_t i = 0; i < 1; i++) {
        auto allowed = BIO_get_write_guarantee(b64);
        std::cout << allowed << std::endl;
        auto written = BIO_write(b64, data.data(), data.size());
        std::cout << written << std::endl;
    }
    auto err_flush = BIO_flush(b64);
    slassert(1 == err_flush);

    auto dest = std::string();
    dest.resize(1024);
    auto read = BIO_read(sink, std::addressof(dest.front()), dest.size());
    std::cout << read << std::endl;
    dest.resize(read);
    std::cout << read << std::endl;
    std::cout << "[" << dest << "]" << std::endl;


    BIO_free(b64);
    int err_destroy = BIO_destroy_bio_pair(src);
    slassert(1 == err_destroy);
    BIO_free(src);
    BIO_free(sink);
}

void test_decode() {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* src = BIO_new(BIO_s_bio());
    int err_src_buf_size = BIO_set_write_buf_size(src, 4096);
    slassert(1 == err_src_buf_size);

    BIO* sink = BIO_new(BIO_s_bio());
    int err_sink_buf_size = BIO_set_write_buf_size(sink, 4096);
    slassert(1 == err_sink_buf_size);

    BIO* pushed_bio = BIO_push(b64, sink);
    slassert(pushed_bio == b64);

    int err_make_pair = BIO_make_bio_pair(src, sink);
    slassert(1 == err_make_pair);

    auto data = std::string("Zm9vYmFyCg==");
    auto written = BIO_write(src, data.data(), data.size());
    std::cout << written << std::endl;
    auto err_flush = BIO_flush(src);
    slassert(1 == err_flush);
    auto err_flush1 = BIO_flush(sink);
    slassert(1 == err_flush1);

    auto dest = std::string();
    dest.resize(1024);
    auto read = BIO_read(b64, std::addressof(dest.front()), dest.size());
    std::cout << read << std::endl;
    dest.resize(read);
    std::cout << read << std::endl;
    std::cout << "[" << dest << "]" << std::endl;

    BIO_free(src);
    BIO_free(b64);
    BIO_free(sink);
}

int main() {
    try {
        //test_hex();
//        test_base64();
        test_decode();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
