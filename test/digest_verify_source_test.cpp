/* 
 * File:   digest_verify_source_test.cpp
 * Author: alex
 *
 * Created on July 16, 2016, 8:18 AM
 */

#include "staticlib/crypto/digest_verify_source.hpp"

#include <array>
#include <iostream>

#include "staticlib/config/assert.hpp"
#include "staticlib/io.hpp"

namespace io = staticlib::io;
namespace sc = staticlib::crypto;

const std::string TEXT = "foo bar baz";
const std::string SIGNATURE = R"(9553aef514b5c005e46b864234c254bf7a792a77cde8b3fdf65385238ed292b0
0a590571fb8fdb46be80431f4410ff7c2a7e2a6ddbbb2b029346a2c7e9d9a752
f06e26a815fe860fb75a36cd3b2d0a2257a4ee625d6cf872396f85ede1cf04ce
cac00e9bf44e6306af0ebf27c32a5357af2970a225eb6daaefb830ee1111634b
9e7f9856e5bb79b1f16c901d212e96223f450909a6826430d41040c6e3fbd94f
e2c021f5033bab692b86350d8f4eb14c163e7bf97d8d79dffdf089e2818fe021
eac9b004928266898d8717972b08ac560cbea31a074e384948975c9ae189a0b1
fbc4ddacb5a33853d9fb6ff7a9dad2cfeaa5704dd02f6c5076cd6cb06afe3019)";
const std::string CERT_PATH = "../test/certificate/test.cert";

void test_verify() {
//    auto src = sc::make_digest_sink_source(io::string_source(TEXT), CERT_PATH);
//    auto sink = io::string_sink();
//    std::array<char, 2> buf;
//    io::copy_all(src, sink, buf.data(), buf.size());
//
//    slassert(src.is_valid());
}

int main() {
    try {
        test_verify();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return 1;
    }
    return 0;
}
