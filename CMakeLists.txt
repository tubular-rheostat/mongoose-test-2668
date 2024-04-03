cmake_minimum_required(VERSION 3.27)
project(mongoose)

set(CMAKE_CXX_STANDARD 20)

add_compile_options(
        -Og
        -Wall
        -Wextra
)

add_compile_options(
        -Wall
        -Wextra
        -Wconversion
        -Wsign-conversion
        -Wformat
        -Wno-unused-function
        -Wimplicit-fallthrough
)

add_executable(mongoose main.cpp
        mongoose.c
        mongoose.h
        mg_fd_netif.cpp
        mg_fd_netif.h
        tun_interface.cpp
        tun_interface.h)

enable_testing()

add_test(NAME mongoose-test COMMAND mongoose --test)

target_compile_definitions(mongoose PRIVATE
        MG_ENABLE_TCPIP=1
        MG_TLS=MG_TLS_MBED
        MG_ENABLE_CUSTOM_LOG)

target_include_directories(mongoose PRIVATE
        include)

target_link_libraries(mongoose PRIVATE
#        ssl
#        crypto
        )

target_compile_options(mongoose PRIVATE
        -fsanitize=address
        -fsanitize=undefined)

target_link_options(mongoose PRIVATE
        -fsanitize=address
        -fsanitize=undefined)

#
#
# mbedtls
set (NETCLIENT_MBEDTLS_PATH /Users/bsandlin/Github/@MBed-TLS/mbedtls)

# cribbed from pico-sdk src/rp2_common/pico_mbedtls/CMakeLists.txt
set(src_crypto
        aes.c
        aesni.c
        arc4.c
        aria.c
        asn1parse.c
        asn1write.c
        base64.c
        bignum.c
        blowfish.c
        camellia.c
        ccm.c
        chacha20.c
        chachapoly.c
        cipher.c
        cipher_wrap.c
        constant_time.c
        cmac.c
        ctr_drbg.c
        des.c
        dhm.c
        ecdh.c
        ecdsa.c
        ecjpake.c
        ecp.c
        ecp_curves.c
        entropy.c
        entropy_poll.c
        error.c
        gcm.c
        havege.c
        hkdf.c
        hmac_drbg.c
        md.c
        md2.c
        md4.c
        md5.c
        memory_buffer_alloc.c
        mps_reader.c
        mps_trace.c
        nist_kw.c
        oid.c
        padlock.c
        pem.c
        pk.c
        pk_wrap.c
        pkcs12.c
        pkcs5.c
        pkparse.c
        pkwrite.c
        platform.c
        platform_util.c
        poly1305.c
        ripemd160.c
        rsa.c
        rsa_internal.c
        sha1.c
        sha256.c
        sha512.c
        threading.c
        timing.c
        version.c
        version_features.c
        xtea.c
)
list(TRANSFORM src_crypto PREPEND ${NETCLIENT_MBEDTLS_PATH}/library/)
add_library(netclient_mbedtls_crypto INTERFACE)
target_sources(netclient_mbedtls_crypto INTERFACE ${src_crypto})

set(src_x509
        certs.c
        pkcs11.c
        x509.c
        x509_create.c
        x509_crl.c
        x509_crt.c
        x509_csr.c
        x509write_crt.c
        x509write_csr.c
)
list(TRANSFORM src_x509 PREPEND ${NETCLIENT_MBEDTLS_PATH}/library/)
add_library(netclient_mbedtls_x509 INTERFACE)
target_sources(netclient_mbedtls_x509 INTERFACE ${src_x509})

set(src_tls
        debug.c
        net_sockets.c
        ssl_cache.c
        ssl_ciphersuites.c
        ssl_cli.c
        ssl_cookie.c
        ssl_msg.c
        ssl_srv.c
        ssl_ticket.c
        ssl_tls.c
        ssl_tls13_keys.c
)
list(TRANSFORM src_tls PREPEND ${NETCLIENT_MBEDTLS_PATH}/library/)
add_library(netclient_mbedtls_tls INTERFACE)
target_sources(netclient_mbedtls_tls INTERFACE ${src_tls})

target_link_libraries(mongoose PRIVATE
        netclient_mbedtls_tls
        netclient_mbedtls_crypto
        netclient_mbedtls_x509)

target_include_directories(netclient_mbedtls_tls INTERFACE
        ${NETCLIENT_MBEDTLS_PATH}/include)

target_include_directories(netclient_mbedtls_crypto INTERFACE
        ${NETCLIENT_MBEDTLS_PATH}/include)

target_include_directories(netclient_mbedtls_x509 INTERFACE
        ${NETCLIENT_MBEDTLS_PATH}/include)

target_include_directories(mongoose PRIVATE
        ${NETCLIENT_MBEDTLS_PATH}/include)


# OpennSSL config
# Intel: /usr/local/opt/openssl@3
# ARM: /opt/homebrew/opt/openssl@3
#target_include_directories(mongoose PRIVATE
#        #        /opt/homebrew/opt/openssl@3/include)
#        /usr/local/opt/openssl@3/include)
#
#target_link_directories(mongoose PRIVATE
#        #        /opt/homebrew/opt/openssl@3/lib)
#        /usr/local/opt/openssl@3/lib)
#
