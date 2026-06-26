#ifndef PQC_CORE_H
#define PQC_CORE_H

#include <vector>
#include <string>
#include <cstdint>

namespace PqcCore {

    namespace Sizes {
        // ML-DSA-44 (Security Level 2)
        constexpr size_t MLDSA44_PUBLIC_KEY = 1312;
        constexpr size_t MLDSA44_SECRET_KEY = 2560;
        constexpr size_t MLDSA44_SIGNATURE  = 2420;

        // ML-DSA-65 (Security Level 3 - Bonus)
        constexpr size_t MLDSA65_PUBLIC_KEY = 1952;
        constexpr size_t MLDSA65_SECRET_KEY = 4032;
        constexpr size_t MLDSA65_SIGNATURE  = 3308;

        // ML-KEM-512 (Security Level 2)
        constexpr size_t MLKEM512_PUBLIC_KEY = 800;
        constexpr size_t MLKEM512_SECRET_KEY = 1632;
        constexpr size_t MLKEM512_CIPHERTEXT = 768;
        constexpr size_t MLKEM512_SHARED_SECRET = 32;
    }

    bool generate_keypair(const std::string& algo, 
                          std::vector<uint8_t>& pub_key, 
                          std::vector<uint8_t>& priv_key);

    bool mldsa_sign(const std::string& algo,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& priv_key,
                    std::vector<uint8_t>& signature);

    bool mldsa_verify(const std::string& algo,
                      const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& pub_key);

    bool mlkem_encapsulate(const std::vector<uint8_t>& pub_key,
                           std::vector<uint8_t>& ciphertext,
                           std::vector<uint8_t>& shared_secret);

    bool mlkem_decapsulate(const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& priv_key,
                           std::vector<uint8_t>& shared_secret);

    std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    
    std::string bytes_to_base64(const std::vector<uint8_t>& bytes);
    std::vector<uint8_t> base64_to_bytes(const std::string& b64);
}

#endif 
