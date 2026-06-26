#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <string>
#include <vector>
#include <cstdint>

namespace PqcCertificate {

    struct Certificate {
        std::string subject;       
        std::string public_key;    
        std::string issuer;        
        std::string signature;     
    };

    std::string serialize_for_signing(const Certificate& cert);

    std::string to_json_string(const Certificate& cert);

    bool from_json_string(const std::string& json_str, Certificate& out_cert);

    bool create_certificate(const std::string& subject_name,
                            const std::vector<uint8_t>& subject_pub_key,
                            const std::string& ca_issuer_name,
                            const std::vector<uint8_t>& ca_priv_key,
                            Certificate& out_cert);

    bool verify_certificate(const Certificate& cert, const std::vector<uint8_t>& ca_pub_key);
}

#endif // CERTIFICATE_H
