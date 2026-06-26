#include "certificate.h"
#include "pqc_core.h"
#include <iostream>

namespace PqcCertificate {

    std::string serialize_for_signing(const Certificate& cert) {
        // Chuẩn hóa dữ liệu có tính chất Deterministic tránh lỗi lệch cấu trúc ký tự [cite: 209]
        return "subject:" + cert.subject + "|public_key:" + cert.public_key + "|issuer:" + cert.issuer;
    }

    std::string to_json_string(const Certificate& cert) {
        // Tạo định dạng JSON thủ công chuẩn xác đúng yêu cầu [cite: 240]
        std::string json = "{\n";
        json += "  \"subject\": \"" + cert.subject + "\",\n";
        json += "  \"public_key\": \"" + cert.public_key + "\",\n";
        json += "  \"issuer\": \"" + cert.issuer + "\",\n";
        json += "  \"signature\": \"" + cert.signature + "\"\n";
        json += "}";
        return json;
    }

    bool from_json_string(const std::string& json_str, Certificate& out_cert) {
        auto extract_value = [](const std::string& json, const std::string& key) -> std::string {
            size_t key_pos = json.find("\"" + key + "\"");
            if (key_pos == std::string::npos) return "";
            size_t colon_pos = json.find(":", key_pos);
            size_t start_quote = json.find("\"", colon_pos);
            size_t end_quote = json.find("\"", start_quote + 1);
            if (start_quote == std::string::npos || end_quote == std::string::npos) return "";
            return json.substr(start_quote + 1, end_quote - start_quote - 1);
        };

        out_cert.subject = extract_value(json_str, "subject");
        out_cert.public_key = extract_value(json_str, "public_key");
        out_cert.issuer = extract_value(json_str, "issuer");
        out_cert.signature = extract_value(json_str, "signature");

        return !out_cert.subject.empty() && !out_cert.public_key.empty() && !out_cert.issuer.empty();
    }

    bool create_certificate(const std::string& subject_name,
                            const std::vector<uint8_t>& subject_pub_key,
                            const std::string& ca_issuer_name,
                            const std::vector<uint8_t>& ca_priv_key,
                            Certificate& out_cert) {
        
        out_cert.subject = subject_name;
        out_cert.public_key = PqcCore::bytes_to_base64(subject_pub_key); // Encode B64 [cite: 235]
        out_cert.issuer = ca_issuer_name;

        // Tạo chuỗi dữ liệu thô để ký
        std::string raw_data = serialize_for_signing(out_cert);
        std::vector<uint8_t> data_bytes(raw_data.begin(), raw_data.end());
        std::vector<uint8_t> sig_bytes;

        // Dùng ML-DSA-44 mặc định để ký chứng chỉ [cite: 244]
        if (!PqcCore::mldsa_sign("mldsa-44", data_bytes, ca_priv_key, sig_bytes)) {
            return false;
        }

        out_cert.signature = PqcCore::bytes_to_base64(sig_bytes);
        return true;
    }

    bool verify_certificate(const Certificate& cert, const std::vector<uint8_t>& ca_pub_key) {
        std::string raw_data = serialize_for_signing(cert);
        std::vector<uint8_t> data_bytes(raw_data.begin(), raw_data.end());
        std::vector<uint8_t> sig_bytes = PqcCore::base64_to_bytes(cert.signature);

        // Xác thực chữ ký bằng Khóa công khai của CA [cite: 249]
        return PqcCore::mldsa_verify("mldsa-44", data_bytes, sig_bytes, ca_pub_key);
    }
}