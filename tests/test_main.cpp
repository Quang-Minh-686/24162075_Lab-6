#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include "pqc_core.h"
#include "certificate.h"

// Biến toàn cục để theo dõi số lượng bài test
int total_tests = 0;
int passed_tests = 0;

// Bộ Macro/Hàm kiểm thử thô sơ trực quan
void assert_test(bool condition, const std::string& test_name) {
    total_tests++;
    if (condition) {
        std::cout << "[PASS] " << test_name << "\n";
        passed_tests++;
    } else {
        std::cerr << "[FAIL] " << test_name << " (Kiểm tra lại logic mã nguồn!)\n";
    }
}

// ============================================================================
// 1. HAPPY PATH TESTS (Kiểm thử chức năng hoạt động đúng khi đầu vào chuẩn)
// ============================================================================
void test_happy_paths() {
    std::cout << "--- BẮT ĐẦU KIỂM THỬ CHỨC NĂNG CHUẨN (HAPPY PATHS) ---\n";

    // Test sinh khóa
    std::vector<uint8_t> mldsa_pub, mldsa_priv;
    assert_test(PqcCore::generate_keypair("mldsa-44", mldsa_pub, mldsa_priv), "Sinh cặp khóa ML-DSA-44");
    assert_test(mldsa_pub.size() == PqcCore::Sizes::MLDSA44_PUBLIC_KEY, "Độ dài khóa công khai ML-DSA-44");

    // Test ký và xác thực chữ ký (ML-DSA)
    std::vector<uint8_t> message = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x50, 0x51, 0x43}; // "Hello PQC"
    std::vector<uint8_t> signature;
    assert_test(PqcCore::mldsa_sign("mldsa-44", message, mldsa_priv, signature), "Tạo chữ ký số ML-DSA-44");
    assert_test(PqcCore::mldsa_verify("mldsa-44", message, signature, mldsa_pub), "Xác thực chữ ký số ML-DSA-44");

    // Test đóng gói và giải gói khóa (ML-KEM)
    std::vector<uint8_t> kem_pub, kem_priv, ct, ss_encaps, ss_decaps;
    PqcCore::generate_keypair("mlkem-512", kem_pub, kem_priv);
    assert_test(PqcCore::mlkem_encapsulate(kem_pub, ct, ss_encaps), "Đóng gói khóa ML-KEM-512 (Encapsulation)");
    assert_test(PqcCore::mlkem_decapsulate(ct, kem_priv, ss_decaps), "Giải gói khóa ML-KEM-512 (Decapsulation)");
    assert_test(ss_encaps == ss_decaps, "So sánh hai mã khóa chung (Shared Secrets) trùng khớp");

    // Test Mini-Project Chứng chỉ PQC
    PqcCertificate::Certificate cert;
    assert_test(PqcCertificate::create_certificate("Sinh Vien A - B26DCAT001", mldsa_pub, "PQ-CA", mldsa_priv, cert), "Tạo chứng chỉ PQC điện tử JSON");
    assert_test(PqcCertificate::verify_certificate(cert, mldsa_pub), "Xác thực chữ ký số trên chứng chỉ bởi CA");
    std::cout << "\n";
}

// ============================================================================
// 2. NEGATIVE TESTS & MISUSE CHECKS (Kiểm thử tiêu cực & Chống can thiệp dữ liệu)
// ============================================================================
void test_negative_cases() {
    std::cout << "--- BẮT ĐẦU KIỂM THỬ TIÊU CỰC & AN TOÀN (NEGATIVE TESTS) ---\n";

    // Chuẩn bị dữ liệu mẫu hợp lệ ban đầu
    std::vector<uint8_t> pub, priv, sig;
    PqcCore::generate_keypair("mldsa-44", pub, priv);
    std::vector<uint8_t> message = {0x11, 0x22, 0x33, 0x44};
    PqcCore::mldsa_sign("mldsa-44", message, priv, sig);

    // Ca tiêu cực 1: Giả mạo nội dung thông điệp (Message Tampering)
    std::vector<uint8_t> tampered_message = {0x11, 0x22, 0x33, 0x99}; // Thay đổi byte cuối cùng
    bool verify_tampered_msg = PqcCore::mldsa_verify("mldsa-44", tampered_message, sig, pub);
    assert_test(verify_tampered_msg == false, "[Fail-closed] Từ chối xác thực khi thông điệp bị can thiệp");

    // Ca tiêu cực 2: Giả mạo chữ ký (Signature Tampering)
    std::vector<uint8_t> tampered_sig = sig;
    if (!tampered_sig.empty()) tampered_sig[0] ^= 0xFF; // Làm sai lệch byte đầu tiên của chữ ký
    bool verify_tampered_sig = PqcCore::mldsa_verify("mldsa-44", message, tampered_sig, pub);
    assert_test(verify_tampered_sig == false, "[Fail-closed] Từ chối xác thực khi cấu trúc chữ ký bị hỏng");

    // Ca tiêu cực 3: Truyền sai kích thước khóa bí mật (Misuse Prevention)
    std::vector<uint8_t> invalid_short_priv = {0x01, 0x02, 0x03}; // Khóa quá ngắn so với tiêu chuẩn
    std::vector<uint8_t> bad_sig;
    bool sign_with_bad_key = PqcCore::mldsa_sign("mldsa-44", message, invalid_short_priv, bad_sig);
    assert_test(sign_with_bad_key == false, "[Fail-closed] Ngăn chặn thực thi khi độ dài khóa bí mật không hợp lệ");

    // Ca tiêu cực 4: ML-KEM Can thiệp Ciphertext (IND-CCA Security Test)
    std::vector<uint8_t> k_pub, k_priv, k_ct, k_ss1, k_ss2;
    PqcCore::generate_keypair("mlkem-512", k_pub, k_priv);
    PqcCore::mlkem_encapsulate(k_pub, k_ct, k_ss1);
    
    std::vector<uint8_t> tampered_ct = k_ct;
    if(!tampered_ct.empty()) tampered_ct[0] ^= 0x55; // Sửa đổi gói tin ciphertext trên đường truyền
    bool decaps_tampered = PqcCore::mlkem_decapsulate(tampered_ct, k_priv, k_ss2);
    assert_test(decaps_tampered == false, "[IND-CCA] Phát hiện và từ chối sinh khóa chung khi Ciphertext bị can thiệp");

    // Ca tiêu cực 5: Giả mạo thông tin trong chứng chỉ điện tử (Certificate Tampering)
    PqcCertificate::Certificate cert;
    PqcCertificate::create_certificate("Sinh Vien A", pub, "PQ-CA", priv, cert);
    cert.subject = "Sinh Vien B (Gia mao ten)"; // Kẻ tấn công cố tình đổi tên trên chứng chỉ JSON
    bool verify_tampered_cert = PqcCertificate::verify_certificate(cert, pub);
    assert_test(verify_tampered_cert == false, "[Anti-Tamper] Chứng chỉ JSON bị phát hiện không hợp lệ ngay khi sửa đổi 1 ký tự");
    
    std::cout << "\n";
}
int main() {
    std::cout << "========================================================\n";
    std::cout << "   HỆ THỐNG KIỂM THỬ TỰ ĐỘNG LAB 6 (POST-QUANTUM REGRESSION)\n";
    std::cout << "========================================================\n\n";

    test_happy_paths();
    test_negative_cases();

    std::cout << "========================================================\n";
    std::cout << "KẾT QUẢ TỔNG HỢP: Đạt " << passed_tests << " / " << total_tests << " bài test.\n";
    std::cout << "========================================================\n";

    // Trả về mã lỗi nếu có bất kỳ bài test nào thất bại, phục vụ quy trình CI/CD và ctest
    if (passed_tests == total_tests) {
        return 0; // SUCCESS
    } else {
        return 1; // FAILURE
    }
}