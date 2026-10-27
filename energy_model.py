"""
energy_model.py — Ước tính năng lượng tiêu thụ (mAh/lần mở khóa) theo
mô hình lý thuyết, KHÔNG đo trực tiếp trên phần cứng (đúng phạm vi đã
xác định ở Mục A.5 và phương pháp ở Mục A.6.2).

Cách làm: đếm số phép toán mật mã mỗi giao thức cần thực hiện, tra
bảng năng lượng trung bình mỗi phép toán đã công bố trong tài liệu kỹ
thuật của một dòng vi điều khiển BLE phổ biến (Nordic nRF52832), rồi
quy đổi sang mAh — theo cùng cách tiếp cận ước tính chi phí mà Jiang,
Shen và Zhu (2020) đã áp dụng (trích dẫn trong Mục A.6.2).

LƯU Ý: các con số ENERGY_PER_OP_UJ dưới đây là số liệu THAM KHẢO ước
lượng cho mục đích minh họa phương pháp — khi viết chính thức vào
khóa luận, cần thay bằng số liệu thực tế trích dẫn từ datasheet Nordic
nRF52832 hoặc từ bài báo đo đạc đã công bố (ví dụ các nghiên cứu benchmark
ECC trên Cortex-M4F), kèm chú thích nguồn rõ ràng.
"""

# Đơn vị: micro-Joule (µJ) mỗi phép toán, tham khảo minh họa cho Cortex-M4F @ 64MHz
ENERGY_PER_OP_UJ = {
    "ecdh_p256": 4400,
    "ecdsa_sign": 3800,
    "ecdsa_verify": 6200,
    "hmac_sha256": 15,
}

VOLTAGE = 3.0  # Volt — điện áp danh định pin CR2032/AA phổ biến cho khóa BLE


def estimate_energy_baseline_uj() -> float:
    """Just Works không thực hiện phép toán mật mã nào."""
    return 0.0


def estimate_energy_proposed_uj() -> float:
    """
    Đếm số phép toán cho MỘT lần mở khóa với giao thức đề xuất:
      - Pha 1: xác minh 2 chữ ký chứng chỉ (ecdsa_verify x2)
        (chứng chỉ đã cấp sẵn từ trước, nhưng vẫn cần xác minh lại mỗi
        lần thiết lập phiên mới theo đúng thiết kế Mục 3.3.1)
      - Pha 2: 1 phép ECDH + 1 phép ký (bên gửi) + 1 phép xác minh chữ ký
        (bên nhận, cho giá trị ephemeral của đối phương)
      - Pha 3: 3 lượt HMAC-SHA256 (2 lượt phản hồi + 1 lượt lệnh mở khóa)
    """
    ops_uj = (
        2 * ENERGY_PER_OP_UJ["ecdsa_verify"]   # Pha 1
        + 1 * ENERGY_PER_OP_UJ["ecdh_p256"]    # Pha 2 - ECDH
        + 1 * ENERGY_PER_OP_UJ["ecdsa_sign"]   # Pha 2 - ký ephemeral
        + 1 * ENERGY_PER_OP_UJ["ecdsa_verify"] # Pha 2 - xác minh chữ ký đối phương
        + 3 * ENERGY_PER_OP_UJ["hmac_sha256"]  # Pha 3
    )
    return ops_uj


def uj_to_mah(energy_uj: float, voltage: float = VOLTAGE) -> float:
    """Quy đổi micro-Joule -> mAh: Q(Ah) = E(J) / V(V) / 3600."""
    energy_j = energy_uj / 1_000_000
    energy_ah = energy_j / voltage / 3600
    return energy_ah * 1000  # mAh


def main():
    base_uj = estimate_energy_baseline_uj()
    prop_uj = estimate_energy_proposed_uj()
    print(f"{'Chế độ':<20s}{'Năng lượng (µJ)':>18s}{'Năng lượng (mAh)':>20s}")
    print("-" * 58)
    print(f"{'Baseline (Just Works)':<20s}{base_uj:>18.2f}{uj_to_mah(base_uj):>20.10f}")
    print(f"{'Giao thức đề xuất':<20s}{prop_uj:>18.2f}{uj_to_mah(prop_uj):>20.10f}")
    print(f"\nMức tăng chi phí năng lượng: {prop_uj - base_uj:.2f} µJ/lần mở khóa "
          f"(so với baseline không có chi phí mật mã nào)")


if __name__ == "__main__":
    main()
