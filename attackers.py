"""
attackers.py — Hiện thực hóa 3 kịch bản tấn công cốt lõi đã xác định
ở Mục A.3 (MT4) và đối chiếu ở Bảng 3.2:

  1. MITMAttacker            — giả mạo ở Pha 1 (không có chứng chỉ hợp lệ)
  2. BLESAAttacker            — giả mạo phản hồi ở Pha 3 (không có khóa phiên hợp lệ)
  3. ReplayAttacker           — phát lại một thông điệp Pha 3 đã cũ (quá hạn timestamp)

Mỗi lớp có method tamper(msg, phase) được protocol.py gọi tại từng
điểm trao đổi thông điệp — đây chính là cách hiện thực hóa năng lực
"đọc / sửa / chèn / chặn / phát lại" của mô hình đối kháng Dolev–Yao
(Mục 3.1).
"""
import os
import time
import crypto_utils as cu


class MITMAttacker:
    """Kịch bản 1 — tấn công MITM ngay tại Pha 1 (không sở hữu chứng chỉ hợp lệ)."""
    name = "MITM"

    def tamper(self, msg, phase):
        if phase == "baseline":
            # Baseline (Just Works) không có khái niệm chứng chỉ -> attacker tự xưng luôn
            return {"type": "REQUEST_UNLOCK", "from": "attacker"}
        if phase in ("cert_central", "cert_peripheral"):
            # Attacker thay chứng chỉ hợp lệ bằng một chứng chỉ tự ký (không có chữ ký CA thật)
            fake_priv, fake_pub = cu.gen_keypair()
            fake_cert = {"id": "attacker_device", "pub": cu.pub_bytes(fake_pub), "sig": os.urandom(70)}
            return {"type": msg["type"], "cert": fake_cert}
        return msg

    def simulate_rssi(self):
        return True

    def simulate_user_confirmation(self):
        return True


class BLESAAttacker:
    """Kịch bản 2 — giả mạo reconnection kiểu BLESA: attacker đóng vai
    peripheral phản hồi Pha 3 mà không có khóa phiên hợp lệ (vì không
    trải qua đúng Pha 1-2 với central)."""
    name = "BLESA_reconnect_spoof"

    def tamper(self, msg, phase):
        if phase == "baseline":
            return {"type": "REQUEST_UNLOCK", "from": "attacker_reconnect"}
        if phase == "response":
            # Không biết khóa phiên thật -> chỉ có thể đoán ngẫu nhiên giá trị HMAC
            return {"type": "RESPONSE", "N_B": os.urandom(8), "T_B": time.time(), "hmac": os.urandom(32)}
        return msg

    def simulate_rssi(self):
        return True

    def simulate_user_confirmation(self):
        return True


class ReplayAttacker:
    """Kịch bản 3 — phát lại một thông điệp Pha 3 đã ghi lại từ một
    phiên hợp lệ trước đó (đã quá hạn cửa sổ thời gian cho phép)."""
    name = "Replay"

    def __init__(self):
        # Giả lập một thông điệp "bắt được" từ 100 giây trước — vượt xa
        # cửa sổ hợp lệ REPLAY_WINDOW_SECONDS = 5 giây trong protocol.py
        self.captured_msg = {"type": "CHALLENGE", "N_A": os.urandom(8), "T_A": time.time() - 100}

    def tamper(self, msg, phase):
        if phase == "baseline":
            return msg  # baseline không có bước nào để chặn phát lại
        if phase == "challenge":
            return self.captured_msg  # thay challenge mới bằng challenge cũ đã bắt được
        return msg

    def simulate_rssi(self):
        return True

    def simulate_user_confirmation(self):
        return True
