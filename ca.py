"""
ca.py — Mô phỏng máy chủ quản lý đáng tin cậy S (Certificate Authority)
dùng ở Pha 1 — Provisioning (Mục 3.3.1).

Trong thực tế, việc cấp chứng chỉ này chỉ thực hiện một lần, trong môi
trường được kiểm soát (ví dụ lúc lắp đặt khóa), không lặp lại mỗi lần
mở khóa.
"""
import crypto_utils as cu


class CA:
    def __init__(self):
        self.priv, self.pub = cu.gen_keypair()

    def issue_cert(self, device_id: str, device_pub) -> dict:
        """Cert = Sign_S(ID, PK) — đúng công thức ở Mục 3.3.1."""
        payload = device_id.encode() + cu.pub_bytes(device_pub)
        sig = cu.sign(self.priv, payload)
        return {"id": device_id, "pub": cu.pub_bytes(device_pub), "sig": sig}

    def verify_cert(self, cert: dict) -> bool:
        try:
            payload = cert["id"].encode() + cert["pub"]
            return cu.verify(self.pub, payload, cert["sig"])
        except Exception:
            # Chứng chỉ bị thiếu trường / định dạng sai (ví dụ do kẻ tấn công giả mạo)
            return False
