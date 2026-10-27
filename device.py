"""
device.py — Đại diện chung cho A (ứng dụng điều khiển / central) và
B (khóa thông minh / peripheral). Mỗi Device giữ:
  - một cặp khóa định danh dài hạn (long-term identity key)
  - một chứng chỉ do CA cấp (Mục 3.3.1)
  - danh sách nonce đã dùng, để chống replay ở Pha 3 (Mục 3.3.3)
"""
import crypto_utils as cu


class Device:
    def __init__(self, device_id: str, ca):
        self.id = device_id
        self.priv, self.pub = cu.gen_keypair()
        self.ca = ca
        self.cert = ca.issue_cert(device_id, self.pub)
        self.seen_nonces = set()

    def new_ephemeral(self):
        """Sinh cặp khóa ECDH tạm thời cho Pha 2 (Session Establishment)."""
        return cu.gen_keypair()
