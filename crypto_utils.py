"""
crypto_utils.py — Các hàm mật mã dùng chung cho mô phỏng.

Dùng đường cong P-256 (secp256r1) cho cả ECDH (trao đổi khóa) và
ECDSA (ký số), đúng như đã mô tả ở Mục 1.3 và Mục 3.3 của khóa luận.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, hmac as _hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

CURVE = ec.SECP256R1()


def gen_keypair():
    """Sinh một cặp khóa EC (dùng chung cho vai trò ký số lẫn ECDH)."""
    priv = ec.generate_private_key(CURVE)
    return priv, priv.public_key()


def pub_bytes(pub) -> bytes:
    """Chuyển khóa công khai thành bytes để gửi đi trên kênh mô phỏng."""
    return pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def load_pub(b: bytes):
    """Khôi phục khóa công khai từ bytes nhận được."""
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b)


def sign(priv, data: bytes) -> bytes:
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pub, data: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Chữ ký định dạng sai / khóa giả mạo không hợp lệ -> coi như xác minh thất bại
        return False


def ecdh_session_key(priv, peer_pub, info: bytes = b"session") -> bytes:
    """Thực hiện ECDH rồi suy dẫn khóa phiên 32 byte bằng HKDF-SHA256."""
    shared = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = _hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()
