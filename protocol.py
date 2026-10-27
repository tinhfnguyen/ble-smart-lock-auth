"""
protocol.py — Cài đặt baseline (BLE Just Works mặc định) và giao thức
đề xuất 4 pha (Mục 3.3 của khóa luận).

Thiết kế mô phỏng: mỗi thông điệp trao đổi giữa central và peripheral
đều đi qua attacker.tamper(msg, phase) trước khi đến người nhận — đây
chính là cách hiện thực hóa mô hình đối kháng Dolev–Yao (kẻ tấn công
kiểm soát hoàn toàn kênh truyền, Mục 3.1). Nếu không có tấn công, gọi
hàm với attacker=None.

attacker.tamper() trả về:
  - msg gốc (không đổi)      -> tấn công thụ động / không can thiệp
  - msg đã bị sửa/giả mạo    -> tấn công chủ động
  - None                     -> kẻ tấn công CHẶN đứng thông điệp (Block)
"""
import os
import time
import crypto_utils as cu

REPLAY_WINDOW_SECONDS = 5.0


def _maybe_tamper(msg, attacker, phase):
    if attacker is None:
        return msg
    return attacker.tamper(msg, phase)


def run_baseline(central, peripheral, attacker=None):
    """
    Mô phỏng BLE Just Works: không có bất kỳ bước xác thực nào
    (Mục 2.3.1) — dùng làm đối chứng (baseline) cho thí nghiệm.
    """
    t0 = time.perf_counter()
    msg = {"type": "REQUEST_UNLOCK", "from": central.id}
    msg = _maybe_tamper(msg, attacker, phase="baseline")
    if msg is None:
        return {"unlocked": False, "reason": "blocked_by_channel", "time": time.perf_counter() - t0}

    # Just Works: peripheral mở khóa ngay khi có yêu cầu, không kiểm tra danh tính
    return {"unlocked": True, "reason": "just_works_no_auth", "time": time.perf_counter() - t0}


def run_proposed(central, peripheral, attacker=None, forced_replay_msg=None):
    """
    Giao thức đề xuất 4 pha, đúng theo Mục 3.3.1 - 3.3.4.
    forced_replay_msg: nếu khác None, dùng để mô phỏng kẻ tấn công phát lại
    một thông điệp Pha 3 đã ghi lại từ trước (kịch bản Replay).
    """
    t0 = time.perf_counter()

    # ---------- Pha 1: Provisioning — trao đổi & xác minh chứng chỉ ----------
    msg1a = _maybe_tamper({"type": "CERT_CENTRAL", "cert": central.cert}, attacker, "cert_central")
    if msg1a is None:
        return {"unlocked": False, "reason": "blocked_at_phase1", "time": time.perf_counter() - t0}
    if not peripheral.ca.verify_cert(msg1a["cert"]):
        return {"unlocked": False, "reason": "phase1_cert_invalid_spoof_blocked", "time": time.perf_counter() - t0}
    central_ltk_pub = cu.load_pub(msg1a["cert"]["pub"])

    msg1b = _maybe_tamper({"type": "CERT_PERIPHERAL", "cert": peripheral.cert}, attacker, "cert_peripheral")
    if msg1b is None:
        return {"unlocked": False, "reason": "blocked_at_phase1", "time": time.perf_counter() - t0}
    if not central.ca.verify_cert(msg1b["cert"]):
        return {"unlocked": False, "reason": "phase1_cert_invalid_spoof_blocked", "time": time.perf_counter() - t0}
    peripheral_ltk_pub = cu.load_pub(msg1b["cert"]["pub"])

    # ---------- Pha 2: Session Establishment — ECDH tạm thời có ký ----------
    a_priv, a_pub = central.new_ephemeral()
    aG = cu.pub_bytes(a_pub)
    sig_a = cu.sign(central.priv, aG)
    msg2a = _maybe_tamper({"type": "SESSION_A", "aG": aG, "sig": sig_a}, attacker, "session_a")
    if msg2a is None:
        return {"unlocked": False, "reason": "blocked_at_phase2", "time": time.perf_counter() - t0}
    if not cu.verify(central_ltk_pub, msg2a["aG"], msg2a["sig"]):
        return {"unlocked": False, "reason": "phase2_signature_invalid_mitm_blocked", "time": time.perf_counter() - t0}

    b_priv, b_pub = peripheral.new_ephemeral()
    bG = cu.pub_bytes(b_pub)
    sig_b = cu.sign(peripheral.priv, bG)
    msg2b = _maybe_tamper({"type": "SESSION_B", "bG": bG, "sig": sig_b}, attacker, "session_b")
    if msg2b is None:
        return {"unlocked": False, "reason": "blocked_at_phase2", "time": time.perf_counter() - t0}
    if not cu.verify(peripheral_ltk_pub, msg2b["bG"], msg2b["sig"]):
        return {"unlocked": False, "reason": "phase2_signature_invalid_mitm_blocked", "time": time.perf_counter() - t0}

    a_pub_eph = cu.load_pub(msg2a["aG"])
    b_pub_eph = cu.load_pub(msg2b["bG"])
    k_central = cu.ecdh_session_key(a_priv, b_pub_eph)
    k_peripheral = cu.ecdh_session_key(b_priv, a_pub_eph)

    # ---------- Pha 3: Mutual Challenge–Response ----------
    N_A, T_A = os.urandom(8), time.time()
    msg3a = {"type": "CHALLENGE", "N_A": N_A, "T_A": T_A}
    if forced_replay_msg is not None:
        msg3a = forced_replay_msg
    msg3a = _maybe_tamper(msg3a, attacker, "challenge")
    if msg3a is None:
        return {"unlocked": False, "reason": "blocked_at_phase3", "time": time.perf_counter() - t0}

    if abs(time.time() - msg3a["T_A"]) > REPLAY_WINDOW_SECONDS:
        return {"unlocked": False, "reason": "phase3_timestamp_expired_replay_blocked", "time": time.perf_counter() - t0}
    if msg3a["N_A"] in peripheral.seen_nonces:
        return {"unlocked": False, "reason": "phase3_nonce_reused_replay_blocked", "time": time.perf_counter() - t0}
    peripheral.seen_nonces.add(msg3a["N_A"])

    resp_b = cu.hmac_sha256(k_peripheral, msg3a["N_A"] + peripheral.id.encode() + str(msg3a["T_A"]).encode())
    N_B, T_B = os.urandom(8), time.time()
    msg3b = _maybe_tamper({"type": "RESPONSE", "N_B": N_B, "T_B": T_B, "hmac": resp_b}, attacker, "response")
    if msg3b is None:
        return {"unlocked": False, "reason": "blocked_at_phase3", "time": time.perf_counter() - t0}

    expected_b = cu.hmac_sha256(k_central, msg3a["N_A"] + peripheral.id.encode() + str(msg3a["T_A"]).encode())
    if msg3b["hmac"] != expected_b:
        return {"unlocked": False, "reason": "phase3_hmac_mismatch_spoof_blocked", "time": time.perf_counter() - t0}

    final_hmac = cu.hmac_sha256(k_central, msg3b["N_B"] + central.id.encode() + b"UNLOCK")
    msg3c = _maybe_tamper({"type": "UNLOCK_CMD", "hmac": final_hmac}, attacker, "unlock_cmd")
    if msg3c is None:
        return {"unlocked": False, "reason": "blocked_at_phase3", "time": time.perf_counter() - t0}

    expected_final = cu.hmac_sha256(k_peripheral, msg3b["N_B"] + central.id.encode() + b"UNLOCK")
    if msg3c["hmac"] != expected_final:
        return {"unlocked": False, "reason": "phase3_final_hmac_mismatch_spoof_blocked", "time": time.perf_counter() - t0}

    # ---------- Pha 4: Liveness / Proximity Check ----------
    rssi_ok = attacker.simulate_rssi() if attacker else True
    user_confirmed = attacker.simulate_user_confirmation() if attacker else True
    if not rssi_ok or not user_confirmed:
        return {"unlocked": False, "reason": "phase4_liveness_failed_relay_mitigated", "time": time.perf_counter() - t0}

    # Ghi nhật ký truy cập (phục vụ Non-repudiation, Mục 2.4.2) — mô phỏng bằng cách trả kèm log
    return {
        "unlocked": True,
        "reason": "all_phases_passed",
        "time": time.perf_counter() - t0,
        "access_log": {"device": central.id, "time": time.time(), "nonce": N_A.hex()},
    }
