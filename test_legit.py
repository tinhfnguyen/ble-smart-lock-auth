"""
test_legit.py — Kiểm tra vệ sinh (sanity check): khi KHÔNG có kẻ tấn
công can thiệp, người dùng hợp lệ phải luôn mở khóa được — tránh
trường hợp giao thức chặn nhầm cả người dùng chính chủ (false positive).
"""
from ca import CA
from device import Device
import protocol as proto

N = 30
success = 0
for _ in range(N):
    ca = CA()
    central = Device("APP_CENTRAL", ca)
    peripheral = Device("SMART_LOCK", ca)
    result = proto.run_proposed(central, peripheral, attacker=None)
    if result["unlocked"]:
        success += 1
    else:
        print("LỖI — người dùng hợp lệ bị từ chối:", result["reason"])

print(f"Người dùng hợp lệ mở khóa thành công: {success}/{N} lần "
      f"({success/N*100:.1f}%)")
