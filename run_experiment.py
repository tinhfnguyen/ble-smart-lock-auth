"""
run_experiment.py — Script chính thực hiện Mục 3.4: chạy 3 kịch bản
tấn công (MITM, BLESA reconnect spoof, Replay), mỗi kịch bản lặp lại
N_TRIALS lần trên baseline (Just Works) và trên giao thức đề xuất,
đo thời gian thực thi, ghi kết quả ra CSV và in bảng tổng hợp.

Cách chạy:
    python3 run_experiment.py
"""
import csv
import statistics

from ca import CA
from device import Device
import protocol as proto
from attackers import MITMAttacker, BLESAAttacker, ReplayAttacker

N_TRIALS = 30


def fresh_pair():
    """Mỗi lần thử lại tạo cặp thiết bị mới với CA mới — mô phỏng đúng
    một phiên độc lập, tránh trạng thái (nonce đã dùng...) rò rỉ giữa
    các lần lặp."""
    ca = CA()
    central = Device("APP_CENTRAL", ca)
    peripheral = Device("SMART_LOCK", ca)
    return central, peripheral


def run_scenario(scenario_name, attacker_factory, n_trials=N_TRIALS):
    rows = []
    for mode, runner in (("baseline", proto.run_baseline), ("proposed", proto.run_proposed)):
        blocked = 0
        times_ms = []
        for i in range(n_trials):
            central, peripheral = fresh_pair()
            attacker = attacker_factory()  # tạo mới mỗi lần để tránh trạng thái tồn dư (ví dụ Replay)
            result = runner(central, peripheral, attacker=attacker)
            times_ms.append(result["time"] * 1000.0)
            if not result["unlocked"]:
                blocked += 1
            rows.append([scenario_name, mode, i + 1, result["unlocked"], result["reason"], round(result["time"] * 1000.0, 4)])

        block_rate = blocked / n_trials * 100
        avg_time = statistics.mean(times_ms)
        std_time = statistics.pstdev(times_ms)
        print(f"{scenario_name:22s} | {mode:9s} | chặn {blocked:2d}/{n_trials} ({block_rate:5.1f}%) "
              f"| thời gian TB {avg_time:7.4f} ms (độ lệch chuẩn {std_time:.4f})")
    return rows


def main():
    scenarios = [
        ("MITM", MITMAttacker),
        ("BLESA_reconnect_spoof", BLESAAttacker),
        ("Replay", ReplayAttacker),
    ]

    all_rows = []
    print("=" * 100)
    print(f"KẾT QUẢ MÔ PHỎNG — {N_TRIALS} lần lặp / kịch bản / chế độ")
    print("=" * 100)
    for name, factory in scenarios:
        all_rows.extend(run_scenario(name, factory))
        print("-" * 100)

    out_path = "simulation_results.csv"
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "mode", "trial", "unlocked", "reason", "time_ms"])
        w.writerows(all_rows)
    print(f"\nĐã lưu {len(all_rows)} dòng kết quả chi tiết vào {out_path}")


if __name__ == "__main__":
    main()
