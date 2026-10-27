# Mô phỏng phần mềm giao thức xác thực BLE — Mục 3.4

Bộ mã nguồn này hiện thực hóa đúng Mục 3.4 (Kế hoạch mô phỏng phần mềm)
của Chương 3: cài đặt bằng Python, không dùng bất kỳ thiết bị phần cứng
vật lý nào, đúng phạm vi đã cam kết ở Mục A.5.

## 1. Cài đặt

Chỉ cần một thư viện ngoài duy nhất:

```bash
pip install cryptography
```

## 2. Cấu trúc file

| File | Vai trò | Tương ứng mục trong khóa luận |
|---|---|---|
| `crypto_utils.py` | Hàm ECDH, ký số ECDSA, HMAC-SHA256 | Mục 1.3 |
| `ca.py` | Máy chủ quản lý S cấp chứng chỉ | Mục 3.3.1 (Pha 1) |
| `device.py` | Lớp Central (App) / Peripheral (Khóa) | Mục 3.3 |
| `protocol.py` | Cài đặt `run_baseline()` (Just Works) và `run_proposed()` (4 pha) | Mục 2.3.1, Mục 3.3.1–3.3.4 |
| `attackers.py` | 3 kịch bản tấn công: MITM, BLESA reconnect spoof, Replay | Bảng 3.2 |
| `run_experiment.py` | Chạy 30 lần lặp × 3 kịch bản × 2 chế độ, xuất CSV | Mục 3.4 |
| `energy_model.py` | Ước tính năng lượng theo mô hình lý thuyết | Mục 3.4 |
| `test_legit.py` | Kiểm tra người dùng hợp lệ không bị chặn nhầm | Kiểm tra vệ sinh |

## 3. Chạy thí nghiệm chính

```bash
python3 run_experiment.py
```

Kết quả in ra màn hình dạng bảng (tỷ lệ chặn tấn công + thời gian thực
thi trung bình mỗi kịch bản/chế độ), đồng thời lưu chi tiết từng lần
chạy vào `simulation_results.csv` — đây chính là bộ số liệu thô dùng
để viết Mục 3.4 và Mục 3.5 (Tiêu chí đánh giá) trong bản khóa luận
chính thức.

## 4. Kiểm tra vệ sinh (không bắt buộc nhưng nên chạy)

```bash
python3 test_legit.py
```

Xác nhận người dùng hợp lệ (không có tấn công) luôn mở khóa thành
công 100% — chứng minh giao thức không gây ra tình trạng từ chối nhầm
(false positive), một tiêu chí quan trọng khi trình bày kết quả với
GVHD.

## 5. Ước tính năng lượng

```bash
python3 energy_model.py
```

**Quan trọng:** các con số trong `ENERGY_PER_OP_UJ` (đầu file
`energy_model.py`) hiện là số liệu **minh họa**, chưa phải số liệu đã
được trích dẫn nguồn chính thức. Trước khi đưa vào bản khóa luận nộp
chính thức, cần thay các con số này bằng dữ liệu tra được từ:
- Datasheet Nordic nRF52832, hoặc
- Một bài báo đã công bố có đo đạc benchmark ECC/HMAC trên lõi
  Cortex-M4F, kèm trích dẫn đầy đủ theo đúng chuẩn đã dùng ở Mục D
  (Tài liệu tham khảo).

## 6. Kết quả mẫu

```
MITM                   | baseline  | chặn  0/30 (  0.0%) | ...
MITM                   | proposed  | chặn 30/30 (100.0%) | ...
BLESA_reconnect_spoof  | baseline  | chặn  0/30 (  0.0%) | ...
BLESA_reconnect_spoof  | proposed  | chặn 30/30 (100.0%) | ...
Replay                 | baseline  | chặn  0/30 (  0.0%) | ...
Replay                 | proposed  | chặn 30/30 (100.0%) | ...
```


