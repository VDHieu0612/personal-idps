# 🛡️ AegisGuard Personal IDS/IPS System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=flat)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**AegisGuard** is a lightweight, cross-platform personal **Network Intrusion Detection System (IDS) & Intrusion Prevention System (IPS)** with a real-time glassmorphic security dashboard. Built specifically for local machines (Windows, Linux, macOS), it offers real-time packet inspection, customizable YAML detection rules, threat intelligence lookup, and active IP blocklists.

---

## 🌟 Key Features

- **⚡ Dual-Engine Ingestion**: 
  - **Engine A (Zero-Driver)**: Socket & Web Connection Inspector using `psutil` (requires zero drivers, runs seamlessly for non-admin users).
  - **Engine B (Kernel Sniffer)**: Deep packet capture using `Scapy` + `Npcap/libpcap` for raw frame decodes and deep payload analysis.
- **📏 Flexible Rule Engine**: Define detection policies in human-readable YAML with sliding-window threshold evaluation (Port Scans, SSH/RDP Brute Force, ICMP Floods, Suspicious Ports, DNS Anomalies).
- **📥 Emerging Threats (ET Open) Online Store**: Direct category streaming from official `rules.emergingthreats.net` repository (50,000+ rules available: Reconnaissance, DoS, CVE Exploits, Web Shells, Malware).
- **📝 Multi-Tier Persistence & SIEM Logging**:
  - **SQLite Database (`ids_storage.db`)**: Ultra-fast local store for real-time Dashboard queries.
  - **Suricata EVE JSON (`logs/eve.json`)**: Industry-standard EVE JSON format for direct ingestion into **Wazuh, Splunk, Filebeat, ELK**.
  - **Snort Fast Log (`logs/fast.log`)**: Human-readable one-line alerts for instant Notepad or terminal inspection.
- **🎨 Glassmorphic React Dashboard**: Pre-built static bundle served directly by FastAPI. Zero Node.js setup required for end-users!
- **🌐 Bilingual UI (English & Tiếng Việt)**: Instant one-click language toggle between English and Vietnamese with persisted local settings.
- **🌐 Threat Intelligence Integration**: Integrated IP reputation checking (AbuseIPDB/Feodo indicators) for real-time risk scoring.
- **🚫 Active IPS Blocking**: One-click manual or rule-automated IP blocking in local firewall tables (`netsh advfirewall`).
- **🛡️ Mapped to MITRE ATT&CK**: Alerts are categorized with MITRE ATT&CK techniques (T1046, T1110, T1071, T1498, etc.) for SOC visibility.

---

## 🏗️ Kiến Trúc Hệ Thống (System Architecture)

<div align="center">
  <img src="docs/images/architecture_workflow.jpg" alt="AegisGuard Architecture & Workflow Infographic" width="100%" />
  <p><em>Hình 1: Sơ đồ kiến trúc tổng quan & luồng xử lý phân tích bảo mật đa tầng của AegisGuard</em></p>
</div>

AegisGuard được thiết kế theo mô hình **Đa tầng (Multi-tier Architecture)** với cơ chế **Dual-Engine Ingestion**, tách biệt rõ ràng giữa tầng thu thập mạng, tầng phân tích chữ ký, tầng lưu trữ chuẩn SIEM và giao diện điều khiển.

```mermaid
flowchart TD
    subgraph Traffic["🌐 Tầng Mạng & Ứng Dụng (Network & Traffic Layer)"]
        RawPackets["Gói tin mạng vật lý (Ethernet / Wi-Fi)"]
        LocalApps["Ứng dụng cục bộ (Browser, Tor, Python, Services)"]
    end

    subgraph DualCapture["⚡ Tầng Thu Thập Kép (Dual-Engine Ingestion)"]
        EngineB["Engine B: Deep Kernel Packet Sniffer\n(Scapy + Npcap / libpcap)"]
        EngineA["Engine A: Socket & Web Connection Inspector\n(psutil Zero-Driver / Zero-Privilege)"]
    end

    subgraph AnalysisEngine["🧠 Tầng Phân Tích & Đối Soát (Detection Engine)"]
        SlidingWindow["Sliding-Window State Tracker\n(Theo dõi tần suất & Sliding Buffer)"]
        RuleMatcher["YAML Rule Evaluator\n(Match Port, Rate, Protocol, Signature)"]
        MITREMapper["MITRE ATT&CK Matrix Tagging\n(T1046, T1110, T1071, T1498...)"]
        ETStore["Kho Luật Trực Tuyến ET Open\n(rules.emergingthreats.net 50.000+ rules)"]
        ThreatIntel["Threat Intelligence Inspector\n(Tra cứu uy tín AbuseIPDB / Feodo)"]
    end

    subgraph StorageLayer["💾 Tầng Lưu Trữ Chuẩn Hóa (Persistence & SIEM Logging)"]
        SQLiteDB[("SQLite Database\n(ids_storage.db)")]
        EVELog["Suricata EVE JSON\n(logs/eve.json)"]
        FastLog["Snort Fast Alert Log\n(logs/fast.log)"]
    end

    subgraph PresentationAction["🛡️ Tầng Phản Ứng & Điều Khiển (IPS & Dashboard)"]
        IPSEnforce["Tường Lửa Chủ Động (IPS)\n(netsh advfirewall / Local Blocklist)"]
        FastAPIServer["FastAPI Backend Server\n(REST API & Static Asset Server :8000)"]
        ReactUI["Glassmorphic React Security Dashboard\n(Song ngữ VI / EN - Zero Node.js Required)"]
    end

    %% Connections
    RawPackets --> EngineB
    LocalApps --> EngineA
    EngineA --> SlidingWindow
    EngineB --> SlidingWindow

    ETStore -.->|"Nạp danh mục theo yêu cầu"| RuleMatcher
    SlidingWindow --> RuleMatcher
    RuleMatcher --> MITREMapper
    ThreatIntel -.->|"Tra cứu IP độc hại"| RuleMatcher

    RuleMatcher -->|"Ghi nhận metadata"| SQLiteDB
    RuleMatcher -->|"Ghi log chuẩn SIEM"| EVELog
    RuleMatcher -->|"Ghi log 1 dòng dễ đọc"| FastLog

    RuleMatcher -->|"Kích hoạt Rule Critical / Tự động chặn"| IPSEnforce
    SQLiteDB <--> FastAPIServer
    IPSEnforce <--> FastAPIServer
    FastAPIServer <--> ReactUI
```

---

### 🗺️ Bản Đồ Quan Hệ Module (CodeBoarding Component Dependency Map)

Kiến trúc các module được phân rã và chuẩn hóa theo tiêu chuẩn **[CodeBoarding](https://github.com/CodeBoarding/CodeBoarding)** (Static Code Analysis & Architectural Dependency Extraction). Tệp phân tích kiến trúc đã được tạo tại [`.codeboarding/analysis.json`](.codeboarding/analysis.json):

```mermaid
graph LR
    Adversary_Simulator["Adversary Attack Simulator\n(test_attacks.py)"]
    Dual_Ingestion["Dual Ingestion Engine\n(engine/capture.py)"]
    Rule_Detector["Rule & Detection Engine\n(engine/detector.py)"]
    Suricata_Importer["Suricata & ET Open Importer\n(engine/suricata_importer.py)"]
    Persistence_Layer["Persistence & SIEM Streaming\n(engine/db.py)"]
    Firewall_IPS["Firewall IPS & Threat Intel\n(engine/main.py, engine/db.py)"]
    FastAPI_Core["FastAPI Gateway & Runtime Core\n(engine/main.py, run.py)"]
    SOC_Dashboard["Glassmorphic SOC Dashboard\n(dashboard/src/)"]

    Adversary_Simulator -- "injects simulated network attack vectors" --> Dual_Ingestion
    Dual_Ingestion -- "dispatches normalized packet events & connection tuples" --> Rule_Detector
    Suricata_Importer -- "generates YAML signatures & triggers engine reload" --> Rule_Detector
    Rule_Detector -- "records packet metadata, alerts, and EVE streams" --> Persistence_Layer
    Rule_Detector -- "triggers automated IP block on critical alert" --> Firewall_IPS
    Firewall_IPS -- "persists active blocked IP registry" --> Persistence_Layer
    FastAPI_Core -- "queries stats, recent alerts, and packet logs" --> Persistence_Layer
    FastAPI_Core -- "executes rule toggle, bulk actions, and custom saves" --> Rule_Detector
    FastAPI_Core -- "requests category downloads from rules.emergingthreats.net" --> Suricata_Importer
    FastAPI_Core -- "invokes netsh firewall commands & Threat Intel checks" --> Firewall_IPS
    SOC_Dashboard -- "polls REST endpoints for real-time state synchronization" --> FastAPI_Core
```

---

## 🔄 Luồng Hoạt Động Tuần Tự (Operational Workflow)

Dưới đây là chu trình xử lý tuần tự từ lúc một gói tin hoặc luồng tấn công chạm vào máy tính cho đến khi hệ thống phân tích, lưu log chuẩn SIEM và chủ động thực thi chặn (IPS):

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Kẻ tấn công / Mạng ngoài
    participant NetCard as Card Mạng / OS Sockets
    participant DualEngine as Dual Capture Engine (A/B)
    participant Detector as Rule Engine & MITRE Mapper
    participant Storage as Lưu Trữ (SQLite + EVE Logs)
    participant IPS as Tường Lửa IPS (Firewall)
    participant API as FastAPI (:8000)
    actor SOCAdmin as Người dùng / SOC Dashboard

    Note over Attacker,NetCard: 1. Phát sinh lưu lượng mạng (Scan, DoS, C2, Phishing)
    Attacker->>NetCard: Gửi gói tin mạng (TCP SYN / UDP Flood / C2 Probe)
    
    NetCard->>DualEngine: Bắt gói tin (Kernel Scapy hoặc Socket Inspector)
    DualEngine->>Detector: inspect_packet(src_ip, dst_ip, port, proto, payload)
    
    critical Phân tích chữ ký & Sliding-Window
        Detector->>Detector: Kiểm tra ngưỡng cửa sổ trượt (Sliding-window threshold)
        Detector->>Detector: Khớp chữ ký YAML & Quy tắc Suricata/ET Open
        Detector->>Detector: Gán nhãn chiến thuật MITRE ATT&CK
    end

    alt Phát hiện hành vi tấn công (Threat Detected)
        Detector->>Storage: 1. Ghi nhận cảnh báo vào SQLite (ids_storage.db)
        Detector->>Storage: 2. Stream log chuẩn Suricata EVE JSON (logs/eve.json)
        Detector->>Storage: 3. Ghi dòng cảnh báo tức thì vào Snort Fast Log (logs/fast.log)
        
        opt Mức độ Critical hoặc Rule có cấu hình block_ip = true
            Detector->>IPS: Kích hoạt chặn địa chỉ IP (Block IP Action)
            IPS->>NetCard: Thực thi chặn thông qua Windows Firewall / netsh
        end
    else Gói tin bình thường (Benign Traffic)
        Detector->>Storage: Ghi nhận thống kê tóm tắt lưu lượng (packet_logs)
    end

    Note over API,SOCAdmin: 2. Giám sát & Quản trị Thời gian thực
    SOCAdmin->>API: Truy vấn dữ liệu thống kê & cảnh báo định kỳ
    API->>Storage: Query SQLite (Alerts, Packet Stats, Blocked IPs)
    Storage-->>API: Trả về dữ liệu JSON
    API-->>SOCAdmin: Render giao diện Glassmorphic, cập nhật biểu đồ & bảng cảnh báo

    opt Người dùng tra cứu hoặc can thiệp thủ công
        SOCAdmin->>API: Tra cứu Threat Intel cho IP đáng ngờ
        API-->>SOCAdmin: Hiển thị Abuse Score, Quốc gia, ISP, Domain
        SOCAdmin->>API: Nhấn "Chặn IP" hoặc "Tải thêm danh mục ET Open"
        API->>IPS: Cập nhật danh sách chặn ngay lập tức
    end
```

---

## 🛠️ Hướng Dẫn Cài Đặt & Build (Build & Setup Guide)

Hệ thống hỗ trợ 2 chế độ triển khai: **Chạy ngay lập tức (Không cần Node.js)** hoặc **Tự build từ Source Code (Dành cho Developer)**.

### Cách 1: Chạy ngay không cần Node.js (Khuyên dùng)
Giao diện React Dashboard đã được build sẵn thành các static assets tối ưu trong thư mục `dashboard/dist/`. FastAPI sẽ tự động mount và phân phối bundle này.

```bash
# 1. Clone repository
git clone https://github.com/VDHieu0612/personal-idps.git
cd personal-idps

# 2. Cài đặt các thư viện Python cần thiết
pip install -r requirements.txt

# 3. Khởi chạy AegisGuard Engine & Dashboard
# (Trên Windows: Khuyên dùng Command Prompt / PowerShell quyền Administrator để kích hoạt Engine B)
# (Trên Linux/macOS: Chạy với quyền sudo)
python run.py
```
👉 Mở trình duyệt web và truy cập: **`http://localhost:8000`**

---

### Cách 2: Tự Build Frontend từ Source Code (Developer Mode)
Nếu bạn muốn chỉnh sửa giao diện React hoặc thêm component mới:

```bash
# 1. Di chuyển vào thư mục dashboard
cd dashboard

# 2. Cài đặt các dependencies
npm install

# 3. Chạy môi trường phát triển (Hot reload)
npm run dev

# 4. Khi hoàn tất, build lại bundle tĩnh vào dashboard/dist/
npm run build
```

---

## ⚙️ Hướng Dẫn Quản Trị Rules (Thêm, Xóa, Sửa, Bật/Tắt)

AegisGuard cho phép bạn quản lý chữ ký phát hiện qua **Giao diện Trực quan (Dashboard)** hoặc **Thao tác File Trực tiếp (YAML)**.

### 1. Thao tác trên Giao Diện Dashboard (Tab: Rule Catalog)
* **Bật / Tắt Rule (Toggle):**
  * Nhấp trực tiếp vào Checkbox bên cạnh mỗi Rule để kích hoạt hoặc tạm dừng.
  * Sử dụng nút **"Bật tất cả" (Enable All)** hoặc **"Tắt tất cả" (Disable All)** để áp dụng hàng loạt theo danh mục đang chọn.
* **Tạo Rule Mới bằng Trình Tạo Trực Quan (Rule Wizard):**
  1. Nhấn nút xanh **"Tạo luật tùy chỉnh" (Add Custom Rule)**.
  2. Điền thông tin:
     * **Tên quy tắc & Mô tả**: Ví dụ `Detect Custom Web Shell`.
     * **Danh mục & Mức độ**: `web_security`, `critical/high/medium/low`.
     * **Mô hình phát hiện (Pattern)**:
       * *Port Match*: Bắt lưu lượng trên các cổng cụ thể (ví dụ: `8080, 8443, 4444`).
       * *Single Target Connection Rate*: Phát hiện brute-force nếu số kết nối đến 1 cổng vượt quá ngưỡng trong khoảng thời gian (ví dụ: 10 lần trong 5 giây).
       * *Port Scan Threshold*: Phát hiện quét cổng nếu quét qua nhiều cổng khác nhau.
     * **Mã MITRE ATT&CK**: Gán mã tương ứng (ví dụ: `T1059`, `T1046`).
  3. Bấm **"Lưu & Kích hoạt quy tắc"** -> Hệ thống tạo file `.yml` và nạp vào Engine ngay lập tức.
* **Nạp Kho Luật Trực Tuyến Emerging Threats (ET Open):**
  1. Nhấn nút tím **"Nhập luật Suricata (.rules)"**.
  2. Tại mục *Chọn danh mục Emerging Threats*, chọn danh mục bạn muốn (Scan, DoS, CVE Exploits, Web Server, Worm, FTP...).
  3. Chọn số lượng rule muốn nạp (ví dụ 50 hoặc 100).
  4. Bấm **"Tải danh mục từ máy chủ ET Open"** -> Hệ thống tự động tải từ `rules.emergingthreats.net`, parse và đưa vào danh sách kiểm soát.

### 2. Thao tác Trực tiếp qua Tệp Cấu Hình YAML (`engine/rules/`)
Tất cả các rules được lưu dưới dạng file `.yml` trong thư mục `engine/rules/`.

* **Cấu trúc một file Rule mẫu (`engine/rules/custom_ssh_brute.yml`):**
```yaml
id: custom-ssh-brute
name: Potential SSH Brute Force Attack
description: Flags repeated connection attempts to SSH port 22.
severity: high
category: credential_access
enabled: true

condition:
  type: single_target_rate
  target_port: 22
  threshold_count: 5
  window_seconds: 10
  group_by: src_ip

action:
  alert: true
  block_ip: false

mitre_attack: T1110
tags:
  - ssh
  - brute_force
```

* **Thêm rule**: Tạo file mới có đuôi `.yml` trong `engine/rules/`.
* **Sửa rule**: Mở file `.yml` tương ứng, chỉnh sửa thông số cổng, ngưỡng hoặc hành động và lưu lại.
* **Xóa rule**: Xóa file `.yml` khỏi thư mục `engine/rules/`.
* *Lưu ý*: Engine tự động load lại danh sách rule khi bạn khởi động lại hoặc gọi API `/api/rules/toggle`.

---

## 📜 Hướng Dẫn Thao Tác Với Logs & Tích Hợp SIEM

AegisGuard thiết kế cơ chế lưu trữ phân tầng giúp bạn dễ dàng theo dõi trên máy cá nhân hoặc đẩy về hệ thống SOC tập trung.

### 1. Giám Sát Log Trực Tiếp Trên Web Dashboard
* **Trang Packets Stream**: Xem luồng gói tin và kết nối theo thời gian thực (TCP, UDP, ICMP, DNS, HTTP/HTTPS), hỗ trợ tìm kiếm theo IP và cổng.
* **Trang Recent Alerts**: Bảng tổng hợp các sự kiện vi phạm an ninh, nhãn mức độ nghiêm trọng, mã MITRE ATT&CK và nút **"Inspect IP"** tra cứu độ nguy hiểm (AbuseIPDB Score).
* **Trang IPS Blocklist**: Quản lý danh sách các IP đang bị chặn, xem lý do chặn và hỗ trợ gỡ chặn (Unblock) tức thì.

### 2. Truy Vấn Cơ Sở Dữ Liệu SQLite (`ids_storage.db`)
Cơ sở dữ liệu SQLite nằm tại thư mục gốc của dự án, lưu trữ toàn bộ dữ liệu có cấu trúc:
* Bảng `alerts`: Chi tiết các cuộc tấn công và vi phạm rule.
* Bảng `packet_logs`: Metadata của các gói tin mạng quét qua máy.
* Bảng `blocked_ips`: Danh sách các IP bị đưa vào tường lửa chặn.

**Ví dụ lệnh truy vấn nhanh qua CLI:**
```bash
# Xem 10 cảnh báo mới nhất
sqlite3 ids_storage.db "SELECT datetime(timestamp, 'unixepoch'), rule_name, severity, src_ip, dst_port FROM alerts ORDER BY timestamp DESC LIMIT 10;"

# Xem các IP bị phát hiện tấn công nhiều nhất
sqlite3 ids_storage.db "SELECT src_ip, COUNT(*) as attack_count FROM alerts GROUP BY src_ip ORDER BY attack_count DESC LIMIT 5;"

# Xem danh sách IP đang bị chặn trong Firewall
sqlite3 ids_storage.db "SELECT ip, reason, datetime(blocked_at, 'unixepoch') FROM blocked_ips;"
```

### 3. Tích Hợp SIEM qua Chuẩn Suricata EVE JSON (`logs/eve.json`)
Mỗi khi có cảnh báo xuất hiện, hệ thống đồng thời ghi một dòng JSON chuẩn công nghiệp vào tệp:
👉 `logs/eve.json`

```json
{"timestamp": "2026-10-02T15:28:45.000Z", "event_type": "alert", "src_ip": "185.220.101.5", "src_port": 54321, "dest_ip": "192.168.1.10", "dest_port": 22, "proto": "TCP", "alert": {"action": "alert", "signature_id": "rule-002", "signature": "SSH Brute Force Attempt", "category": "credential_access", "severity": "high", "mitre_attack": "T1110"}}
```

**Cách tích hợp với Wazuh Agent:**
Thêm đoạn sau vào file cấu hình `ossec.conf` của Wazuh Agent:
```xml
<localfile>
  <log_format>suricata</log_format>
  <location>D:\ĐACN\personal-ids\logs\eve.json</location>
</localfile>
```

### 4. Theo Dõi Nhanh Bằng Snort Fast Log (`logs/fast.log`)
Tệp log văn bản ngắn gọn, 1 dòng cho mỗi sự kiện:
👉 `logs/fast.log`

```text
10/02/2026-15:28:45  [**] [rule-002] SSH Brute Force Attempt [**] [Category: credential_access] [Priority: high] {TCP} 185.220.101.5:54321 -> 192.168.1.10:22
```

**Cách theo dõi trực tiếp trên PowerShell (tương tự `tail -f` trên Linux):**
```powershell
Get-Content logs/fast.log -Wait -Tail 20
```

---

## 🧪 Quick Attack Testing (Demo trong 5s)

Để kiểm chứng khả năng phát hiện của IDS/IPS và xem các biểu đồ trên Dashboard phản hồi tức thì, mở một terminal thứ 2 và chạy:

```bash
# Chạy toàn bộ kịch bản tấn công mẫu (Port Scan, SSH/RDP Brute Force, DoS, C2, DNS Tunneling)
python test_attacks.py --all

# Hoặc mở menu tương tác để chọn từng bài test:
python test_attacks.py
```

---

## 💡 Engineering Design Rationale (Why Signature + Threat Intel vs Flow ML)

Nhiều nghiên cứu học thuật về IDS thường sử dụng các bộ dữ liệu như **CICIDS2017** và phụ thuộc vào công cụ trích xuất **CICFlowMeter** (tính toán hơn 80 thuộc tính thống kê 2 chiều sau khi một luồng mạng đã kết thúc).

Trong môi trường triển khai thực tế trên máy tính cá nhân, việc chờ đợi kết thúc luồng (flow completion) gây ra độ trễ phát hiện rất lớn và tiêu tốn nhiều RAM/CPU. **AegisGuard** giải quyết triệt để vấn đề này bằng cách kết hợp:
1. **Phân tích theo gói tin và cửa sổ trượt thời gian thực (Sliding-window statistics)**: Phát hiện ngay khi tần suất vượt ngưỡng mà không cần đợi flow kết thúc.
2. **Bộ chữ ký luật (Rule Signatures)**: Tương thích Suricata & ET Open giúp phát hiện chính xác với độ trễ gần bằng 0.
3. **Cơ chế Threat Intelligence Feeds**: Kiểm tra danh tiếng IP độc hại (AbuseIPDB/Feodo) ngay tại thời điểm kết nối.

---

## 📜 License

Phát hành dưới giấy phép [MIT License](LICENSE).
