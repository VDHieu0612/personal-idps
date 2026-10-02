export type Language = 'en' | 'vi';

export const translations = {
  en: {
    brandSubtitle: "Personal Network Protection & Security Operations",
    versionBadge: "v1.0 IDS/IPS",
    langToggle: "Tiếng Việt",
    
    // Tabs
    tabs: {
      dashboard: "Dashboard",
      logs: "Traffic & Alerts",
      rules: "Rules",
      blocked: "Blocked IPs",
    },
    
    // Engine status
    status: {
      mode: "Mode",
      active: "ACTIVE",
    },
    
    // Stats cards
    stats: {
      totalPackets: "Total Packets Monitored",
      totalPacketsSub: "Real-time network traffic",
      alerts24h: "Security Alerts (24h)",
      alertsTotalSub: "Total accumulated",
      activeRules: "Active Detection Rules",
      activeRulesSub: "Engine Rulesets active",
      blockedIps: "Blocked Threat IPs",
      blockedIpsSub: "Firewall Enforcement",
    },
    
    // Dashboard sections
    dashboard: {
      severityDist: "Alert Severity Distribution",
      liveSync: "Live Sync",
      topSources: "Top Threat Source IPs",
      abuseCounter: "Abuse Counter",
      protocols: "Monitored Protocols",
      networkLayer: "Network Layer",
      recentAlerts: "Real-Time Security Alerts",
      autoRefresh: "Auto-Refreshing (Polling 2s)",
      noAlerts: "No security alerts triggered yet. Sniffing traffic...",
      noThreatSources: "No threat sources recorded yet.",
      listeningProtocols: "Listening for network protocols...",
      alertsCount: "alerts",
      pktsCount: "pkts",
    },
    
    // Tables
    table: {
      time: "Time",
      timestamp: "Timestamp",
      severity: "Severity",
      ruleName: "Rule Name",
      ruleIdName: "Rule ID & Name",
      srcIp: "Source IP",
      srcIpPort: "Source IP:Port",
      dstIp: "Destination IP",
      dstIpPort: "Dest IP:Port",
      protocol: "Protocol",
      mitre: "MITRE ID",
      details: "Details",
      length: "Length (Bytes)",
      info: "Info / Payload Preview",
      actions: "Actions",
    },
    
    // Logs page
    logs: {
      subTabAlerts: "Security Alerts",
      subTabPackets: "Raw Packets",
      allSeverities: "All Severities",
      searchPlaceholder: "Search IP, Rule, Protocol...",
      noAlertsMatch: "No matching security alerts found.",
      noPacketsMatch: "No packet logs captured matching filter.",
    },
    
    // Rules page
    rules: {
      title: "Rule Catalog & Checkbox Management",
      subtitle: "Suricata-style rule preset store. Simply tick checkboxes to enable or disable signatures in real-time.",
      activeRatio: "Rules Active",
      enableAll: "Enable All",
      disableAll: "Disable All",
      addCustomRule: "Add Custom Rule",
      importSuricata: "Import Suricata (.rules)",
      suricataModal: {
        title: "Suricata & Snort Rules Importer",
        desc: "Convert standard single-line Suricata/Snort rules or download official Emerging Threats (ET Open) category rulesets (50,000+ rules available) directly into the engine.",
        categoryLabel: "Select Official ET Open Category:",
        fetchCategoryBtn: "Fetch Category from ET Open",
        fetchingCategory: "Fetching from Repository...",
        fetchLimit: "Limit rules:",
        orPasteManually: "Or Paste Custom Suricata Rules Manually (.rules):",
        placeholder: "Paste Suricata rules here (e.g. alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:\"...\"; sid:2001219;))",
        loadSample: "Load Offline 10-Rule Sample",
        importBtn: "Convert & Import to Engine",
        importing: "Importing...",
        successMsg: "Successfully imported rules into the engine!",
        close: "Close"
      },
      categories: {
        all: "All Categories",
        web_phishing: "Web & Phishing",
        credential_access: "Brute Force & Auth",
        reconnaissance: "Recon & Scans",
        command_and_control: "C2 & Botnets",
        denial_of_service: "DoS & Floods",
        exfiltration: "DNS & Exfiltration",
      },
      wizard: {
        title: "Visual Rule Creator Wizard",
        close: "Close",
        ruleTitle: "Rule Title",
        ruleTitlePlaceholder: "e.g. Detect Custom Web Shell",
        desc: "Description",
        descPlaceholder: "e.g. Flags suspicious web traffic targeting admin ports",
        category: "Category",
        severity: "Severity",
        pattern: "Detection Trigger Pattern",
        patternPortMatch: "Port Match (Flags specific ports e.g. 8080, 4444)",
        patternSingleRate: "Single Target Connection Rate (Brute Force threshold)",
        patternThreshold: "Port Scan Probe Threshold (Distinct ports scan)",
        targetPorts: "Target Port(s)",
        thresholdCount: "Threshold Count",
        windowSeconds: "Window (Seconds)",
        mitreCode: "MITRE ATT&CK Code",
        cancel: "Cancel",
        save: "Save & Activate Rule",
      },
    },
    
    // Blocked IPs page
    blocked: {
      title: "IPS Active Blocklist & Firewall Enforcement",
      subtitle: "Prevent connection attempts from malicious actors by adding target IPs to the local blocklist.",
      ipPlaceholder: "IP Address (e.g. 185.220.101.5)",
      reasonPlaceholder: "Reason",
      btnBlock: "Block IP",
      tableTitle: "Active Blocked IP Register",
      reasonHeader: "Reason",
      blockedAtHeader: "Blocked Timestamp",
      noBlocked: "No active blocked IP addresses. Your personal firewall is clear.",
      btnUnblock: "Unblock",
      defaultReason: "Manual Administrative Block",
    },
    
    // Threat intel modal
    threatModal: {
      title: "Threat Intelligence Inspector",
      targetIp: "Target IP Address",
      statusBlocked: "BLOCKED IN IPS",
      statusAllowed: "ALLOWED",
      querying: "Querying Threat Intelligence Feeds...",
      abuseScore: "Abuse Confidence Score",
      country: "Origin Country",
      usageType: "Usage Type",
      domain: "Domain Hostname",
      notFound: "No threat intel record found for this IP.",
      btnUnblock: "Unblock IP Address",
      btnBlock: "Block IP in Personal IPS Firewall",
      blockedReason: "Blocked from Threat Intel Inspector",
    },
    
    // Footer
    footer: "AegisGuard Personal IDS/IPS & Security Operations Engine © 2026. All rights reserved.",
  },
  
  vi: {
    brandSubtitle: "Hệ thống bảo vệ mạng cá nhân & Giám sát an toàn thông tin (SOC)",
    versionBadge: "v1.0 IDS/IPS",
    langToggle: "English",
    
    // Tabs
    tabs: {
      dashboard: "Tổng quan",
      logs: "Lưu lượng & Cảnh báo",
      rules: "Bộ quy tắc",
      blocked: "Danh sách chặn",
    },
    
    // Engine status
    status: {
      mode: "Chế độ",
      active: "HOẠT ĐỘNG",
    },
    
    // Stats cards
    stats: {
      totalPackets: "Tổng gói tin giám sát",
      totalPacketsSub: "Lưu lượng mạng thời gian thực",
      alerts24h: "Cảnh báo bảo mật (24h)",
      alertsTotalSub: "Tổng tích lũy",
      activeRules: "Quy tắc đang bật",
      activeRulesSub: "Tập luật đang kích hoạt",
      blockedIps: "IP đe dọa đã chặn",
      blockedIpsSub: "Thực thi bởi tường lửa",
    },
    
    // Dashboard sections
    dashboard: {
      severityDist: "Phân bổ mức độ nghiêm trọng",
      liveSync: "Đồng bộ trực tiếp",
      topSources: "Nguồn IP tấn công hàng đầu",
      abuseCounter: "Số lần vi phạm",
      protocols: "Giao thức mạng giám sát",
      networkLayer: "Tầng mạng",
      recentAlerts: "Cảnh báo bảo mật thời gian thực",
      autoRefresh: "Tự động làm mới (Chu kỳ 2s)",
      noAlerts: "Chưa ghi nhận cảnh báo bảo mật nào. Đang bắt gói tin...",
      noThreatSources: "Chưa ghi nhận IP nguồn độc hại nào.",
      listeningProtocols: "Đang lắng nghe các giao thức mạng...",
      alertsCount: "cảnh báo",
      pktsCount: "gói",
    },
    
    // Tables
    table: {
      time: "Thời gian",
      timestamp: "Mốc thời gian",
      severity: "Mức độ",
      ruleName: "Tên quy tắc",
      ruleIdName: "Mã & Tên quy tắc",
      srcIp: "IP Nguồn",
      srcIpPort: "IP Nguồn:Cổng",
      dstIp: "IP Đích",
      dstIpPort: "IP Đích:Cổng",
      protocol: "Giao thức",
      mitre: "Mã MITRE",
      details: "Chi tiết",
      length: "Kích thước (Bytes)",
      info: "Thông tin / Dữ liệu gói tin",
      actions: "Thao tác",
    },
    
    // Logs page
    logs: {
      subTabAlerts: "Cảnh báo bảo mật",
      subTabPackets: "Gói tin thô",
      allSeverities: "Tất cả mức độ",
      searchPlaceholder: "Tìm IP, Quy tắc, Giao thức...",
      noAlertsMatch: "Không tìm thấy cảnh báo phù hợp với bộ lọc.",
      noPacketsMatch: "Không có gói tin nào khớp với từ khóa tìm kiếm.",
    },
    
    // Rules page
    rules: {
      title: "Kho quy tắc & Quản lý Checkbox",
      subtitle: "Bộ luật mẫu theo phong cách Suricata. Dễ dàng bật hoặc tắt các chữ ký bảo mật chỉ bằng một cú nhấp chuột.",
      activeRatio: "Quy tắc đang bật",
      enableAll: "Bật tất cả",
      disableAll: "Tắt tất cả",
      addCustomRule: "Tạo luật tùy chỉnh",
      importSuricata: "Nhập luật Suricata (.rules)",
      suricataModal: {
        title: "Bộ chuyển đổi & Nhập luật Suricata / ET Open",
        desc: "Chuyển đổi cú pháp quy tắc chuẩn của Suricata/Snort hoặc nạp trực tiếp danh mục từ kho chính thức Emerging Threats (hơn 50.000 rules) thành định dạng YAML tương thích.",
        categoryLabel: "Chọn danh mục Emerging Threats (ET Open):",
        fetchCategoryBtn: "Tải danh mục từ máy chủ ET Open",
        fetchingCategory: "Đang tải từ kho lưu trữ...",
        fetchLimit: "Giới hạn số rules:",
        orPasteManually: "Hoặc tự dán nội dung Suricata rules thủ công (.rules):",
        placeholder: "Dán nội dung rules của Suricata vào đây (ví dụ: alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:\"...\"; sid:2001219;))",
        loadSample: "Nạp 10 rule mẫu offline",
        importBtn: "Chuyển đổi & Nhập vào hệ thống",
        importing: "Đang nhập...",
        successMsg: "Đã nạp thành công các quy tắc vào hệ thống!",
        close: "Đóng"
      },
      categories: {
        all: "Tất cả danh mục",
        web_phishing: "Web & Lừa đảo (Phishing)",
        credential_access: "Dò mật khẩu & Xác thực",
        reconnaissance: "Quét cổng & Trinh sát",
        command_and_control: "C2 & Botnet độc hại",
        denial_of_service: "Tấn công DoS & Floods",
        exfiltration: "Rò rỉ dữ liệu & DNS",
      },
      wizard: {
        title: "Trình tạo quy tắc trực quan (Wizard)",
        close: "Đóng",
        ruleTitle: "Tên quy tắc",
        ruleTitlePlaceholder: "Ví dụ: Phát hiện Web Shell tùy chỉnh",
        desc: "Mô tả",
        descPlaceholder: "Ví dụ: Cảnh báo truy cập web đáng ngờ vào cổng quản trị",
        category: "Danh mục",
        severity: "Mức độ nghiêm trọng",
        pattern: "Mẫu phát hiện kích hoạt",
        patternPortMatch: "Khớp cổng (Cảnh báo các cổng cụ thể như 8080, 4444)",
        patternSingleRate: "Tần suất kết nối vào 1 đích (Ngưỡng Brute Force)",
        patternThreshold: "Ngưỡng quét cổng (Quét nhiều cổng khác nhau)",
        targetPorts: "Cổng mục tiêu",
        thresholdCount: "Ngưỡng số lần",
        windowSeconds: "Khung thời gian (Giây)",
        mitreCode: "Mã kỹ thuật MITRE ATT&CK",
        cancel: "Hủy bỏ",
        save: "Lưu & Kích hoạt quy tắc",
      },
    },
    
    // Blocked IPs page
    blocked: {
      title: "Danh sách chặn IPS & Thực thi tường lửa",
      subtitle: "Ngăn chặn các nỗ lực kết nối từ các đối tượng độc hại bằng cách thêm địa chỉ IP vào danh sách chặn.",
      ipPlaceholder: "Địa chỉ IP (Ví dụ: 185.220.101.5)",
      reasonPlaceholder: "Lý do chặn",
      btnBlock: "Chặn IP",
      tableTitle: "Sổ đăng ký IP đang bị chặn",
      reasonHeader: "Lý do",
      blockedAtHeader: "Thời điểm chặn",
      noBlocked: "Không có IP nào đang bị chặn. Tường lửa cá nhân của bạn đang thông suốt.",
      btnUnblock: "Bỏ chặn",
      defaultReason: "Chặn thủ công bởi quản trị viên",
    },
    
    // Threat intel modal
    threatModal: {
      title: "Thanh tra tình báo mối đe dọa (Threat Intel)",
      targetIp: "Địa chỉ IP mục tiêu",
      statusBlocked: "ĐÃ CHẶN TRONG IPS",
      statusAllowed: "ĐANG CHO PHÉP",
      querying: "Đang tra cứu từ các nguồn Threat Intel...",
      abuseScore: "Điểm mức độ nguy hiểm (Abuse Score)",
      country: "Quốc gia xuất xứ",
      usageType: "Loại hình sử dụng",
      domain: "Tên miền máy chủ",
      notFound: "Không tìm thấy dữ liệu tình báo cho IP này.",
      btnUnblock: "Bỏ chặn địa chỉ IP",
      btnBlock: "Chặn IP trong tường lửa IPS",
      blockedReason: "Bị chặn từ thanh tra Threat Intel",
    },
    
    // Footer
    footer: "Hệ thống IDS/IPS cá nhân & Giám sát an ninh mạng AegisGuard © 2026. Bản quyền thuộc về tác giả.",
  },
};
