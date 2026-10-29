import datetime
import json
import os
import re
import subprocess
import requests

# ตั้งค่าคีย์และ URL
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL_HERE"
DASHBOARD_PATH = "/var/www/html/dashboard.html"
HISTORY_JSON_PATH = "/var/www/html/security_history.json"
MY_SAFE_IP = ""  

# 1. อ่านบันทึกการเข้าถึงล่าสุด 50 บรรทัดจาก Nginx
logs = subprocess.getoutput("sudo tail -n 50 /var/log/nginx/access.log")

prompt = f"""
วิเคราะห์ Nginx access log ต่อไปนี้ว่ามีการโจมตีหรือความผิดปกติหรือไม่:
{logs}

ตอบกลับเป็น JSON เท่านั้น โดยมี key ดังนี้:
- "risk_level": ("Low", "Medium", "High")
- "attack_count": (จำนวนตัวเลขเท่านั้น)
- "summary_th": (สรุปสั้นๆ ภาษาไทย)
- "attacker_ips": (รายการ IP ที่ต้องสงสัย)
"""

ai_data = None
try:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"},
    }
    res = requests.post(url, json=payload, timeout=12)
    if res.status_code == 200:
        res_json = res.json()
        ai_data = json.loads(
            res_json["candidates"][0]["content"]["parts"][0]["text"]
        )
except Exception:
    pass

# ระบบ Fallback เมื่อ API ขัดข้อง
if not ai_data:
    suspicious_lines = [
        line
        for line in logs.splitlines()
        if any(
            k in line
            for k in [
                " 403 ",
                " 404 ",
                " 500 ",
                "../",
                "select",
                "wp-admin",
                "wp-login",
                "env",
            ]
        )
    ]
    ips = list(
        set([
            re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)[0]
            for line in suspicious_lines
            if re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        ])
    )
    count = len(suspicious_lines)
    risk = "High" if count > 10 else ("Medium" if count > 0 else "Low")
    summary = (
        f"ตรวจพบรายการผิดปกติ (403/404/Scan) จำนวน {count} ครั้ง"
        if count > 0
        else "การทำงานปกติ ไม่พบพฤติกรรมผิดปกติ"
    )
    ai_data = {
        "risk_level": risk,
        "attack_count": count,
        "summary_th": summary,
        "attacker_ips": ips if ips else [],
    }

# 2. ทำการ Auto-Block IP ลงในตาราง Blacklist ของ Firewall
blocked_ips = []
for ip in ai_data.get("attacker_ips", []):
    found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(ip))
    for item in found_ips:
        if item != MY_SAFE_IP and item not in blocked_ips:
            subprocess.run(f"sudo ipset add blacklist {item} -exist", shell=True)
            blocked_ips.append(item)

now = datetime.datetime.now()
today_str = now.strftime("%Y-%m-%d")

# 3. บันทึกและสะสมข้อมูลประวัติรายวันลงไฟล์ JSON (Daily History Database)
history_db = {}
if os.path.exists(HISTORY_JSON_PATH):
    try:
        with open(HISTORY_JSON_PATH, "r", encoding="utf-8") as f:
            history_db = json.load(f)
    except Exception:
        history_db = {}

if today_str not in history_db:
    history_db[today_str] = {
        "date": today_str,
        "total_attacks": 0,
        "scans_count": 0,
        "highest_risk": "Low",
        "unique_ips": [],
        "timeline": [],
    }

day_entry = history_db[today_str]
day_entry["scans_count"] += 1
day_entry["total_attacks"] += ai_data.get("attack_count", 0)

# ประเมินระดับความเสี่ยงสูงสุดของวัน
risk_weight = {"High": 3, "Medium": 2, "Low": 1}
if risk_weight.get(ai_data.get("risk_level", "Low"), 1) > risk_weight.get(
    day_entry.get("highest_risk", "Low"), 1
):
    day_entry["highest_risk"] = ai_data.get("risk_level", "Low")

# บันทึก IP ประจำวันแบบไม่ซ้ำ
for ip in blocked_ips:
    if ip not in day_entry["unique_ips"]:
        day_entry["unique_ips"].append(ip)

# บันทึก Timeline
day_entry["timeline"].append({
    "time": now.strftime("%H:%M"),
    "risk": ai_data.get("risk_level", "Low"),
    "attacks": ai_data.get("attack_count", 0),
    "summary": ai_data.get("summary_th", ""),
})

with open(HISTORY_JSON_PATH, "w", encoding="utf-8") as f:
    json.dump(history_db, f, ensure_ascii=False, indent=2)

# 4. ส่งแจ้งเตือน Discord
if (
    ai_data.get("attack_count", 0) > 0
    and DISCORD_WEBHOOK_URL != "YOUR_DISCORD_WEBHOOK_URL_HERE"
):
    color_map = {"High": 16711680, "Medium": 16753920, "Low": 65280}
    discord_msg = {
        "username": "AI Security Scanner",
        "embeds": [{
            "title": f"🛡️ Security Alert (Risk: {ai_data.get('risk_level', 'Low')})",
            "description": ai_data.get("summary_th", "-"),
            "color": color_map.get(ai_data.get("risk_level", "Low"), 65280),
            "fields": [
                {
                    "name": "🚨 การโจมตีรอบนี้",
                    "value": f"{ai_data.get('attack_count', 0)} ครั้ง",
                    "inline": True,
                },
                {
                    "name": "📊 ยอดสะสมวันนี้",
                    "value": f"{day_entry['total_attacks']} ครั้ง",
                    "inline": True,
                },
                {
                    "name": "🌐 บล็อก IP อัตโนมัติ",
                    "value": (
                        f"```json\n{json.dumps(blocked_ips, ensure_ascii=False)}\n```"
                        if blocked_ips
                        else "ไม่มี"
                    ),
                    "inline": False,
                },
                {
                    "name": "🖥️ ตรวจสอบประวัติรายวัน",
                    "value": "https://lynxlunarcs.duckdns.org/dashboard.html",
                    "inline": False,
                },
            ],
        }],
    }
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=discord_msg, timeout=5)
    except Exception:
        pass

# 5. สร้างหน้าเว็บ Dashboard สไตล์ BUU Informatics
html_content = """<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AI Security Dashboard - BUU Informatics</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --buu-blue: #0f2c59;
            --buu-gold: #f6c90e;
            --buu-gold-hover: #e0b400;
            --bg-page: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #1e293b;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --danger-color: #ef4444;
            --danger-bg: #fee2e2;
        }

        body { 
            font-family: 'Prompt', sans-serif; 
            background-color: var(--bg-page); 
            color: var(--text-main); 
            min-height: 100vh;
        }

        /* Header Navbar */
        .header-navbar {
            background-color: #ffffff;
            border-bottom: 3px solid var(--buu-gold);
            padding: 1rem 2rem;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
        }
        .brand-badge {
            background: var(--buu-blue);
            color: #ffffff;
            font-weight: 700;
            font-size: 1.15rem;
            padding: 6px 14px;
            border-radius: 8px;
            letter-spacing: 0.5px;
        }
        .brand-title {
            color: var(--buu-blue);
            font-weight: 700;
            font-size: 1.35rem;
            margin: 0;
            line-height: 1.2;
        }
        .btn-buu-gold {
            background-color: var(--buu-gold);
            color: var(--buu-blue);
            font-weight: 600;
            border: none;
            padding: 6px 16px;
            border-radius: 8px;
            transition: all 0.2s;
        }
        .btn-buu-gold:hover {
            background-color: var(--buu-gold-hover);
            color: var(--buu-blue);
        }

        /* Metric Cards */
        .card-custom { 
            background-color: var(--card-bg); 
            border: 1px solid var(--border-color); 
            border-radius: 12px; 
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.03);
            position: relative;
            overflow: hidden;
        }
        .card-custom.border-blue-left {
            border-left: 5px solid var(--buu-blue);
        }
        .card-custom.border-red-left {
            border-left: 5px solid var(--danger-color);
        }
        .card-custom.border-gold-left {
            border-left: 5px solid var(--buu-gold);
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.95rem;
            font-weight: 500;
        }
        .stat-value {
            font-size: 2.4rem;
            font-weight: 700;
            line-height: 1.1;
            margin-top: 8px;
            margin-bottom: 4px;
        }
        .stat-desc {
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .section-title {
            color: var(--buu-blue);
            font-weight: 600;
            font-size: 1.1rem;
        }

        /* Tables & Lists */
        .table-responsive {
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        .table-custom th {
            background-color: #f1f5f9;
            color: var(--buu-blue);
            font-weight: 600;
            padding: 12px 16px;
            border-bottom: 2px solid var(--border-color);
        }
        .table-custom td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-main);
        }
        .badge-ip-banned {
            background-color: var(--danger-bg);
            color: var(--danger-color);
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>

    <!-- Header Bar -->
    <header class="header-navbar mb-4">
        <div class="container-fluid d-flex flex-column flex-md-row justify-content-between align-items-md-center gap-3">
            <div class="d-flex align-items-center gap-3">
                <span class="brand-badge">IF BUU</span>
                <div>
                    <h1 class="brand-title">AI Security & Threat Intelligence</h1>
                    <small class="text-secondary">ระบบเฝ้าระวังความปลอดภัยและรายงานสถิติย้อนหลังรายวัน (Host: lynxcs-vps)</small>
                </div>
            </div>
            <div class="d-flex align-items-center gap-2">
                <label for="dateSelect" class="form-label m-0 text-nowrap fw-semibold text-secondary">📅 วันที่:</label>
                <select id="dateSelect" class="form-select bg-white text-dark border-secondary-subtle" style="width: auto;" onchange="renderDateData(this.value)">
                </select>
                <button class="btn btn-buu-gold" onclick="location.reload()">🔄 รีเฟรช</button>
            </div>
        </div>
    </header>

    <div class="container-fluid px-4 pb-4">
        <!-- 3 Metric Cards -->
        <div class="row g-3 mb-4">
            <div class="col-12 col-md-4">
                <div class="card card-custom border-red-left p-3">
                    <span class="stat-label">ระดับความเสี่ยงสูงสุดของวัน</span>
                    <div class="stat-value text-danger" id="statRisk">-</div>
                    <span id="statScans" class="stat-desc">สแกนทั้งหมด - รอบ</span>
                </div>
            </div>
            <div class="col-12 col-md-4">
                <div class="card card-custom border-gold-left p-3">
                    <span class="stat-label">จำนวนการตรวจจับและสกัดกั้น (ครั้ง)</span>
                    <div class="stat-value" style="color: var(--buu-blue);" id="statAttacks">0</div>
                    <span class="stat-desc">ผ่านการคัดกรอง WAF & Rate Limit</span>
                </div>
            </div>
            <div class="col-12 col-md-4">
                <div class="card card-custom border-blue-left p-3">
                    <span class="stat-label">จำนวน IP ที่ถูกขึ้นบัญชีดำ (Blacklist)</span>
                    <div class="stat-value" style="color: var(--buu-blue);" id="statIPCount">0</div>
                    <span class="stat-desc">ถูกบล็อกระดับ Kernel iptables ถาวร</span>
                </div>
            </div>
        </div>

        <!-- Chart + Banned IP List -->
        <div class="row g-3 mb-4">
            <div class="col-12 col-lg-8">
                <div class="card card-custom p-3 h-100">
                    <h5 class="section-title mb-3">📈 ความถี่การโจมตีในแต่ละช่วงเวลา (24 ชั่วโมง)</h5>
                    <div style="position: relative; height: 280px;">
                        <canvas id="threatChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-12 col-lg-4">
                <div class="card card-custom p-3 h-100">
                    <h5 class="section-title mb-2">🚫 รายการ IP ที่ถูกสกัดกั้นในวันนั้น</h5>
                    <div id="ipListContainer" class="overflow-auto mt-2" style="max-height: 270px;">
                        <ul class="list-group list-group-flush" id="ipList"></ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- Timeline Logs Table -->
        <div class="card card-custom p-3">
            <h5 class="section-title mb-3">📝 รายละเอียดบันทึกการตรวจจับตามรอบเวลา</h5>
            <div class="table-responsive">
                <table class="table table-hover table-custom align-middle mb-0">
                    <thead>
                        <tr>
                            <th>เวลา</th>
                            <th>ระดับความเสี่ยง</th>
                            <th>จำนวนคำขอผิดปกติ</th>
                            <th>สรุปผลการวิเคราะห์ด้วย AI</th>
                        </tr>
                    </thead>
                    <tbody id="timelineTableBody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let rawHistoryData = {};
        let threatChartInstance = null;

        async function initDashboard() {
            try {
                const res = await fetch('/security_history.json?t=' + Date.now());
                rawHistoryData = await res.json();
                
                const dates = Object.keys(rawHistoryData).sort().reverse();
                const dateSelect = document.getElementById('dateSelect');
                dateSelect.innerHTML = '';

                if (dates.length === 0) {
                    dateSelect.innerHTML = '<option>ไม่มีข้อมูล</option>';
                    return;
                }

                dates.forEach(d => {
                    const opt = document.createElement('option');
                    opt.value = d;
                    opt.textContent = d;
                    dateSelect.appendChild(opt);
                });

                renderDateData(dates[0]);
            } catch (err) {
                console.error("Failed to load history data:", err);
            }
        }

        function renderDateData(selectedDate) {
            const data = rawHistoryData[selectedDate];
            if (!data) return;

            const riskBadge = document.getElementById('statRisk');
            riskBadge.textContent = data.highest_risk;
            riskBadge.className = 'stat-value ' + (data.highest_risk === 'High' ? 'text-danger' : (data.highest_risk === 'Medium' ? 'text-warning' : 'text-success'));

            document.getElementById('statScans').textContent = `สแกนทั้งหมด ${data.scans_count} รอบ`;
            document.getElementById('statAttacks').textContent = data.total_attacks.toLocaleString();
            document.getElementById('statIPCount').textContent = data.unique_ips.length.toLocaleString();

            const ipList = document.getElementById('ipList');
            ipList.innerHTML = '';
            if (data.unique_ips.length === 0) {
                ipList.innerHTML = '<li class="list-group-item bg-transparent text-secondary">ไม่พบ IP บุกรุกในวันนี้ (Traffic ปลอดภัย)</li>';
            } else {
                data.unique_ips.forEach(ip => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item bg-transparent d-flex justify-content-between align-items-center py-2 px-1 border-bottom';
                    li.innerHTML = `<strong>${ip}</strong><span class="badge-ip-banned">Banned</span>`;
                    ipList.appendChild(li);
                });
            }

            const tbody = document.getElementById('timelineTableBody');
            tbody.innerHTML = '';
            const timeline = [...(data.timeline || [])].reverse();
            if (timeline.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-3">ไม่มีรายการบันทึก</td></tr>';
            } else {
                timeline.forEach(row => {
                    const tr = document.createElement('tr');
                    const badgeClass = row.risk === 'High' ? 'bg-danger text-white' : (row.risk === 'Medium' ? 'bg-warning text-dark' : 'bg-success text-white');
                    tr.innerHTML = `
                        <td class="font-monospace text-primary fw-bold">${row.time} น.</td>
                        <td><span class="badge ${badgeClass}">${row.risk}</span></td>
                        <td>${row.attacks} รายการ</td>
                        <td>${row.summary}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            renderChart(data.timeline || []);
        }

        function renderChart(timeline) {
            const ctx = document.getElementById('threatChart').getContext('2d');
            const labels = timeline.map(t => t.time);
            const values = timeline.map(t => t.attacks);

            if (threatChartInstance) {
                threatChartInstance.destroy();
            }

            threatChartInstance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'จำนวนคำขอที่ถูกสกัดกั้น',
                        data: values,
                        borderColor: '#0f2c59',
                        backgroundColor: 'rgba(15, 44, 89, 0.08)',
                        fill: true,
                        tension: 0.35,
                        pointBackgroundColor: '#f6c90e',
                        pointBorderColor: '#0f2c59',
                        pointRadius: 4,
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: '#f1f5f9' }, ticks: { color: '#64748b' } },
                        y: { grid: { color: '#f1f5f9' }, ticks: { color: '#64748b', stepSize: 1 }, beginAtZero: true }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        initDashboard();
    </script>
</body>
</html>
"""

with open(DASHBOARD_PATH, "w", encoding="utf-8") as f:
    f.write(html_content)

print("อัปเดตสคริปต์และหน้าเว็บ Dashboard สไตล์ BUU Informatics สำเร็จเรียบร้อย!")
