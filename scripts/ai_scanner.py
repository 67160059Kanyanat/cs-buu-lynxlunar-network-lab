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
timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")

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

# อัปเดตข้อมูลของวันนี้
day_entry = history_db[today_str]
day_entry["scans_count"] += 1
day_entry["total_attacks"] += ai_data.get("attack_count", 0)

# กำหนดระดับความเสี่ยงสูงสุดของวัน
risk_weight = {"High": 3, "Medium": 2, "Low": 1}
if risk_weight.get(ai_data.get("risk_level", "Low"), 1) > risk_weight.get(
    day_entry.get("highest_risk", "Low"), 1
):
  day_entry["highest_risk"] = ai_data.get("risk_level", "Low")

# บันทึก IP ประจำวันแบบไม่ซ้ำ
for ip in blocked_ips:
  if ip not in day_entry["unique_ips"]:
    day_entry["unique_ips"].append(ip)

# บันทึก Timeline ย่อยแต่ละรอบสแกน
day_entry["timeline"].append({
    "time": now.strftime("%H:%M"),
    "risk": ai_data.get("risk_level", "Low"),
    "attacks": ai_data.get("attack_count", 0),
    "summary": ai_data.get("summary_th", ""),
})

# เซฟประวัติย้อนหลัง
with open(HISTORY_JSON_PATH, "w", encoding="utf-8") as f:
  json.dump(history_db, f, ensure_ascii=False, indent=2)

# 4. ส่งแจ้งเตือน Discord (เฉพาะเมื่อพบเหตุผิดปกติเพื่อไม่ให้รก)
if (
    ai_data.get("attack_count", 0) > 0
    and DISCORD_WEBHOOK_URL != "YOUR_DISCORD_WEBHOOK_URL"
):
  color_map = {"High": 16711680, "Medium": 16753920, "Low": 65280}
  discord_msg = {
      "username": "AI Security Scanner",
      "embeds": [{
          "title": (
              f"🛡️ Security Alert (Risk: {ai_data.get('risk_level', 'Low')})"
          ),
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

# 5. สร้างหน้าเว็บ Dashboard พร้อมระบบเลือกดูย้อนหลังรายวัน (Daily Viewer + Chart.js)
html_content = """<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AI Security Dashboard - ระบบรายงานภัยคุกคามย้อนหลัง</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Prompt', sans-serif; background-color: #0b0f19; color: #e2e8f0; }
        .card-custom { background-color: #161e2e; border: 1px solid #2d3748; border-radius: 12px; }
        .accent-blue { color: #38bdf8; }
        .accent-red { color: #f87171; }
        .accent-green { color: #4ade80; }
    </style>
</head>
<body class="p-3 p-md-4">
    <div class="container-fluid max-w-7xl">
        <!-- Header -->
        <div class="d-flex flex-column flex-md-row justify-content-between align-items-md-center mb-4 pb-3 border-bottom border-secondary gap-3">
            <div>
                <h2 class="fw-bold m-0 accent-blue">🛡️ AI Security & Threat Intelligence</h2>
                <small class="text-secondary">ระบบเฝ้าระวังความปลอดภัยและรายงานสถิติย้อนหลังรายวัน (Host: lynxcs-vps)</small>
            </div>
            <div class="d-flex align-items-center gap-2">
                <label for="dateSelect" class="form-label m-0 text-nowrap fw-semibold">📅 เลือกวันที่:</label>
                <select id="dateSelect" class="form-select bg-dark text-light border-secondary" style="width: auto;" onchange="renderDateData(this.value)">
                </select>
                <button class="btn btn-outline-info btn-sm" onclick="location.reload()">🔄 รีเฟรช</button>
            </div>
        </div>

        <!-- Metric Cards -->
        <div class="row g-3 mb-4">
            <div class="col-12 col-md-4">
                <div class="card card-custom p-3 shadow-sm">
                    <span class="text-secondary small">ระดับความเสี่ยงสูงสุดของวัน</span>
                    <h2 class="fw-bold mt-2 mb-0" id="statRisk">-</h2>
                    <small id="statScans" class="text-secondary mt-1">สแกนทั้งหมด - รอบ</small>
                </div>
            </div>
            <div class="col-12 col-md-4">
                <div class="card card-custom p-3 shadow-sm">
                    <span class="text-secondary small">จำนวนการตรวจจับและสกัดกั้น (ครั้ง)</span>
                    <h2 class="fw-bold mt-2 mb-0 accent-red" id="statAttacks">0</h2>
                    <small class="text-secondary mt-1">ผ่านการคัดกรอง WAF & Rate Limit</small>
                </div>
            </div>
            <div class="col-12 col-md-4">
                <div class="card card-custom p-3 shadow-sm">
                    <span class="text-secondary small">จำนวน IP ที่ถูกขึ้นบัญชีดำ (Blacklist)</span>
                    <h2 class="fw-bold mt-2 mb-0 accent-green" id="statIPCount">0</h2>
                    <small class="text-secondary mt-1">ถูกบล็อกระดับ Kernel iptables ถาวร</small>
                </div>
            </div>
        </div>

        <!-- Chart Section -->
        <div class="row g-3 mb-4">
            <div class="col-12 col-lg-8">
                <div class="card card-custom p-3 shadow-sm h-100">
                    <h5 class="fw-bold mb-3">📈 ความถี่การโจมตีในแต่ละช่วงเวลา (24 ชั่วโมง)</h5>
                    <div style="position: relative; height: 260px;">
                        <canvas id="threatChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-12 col-lg-4">
                <div class="card card-custom p-3 shadow-sm h-100">
                    <h5 class="fw-bold mb-2">🚫 รายการ IP ที่ถูกสกัดกั้นในวันนั้น</h5>
                    <div id="ipListContainer" class="overflow-auto mt-2" style="max-height: 250px;">
                        <ul class="list-group list-group-flush" id="ipList"></ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Timeline Table -->
        <div class="card card-custom p-3 shadow-sm">
            <h5 class="fw-bold mb-3">📝 รายละเอียดบันทึกการตรวจจับตามรอบเวลา</h5>
            <div class="table-responsive">
                <table class="table table-dark table-hover align-middle mb-0">
                    <thead>
                        <tr class="text-secondary">
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

            // Render stats
            const riskBadge = document.getElementById('statRisk');
            riskBadge.textContent = data.highest_risk;
            riskBadge.className = 'fw-bold mt-2 mb-0 ' + (data.highest_risk === 'High' ? 'accent-red' : (data.highest_risk === 'Medium' ? 'text-warning' : 'accent-green'));

            document.getElementById('statScans').textContent = `สแกนทั้งหมด ${data.scans_count} รอบ`;
            document.getElementById('statAttacks').textContent = data.total_attacks.toLocaleString();
            document.getElementById('statIPCount').textContent = data.unique_ips.length.toLocaleString();

            // Render IP List
            const ipList = document.getElementById('ipList');
            ipList.innerHTML = '';
            if (data.unique_ips.length === 0) {
                ipList.innerHTML = '<li class="list-group-item bg-transparent text-secondary">ไม่พบ IP บุกรุกในวันนี้ (Traffic ปลอดภัย)</li>';
            } else {
                data.unique_ips.forEach(ip => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item bg-transparent text-danger font-monospace py-1 px-0 border-secondary';
                    li.textContent = `🛑 ${ip} (Banned)`;
                    ipList.appendChild(li);
                });
            }

            // Render Timeline Table
            const tbody = document.getElementById('timelineTableBody');
            tbody.innerHTML = '';
            const timeline = [...(data.timeline || [])].reverse();
            if (timeline.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center text-secondary py-3">ไม่มีรายการบันทึก</td></tr>';
            } else {
                timeline.forEach(row => {
                    const tr = document.createElement('tr');
                    const badgeClass = row.risk === 'High' ? 'bg-danger' : (row.risk === 'Medium' ? 'bg-warning text-dark' : 'bg-success');
                    tr.innerHTML = `
                        <td class="font-monospace text-info">${row.time} น.</td>
                        <td><span class="badge ${badgeClass}">${row.risk}</span></td>
                        <td>${row.attacks} รายการ</td>
                        <td class="text-light">${row.summary}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            // Render Chart
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
                        label: 'จำนวนภัยคุกคามที่ตรวจจับได้',
                        data: values,
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.15)',
                        fill: true,
                        tension: 0.35,
                        pointBackgroundColor: '#38bdf8'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } },
                        y: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8', stepSize: 1 }, beginAtZero: true }
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

print(
    "✅ อัปเดตสคริปต์สำเร็จ! ระบบเริ่มสะสมประวัติรายวันและสร้าง Dashboard"
    " ย้อนหลังแล้ว"
)
