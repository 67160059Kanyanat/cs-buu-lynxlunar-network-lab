# Multi-Layered Defense-in-Depth WordPress Architecture
> ระบบเว็บจัดการเนื้อหา WordPress บนสภาพแวดล้อม Azure VPS เสริมความมั่นคงปลอดภัยเชิงลึก 6 ระดับชั้น พร้อมระบบตรวจจับและแจ้งเตือนภัยคุกคามด้วย AI ผ่าน Discord Webhook

---

## 📌 ภาพรวมสถาปัตยกรรมความปลอดภัย (Defense-in-Depth)

โปรเจกต์นี้ออกแบบและพัฒนาตามหลักการ **Defense-in-Depth** เพื่อกระจายการป้องกันซ้อนทับกันหลายระดับ ป้องกันไม่ให้ทราฟฟิกอันตรายเข้าถึงระดับฐานข้อมูลหรือตัวประมวลผลสคริปต์โดยตรง:

| ระดับชั้น (Layer) | เทคโนโลยี / เครื่องมือ | หน้าที่และการป้องกัน |
| :--- | :--- | :--- |
| **Layer 1: Perimeter & Cloud Network** | DuckDNS, Azure NSG, IPset | ควบคุมสิทธิ์การเชื่อมต่อระดับเครือข่ายคลาวด์และคัดกรองทราฟฟิกที่ไม่พึงประสงค์ |
| **Layer 2: Host & Operating System** | Ubuntu 24.04 LTS, OpenSSH, Fail2Ban | บังคับใช้ SSH Key Authentication และตรวจจับการบุกรุกผ่าน `sshd` jail |
| **Layer 3: Reverse Proxy & Gateway** | Nginx Reverse Proxy, Let's Encrypt | จัดการ TLSv1.3, Security Headers, Rate Limiting และสกัดกั้นคำขออันตราย (HTTP 403) |
| **Layer 4: Application Runtime** | PHP 8.3-FPM (UNIX Domain Socket) | ประมวลผลผ่าน FastCGI IPC Socket ปลอดภัยและแยกสิทธิ์โปรเซส (`www-data`) |
| **Layer 5: Application & CMS** | WordPress Core, Astra Child Theme, WP Armour | ดักจับสแปมบอทด้วยเทคนิค Honeypot และสกัดกั้น User Enumeration |
| **Layer 6: Data Persistence** | MySQL 8.0 Server | ปิดการเชื่อมต่อภายนอก (Localhost Only) และควบคุมสิทธิ์ของระบบไฟล์ |

---

## 🛡️ รายละเอียดการเสริมความปลอดภัย (Hardening Highlights)

### 1. Nginx Web Server Hardening
- **Information Masking:** ปิดการส่งเลขรุ่นซอฟต์แวร์ (`server_tokens off;`) ป้องกันการทำ Banner Grabbing
- **Rate Limiting:** จำกัดอัตราคำขอที่ 5 Requests/วินาที ป้องกัน HTTP Flood / DoS
- **HTTP Security Headers:** บังคับใช้ HSTS, CSP, X-Frame-Options (`SAMEORIGIN`), X-Content-Type-Options (`nosniff`)
- **Attack Vector Filtering:** ตัดสิทธิ์เป็น `403 Forbidden` ทันทีเมื่อตรวจพบ SQL Injection, XSS, Path Traversal
- **Access Control:** ปิดกั้นการเข้าถึง `wp-config.php`, `xmlrpc.php`, `readme.html` รวมถึง REST API User Enumeration (`/wp-json/wp/v2/users`) และ Author URL Scanning (`/?author=1`, `/author/admin/`)

### 2. Intrusion Prevention (Fail2Ban)
- ตรวจสอบบันทึกเหตุการณ์แบบเรียลไทม์ผ่าน 2 Jails หลัก:
  - `sshd`: สกัดกั้นการสุ่มรหัสผ่าน SSH Brute-Force
  - `nginx-botsearch`: ตรวจจับและขึ้นแบล็กลิสต์ IP บอทที่พยายามสแกนหาช่องโหว่

### 3. Application Protection (Honeypot Anti-Spam)
- ติดตั้ง **WP Armour** สกัดกั้นสแปมบอทระดับฟอร์ม (Login, Register, Comment) โดยสร้างฟิลด์กับดักที่ซ่อนจากสายตามนุษย์ ไม่ส่งผลกระทบต่อความเร็วของระบบและไม่รบกวนผู้ใช้งานจริง

### 4. AI Log Analysis & Discord Alert
- พัฒนาสคริปต์ `ai_scanner.py` ตรวจอ่านบันทึกการเข้าถึง `/var/log/nginx/access.log` แบบเรียลไทม์
- ตรวจจับพฤติกรรมผิดปกติและส่งข้อมูลสรุป (IP ผู้โจมตี, Payload, ประเภทภัยคุกคาม) ผ่าน **Discord Webhook** แจ้งเตือนผู้ดูแลระบบแบบทันกาล

---

## 📂 โครงสร้างไดเรกทอรีของโปรเจกต์ (Repository Structure)

```text
├── config/
│   ├── fail2ban/
│   │   └── jail.local                  # การตั้งค่า Jails ของ Fail2Ban
│   ├── nginx/
│   │   └── nginx-hardened.conf         # ไฟล์กำหนดค่า Hardening ของ Nginx Reverse Proxy
│   └── wordpress/
│       └── wp-config-sample.php        # ตัวอย่างไฟล์กำหนดค่าความปลอดภัย WordPress
├── scripts/
│   └── ai_scanner.py                   # สคริปต์ตรวจจับ Access Log และแจ้งเตือน Discord
├── .gitignore                          # ป้องกันการอัปโหลด Secrets, Keys และ Logs
└── README.md                           # เอกสารอธิบายภาพรวมโครงการ

