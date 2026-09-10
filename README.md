# ❤️ Live Heart Rate Monitor

A lightweight real-time heart-rate monitoring system using a **Samsung Galaxy Watch 4**, **Heart for Bluetooth**, **HR PUSH**, and **FastAPI WebSockets**.

The project receives heart-rate data from the watch through Bluetooth, forwards it to a FastAPI webhook, and instantly displays the data on a live web dashboard.

**No MQTT. No database. No polling. No external frontend framework.**

---

## 🔄 Architecture

```text
┌──────────────────────┐
│   Samsung Galaxy    │
│       Watch 4       │
└──────────┬───────────┘
           │
           │ Heart Rate
           ▼
┌──────────────────────┐
│ Heart for Bluetooth  │
│      Wear OS App     │
└──────────┬───────────┘
           │
           │ Bluetooth LE
           ▼
┌──────────────────────┐
│       HR PUSH        │
│    Android App       │
└──────────┬───────────┘
           │
           │ HTTP POST
           ▼
┌──────────────────────┐
│       FastAPI        │
│    /webhook/hr       │
└──────────┬───────────┘
           │
           │ Validate + Normalize
           ▼
┌──────────────────────┐
│   In-Memory State    │
│ Latest HR + History  │
└──────────┬───────────┘
           │
           │ WebSocket
           ▼
┌──────────────────────┐
│    Web Dashboard     │
│                      │
│       ❤️ 82 BPM      │
│                      │
│  Min Avg Max + Chart │
└──────────────────────┘
```

---

## 📱 Required Apps

### 1. Heart for Bluetooth

Install **Heart for Bluetooth** on the Galaxy Watch from Google Play.

[Heart for Bluetooth — Google Play](https://play.google.com/store/apps/details?id=lukas.the.coder.heartforbluetooth

The application runs on Wear OS and turns the watch into a standard Bluetooth Low Energy heart-rate sensor. Galaxy Watch 4/5 are listed among its tested watches.

> **Important:** Heart for Bluetooth is installed on the **watch**, not the Android phone.

### 2. HR PUSH

Install **HR PUSH** on the Android phone.

[HR PUSH — Google Play](https://play.google.com/store/apps/details?id=moe.iacg.hrpush)

HR PUSH receives the Bluetooth heart-rate data and forwards it to your HTTP endpoint.

---

## 🛠️ Requirements

### Hardware

* Samsung Galaxy Watch 4
* Android phone
* Bluetooth enabled
* Phone and FastAPI server reachable over the network

### Software

* Python
* FastAPI
* Uvicorn
* WebSockets

`main.py`: for vercel (it require redis)
`app.py`: for vps server
`hr.service`: systemd setup for webhook server  

- install packages

```sh
pip install fastapi uvicorn httpx gunicorn websockets httptools uvloop
```

- Test on Localhost  

```sh
uvicorn app:app --host 0.0.0.0 --port 6023
```

# ⌚ Galaxy Watch Setup

1. Open Google Play Store on the **Galaxy Watch 4**.
2. Install **Heart for Bluetooth**.
3. Open the application on the watch.
4. Start heart-rate broadcasting.
5. Keep Bluetooth enabled.
6. Make sure the phone is able to detect the watch's BLE heart-rate service.

Heart for Bluetooth exposes the watch's current heart rate using the standardized Bluetooth Low Energy heart-rate protocol.

### Background operation

If heart-rate transmission stops when the Watch 4 screen turns off, check the watch's background activity permissions for **Heart for Bluetooth**.

---

# 📱 HR PUSH Setup

Open HR PUSH on your Android phone.

Configure its HTTP/webhook destination:

```text
http://SERVER_IP:2603/webhook/hr
```

For example:

```text
http://127.0.0.1:2603/webhook/hr
```

Use:

```text
Method: POST
Content-Type: application/json
```

The phone must be able to reach the FastAPI server.

---

# 📡 Webhook Format

The FastAPI endpoint accepts common heart-rate JSON formats.

### Recommended

```json
{
  "heart_rate": 82
}
```

Also supported:

```json
{
  "bpm": 82
}
```

```json
{
  "hr": 82
}
```

```json
{
  "heartRate": 82
}
```

Nested data is also supported:

```json
{
  "data": {
    "heart_rate": 82
  }
}
```

---

# 🧪 Test the Webhook

Before testing with HR PUSH, verify the server manually:

```bash
curl -X POST \
  http://127.0.0.1:2603/webhook/hr \
  -H "Content-Type: application/json" \
  -d '{"heart_rate":82}'
```

Expected response:

```json
{
  "success": true,
  "message": "Heart-rate reading accepted",
  "timestamp": "2026-09-09T07:30:00.000Z",
  "data": {
    "heart_rate": 82,
    "timestamp": "2026-09-09T07:30:00.000Z",
    "source": "HR PUSH",
    "connected_clients": 1
  }
}
```

The browser should immediately display:

```text
❤️

82

BPM
```

No page refresh is required.

---

# 🔌 API

| Endpoint      | Method    | Description         |
| ------------- | --------- | ------------------- |
| `/`           | GET       | Live dashboard      |
| `/webhook/hr` | POST      | Receive HR data     |
| `/api/hr`     | GET       | Get latest HR       |
| `/api/health` | GET       | Service health      |
| `/ws`         | WebSocket | Real-time HR stream |

---

## ❤️ WebSocket Message

The server broadcasts:

```json
{
  "type": "heart_rate",
  "data": {
    "heart_rate": 82,
    "timestamp": "2026-09-09T07:30:00.123Z",
    "source": "HR PUSH"
  }
}
```

When a browser initially connects, it receives a snapshot:

```json
{
  "type": "snapshot",
  "data": {
    "heart_rate": 82,
    "timestamp": "2026-09-09T07:30:00.123Z",
    "source": "HR PUSH"
  },
  "history": [],
  "server_time": "2026-09-09T07:30:01.000Z"
}
```

FastAPI provides native WebSocket support for persistent real-time connections and can send/receive text, JSON, and binary data.

---

# ✅ Data Validation

Incoming heart-rate values are validated before broadcasting.

Default accepted range:

```text
25 BPM → 250 BPM
```

Invalid values are rejected.

Examples:

```text
null       ❌
"hello"    ❌
-10        ❌
0          ❌
999        ❌
82         ✅
```

The server also validates:

* HTTP method
* Content-Type
* JSON syntax
* JSON object structure
* Heart-rate field
* Numeric value
* Physiological range

---

# 🔐 Optional Webhook Authentication

For a public server, configure a webhook token:

```bash
export HR_WEBHOOK_TOKEN="your-long-random-secret"
```

Then send:

```text
X-Webhook-Token: your-long-random-secret
```

Example:

```bash
curl -X POST \
  http://127.0.0.1:2603/webhook/hr \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: your-long-random-secret" \
  -d '{"heart_rate":82}'
```

---

# 📊 Dashboard

The web interface provides:

* ❤️ Current BPM
* 🟢 Live connection status
* 🕐 Last update time
* Minimum HR
* Average HR
* Maximum HR
* Lightweight real-time graph
* Automatic WebSocket reconnect
* Responsive mobile/desktop UI

The dashboard uses the browser's native WebSocket API and HTML/CSS/JavaScript.

---

# ⚡ Performance

The application is intentionally lightweight.

```text
HTTP webhook
      ↓
Validate
      ↓
Update in-memory state
      ↓
Broadcast WebSocket message
      ↓
Browser
```

There is:

* No database query for every reading
* No HTTP polling
* No MQTT broker
* No Redis
* No background worker
* No frontend framework
* No external JavaScript library

Recent readings are stored in a **bounded in-memory history**, preventing unlimited RAM growth.

---

# 🧩 Technology Stack

```text
Samsung Galaxy Watch 4
        │
        │ Bluetooth LE
        ▼
Heart for Bluetooth
        │
        ▼
HR PUSH
        │
        │ HTTP POST / JSON
        ▼
FastAPI
        │
        ├── REST API
        │
        └── WebSocket
               │
               ▼
        HTML + CSS + JavaScript
```

### Backend

* Python
* FastAPI
* Uvicorn
* WebSockets

### Frontend

* HTML5
* CSS3
* Modern JavaScript
* WebSocket API
* Canvas API

### Transport

* Bluetooth Low Energy
* HTTP/HTTPS
* JSON
* WebSocket

---

# 🩺 Data Flow Example

A heart-rate reading of `82 BPM` travels through the system:

```text
Galaxy Watch
     │
     │ 82 BPM
     ▼
Heart for Bluetooth
     │
     │ BLE Heart Rate
     ▼
HR PUSH
     │
     │ POST /webhook/hr
     │ {"heart_rate":82}
     ▼
FastAPI
     │
     │ Validate
     │ Store latest value
     ▼
WebSocket
     │
     │ {"type":"heart_rate",...}
     ▼
Browser
     │
     ▼
❤️ 82 BPM
```

Typical end-to-end behavior is event-driven: the server does not repeatedly ask for the current heart rate; it receives the reading and pushes it to connected browsers.

---

# 🔗 Project Links


**Heart for Bluetooth**

[Google Play](https://play.google.com/store/apps/details?id=lukas.the.coder.heartforbluetooth)

**HR PUSH**

[Google Play](https://play.google.com/store/apps/details?id=moe.iacg.hrpush)

**FastAPI**

[FastAPI Documentation](https://fastapi.tiangolo.com/)

---

# ⚠️ Notes

This project is intended for **personal monitoring and experimentation**.

The displayed heart rate should not be considered a medical measurement or used for medical diagnosis.


## ⭐ Credits

Built with:

* Samsung Galaxy Watch 4
* Heart for Bluetooth by Lukas the Coder
* HR PUSH
* FastAPI
* WebSockets
* Python
