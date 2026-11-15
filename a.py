import requests

KEY = "B1S-K6G4-RCM7-HQZM"
BASE_URL = "https://locket.b1s.id.vn/api/v2/locketgold"
ENDPOINTS = [
    "module/all-in-one",
    "script/upload_frame",
    "script/photobooth_request",
    "script/photobooth_response",
    "script/profile_request",
    "script/profile_response",
    "script/frame_router",
    "script/locket_api",
    "script/revenuecat_request",
    "script/revenuecat_response",
    "script/firebase_request",
    "script/firebase_response",
    "script/conf_header",
]

HEADERS = {
    "User-Agent": "Shadowrocket/2490 CFNetwork/1498.700.2 Darwin/23.6.0",
    "Accept": "*/*",
    "Accept-Language": "vi-VN,vi;q=0.9",
}

output_file = "full_b1s_dump.txt"

with requests.Session() as s, open(output_file, "w", encoding="utf-8") as out:
    s.headers.update(HEADERS)
    for ep in ENDPOINTS:
        url = f"{BASE_URL}/{ep}?key={KEY}"
        try:
            r = s.get(url, timeout=15)
            header = f"\n{'='*50}\n[{r.status_code}] {ep} ({len(r.text)} bytes)\nURL: {url}\n{'='*50}\n"
            print(header.strip())
            print(r.text[:300] + ("\n...[Đã lưu full vào file]...\n" if len(r.text) > 300 else ""))
            out.write(header + r.text + "\n")
        except Exception as e:
            print(f"[LỖI] {ep}: {e}")

print(f"\n✅ Đã gom toàn bộ code vào file: {output_file}")
