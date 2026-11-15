import re
import subprocess
import requests

HEADERS = {
    "User-Agent": "Shadowrocket/2490 CFNetwork/1498.700.2 Darwin/23.6.0",
    "Accept": "*/*",
}

# 1. Đọc file full_b1s_dump.txt có sẵn trên Codespaces để săn toàn bộ URL & đường dẫn Worker
with open("full_b1s_dump.txt", "r", encoding="utf-8") as f:
    dump_text = f.read()

# Tìm mọi URL trong code (đặc biệt là workers.dev, b1s.id.vn và các route API)
urls = sorted(set(re.findall(r'https?://[^\s"\'`<>\\)\]]+', dump_text)))

# Tìm các đường dẫn tương đối (path) nối sau workers.dev trong script frame_router
worker_paths = sorted(set(re.findall(r'["\'](/[a-zA-Z0-9_\-/\.]+)["\']', dump_text)))

with open("cloudflare_worker_dump.txt", "w", encoding="utf-8") as out:
    out.write("=== 1. DANH SÁCH TOÀN BỘ URL TÌM THẤY TRONG SCRIPT ===\n")
    for u in urls:
        out.write(f"- {u}\n")

    out.write("\n=== 2. CÁC ROUTE / PATH NỘI BỘ TRONG SCRIPT ===\n")
    for p in worker_paths:
        out.write(f"- {p}\n")

    out.write("\n=== 3. KẾT QUẢ THĂM DÒ (PROBE) CLOUDFLARE WORKER ===\n")
    # Thử gọi vào gốc worker và các path tìm được trên b1steam-frames-1
    base_worker = "https://b1steam-frames-1.nhb-120111.workers.dev"
    test_targets = [base_worker, f"{base_worker}/frames", f"{base_worker}/list", f"{base_worker}/index.json"]
    for p in worker_paths:
        if any(k in p.lower() for k in ["frame", "list", "json", "api", "config", "v1", "v2"]):
            test_targets.append(base_worker + p)

    # Thêm các URL workers.dev bắt được trực tiếp trong code
    for u in urls:
        if "workers.dev" in u:
            test_targets.append(u)

    seen = set()
    with requests.Session() as s:
        s.headers.update(HEADERS)
        for target in test_targets:
            if target in seen:
                continue
            seen.add(target)
            try:
                r = s.get(target, timeout=10)
                out.write(f"\n--- [{r.status_code}] {target} ({len(r.text)} bytes) ---\n")
                out.write(r.text[:2000] + ("\n...[Cắt bớt]...\n" if len(r.text) > 2000 else "\n"))
                print(f"[{r.status_code}] {target} -> {len(r.text)} bytes")
            except Exception as e:
                out.write(f"\n--- [ERR] {target}: {e} ---\n")

# 2. Tự động commit và bắn cả 2 file về kho GitHub truongphp/Vip
subprocess.run(["git", "add", "full_b1s_dump.txt", "cloudflare_worker_dump.txt", "a.py"])
subprocess.run(["git", "commit", "-m", "Update full dump + Cloudflare Worker probe"])
subprocess.run(["git", "push"])
print("\n🚀 Đã bắn toàn bộ dữ liệu về kho GitHub truongphp/Vip thành công!")
