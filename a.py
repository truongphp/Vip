#!/usr/bin/env python3
"""
Script chạy trực tiếp trên GitHub Codespaces (repo truongphp/Vip):
Chỉ cần chạy `python3 a.py` để tải các file .sgmodule / .js từ cấu hình đã cung cấp,
lưu thành .txt vào thư mục `scraped_txt/` và tự động `git push` lên repo.
"""

import gzip
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "Shadowrocket/2490 CFNetwork/1498.700.2 Darwin/23.6.0"
OUTPUT_DIR = Path("scraped_txt")

TARGETS = [
    (
        "LocketGold_sgmodule.txt",
        "https://dinhduyvinh.tech/i/LocketGold_by_duyvinh09_f7f1125d8252b6bd0cae62b46efc7990567bb976997b6cacaed9fd62425b38d8.sgmodule",
    ),
    (
        "Locket_Filters.js.txt",
        "https://locket.dinhduyvinh.tech/js/Locket_Filters.js",
    ),
    (
        "Locket_Unlocked.js.txt",
        "https://locket.dinhduyvinh.tech/js/Locket_Unlocked.js?widget_frame=https%3A%2F%2Fi.ibb.co%2F1Yt1Dzzy%2FShin-chan-1.png",
    ),
    (
        "Locket_Duyvinh09.js.txt",
        "https://locket.dinhduyvinh.tech/js/Locket_Duyvinh09.js",
    ),
    (
        "deleteHeader.js.txt",
        "https://locket.dinhduyvinh.tech/js/deleteHeader.js",
    ),
]


def fetch_text(url: str, timeout: int = 30) -> str:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, identity",
        "Cache-Control": "no-cache",
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if "gzip" in (resp.headers.get("Content-Encoding") or "").lower():
            raw = gzip.decompress(raw)
        charset = resp.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")


def run_git(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], text=True, capture_output=True)


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    saved_files: list[str] = []

    for filename, url in TARGETS:
        print(f"⏳ Đang tải: {filename}")
        try:
            content = fetch_text(url)
            out_path = OUTPUT_DIR / filename
            out_path.write_text(content, encoding="utf-8")
            saved_files.append(str(out_path))
            print(f"   ✅ Đã lưu: {out_path} ({len(content):,} ký tự)")
        except urllib.error.HTTPError as e:
            print(f"   ❌ HTTP {e.code} khi tải {filename}: {e.reason}")
        except Exception as e:
            print(f"   ❌ Lỗi tải {filename}: {e}")

    if not saved_files:
        print("\n❌ Không tải được file nào.")
        return 1

    add_res = run_git(["add", *saved_files, "a.py"])
    if add_res.returncode != 0:
        print(f"\n⚠️ Không chạy được git add: {add_res.stderr.strip()}")
        return 1

    status_res = run_git(["status", "--porcelain"])
    if not status_res.stdout.strip():
        print("\nℹ️ Nội dung không có gì thay đổi so với repo, bỏ qua commit.")
        return 0

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    commit_res = run_git(["commit", "-m", f"Update scraped_txt ({now_str})"])
    if commit_res.returncode != 0:
        print(f"\n❌ Lỗi git commit: {commit_res.stderr.strip() or commit_res.stdout.strip()}")
        return 1

    push_res = run_git(["push"])
    if push_res.returncode != 0:
        print(f"\n❌ Lỗi git push: {push_res.stderr.strip() or push_res.stdout.strip()}")
        return 1

    print("\n🚀 Đã lưu toàn bộ file .txt và push lên repo truongphp/Vip thành công!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
