#!/usr/bin/env python3
"""
Chạy 1 lần trên GitHub Codespaces (hoặc máy cá nhân) để:
1. Tải toàn bộ ~125 khung PNG từ script @duyvinh09
2. Upload hàng loạt lên tài khoản imgbb của bạn (lưu vĩnh viễn, KHÔNG đặt expiration)
3. Tự động gộp vào frames.json (giữ nguyên 17 khung cũ, lưu tiến độ liên tục để chạy tiếp nếu gián đoạn)

Cách chạy nhanh trên Codespaces:
  IMGBB_API_KEY="YOUR_KEY" python3 sync_frames_imgbb.py
"""

import base64
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

FRAMES_JSON = Path("frames.json")
BASE_IMG_URL = "https://locket.dinhduyvinh.tech/images/{fid}.png"

# (id, name, category, bg_color)
NEW_FRAMES = [
    # --- PhotoBooth 4 ảnh ---
    ("pb_khung4_merry_christmas", "🎄 Thư Giáng Sinh (4 ô)", "PhotoBooth 4 ảnh", "#202020"),
    ("pb_khung4_christmas_palette", "❄️ Giáng Sinh Tuyết Xanh (4 ô)", "PhotoBooth 4 ảnh", "#426E89"),
    ("pb_khung4_happy_birthday", "🎂 Sinh Nhật Y2K (4 ô)", "PhotoBooth 4 ảnh", "#242424"),
    ("pb_khung4_shin1", "🖍️ Shin Xanh Tinh Nghịch (4 ô)", "PhotoBooth 4 ảnh", "#279ED6"),
    ("pb_khung4_shin2", "🖍️ Shin Hồng Dễ Thương (4 ô)", "PhotoBooth 4 ảnh", "#ED75B1"),
    ("pb_khung4_shin3", "🖍️ Shin Cam Năng Động (4 ô)", "PhotoBooth 4 ảnh", "#EF6217"),
    ("pb_khung4_smile", "😊 Smile! (4 ô)", "PhotoBooth 4 ảnh", "#252525"),
    ("pb_khung4_scrapbook_do", "📕 Scrapbook Đỏ (4 ô)", "PhotoBooth 4 ảnh", "#671C2A"),
    ("pb_khung4_inspire_arena", "🎵 Inspire Arena (4 ô)", "PhotoBooth 4 ảnh", "#267BB5"),
    ("pb_khung4_my_vault", "⚡ My Vault (4 ô)", "PhotoBooth 4 ảnh", "#292929"),
    ("pb_khung4_cham_bi", "🔴 Chấm Bi (4 ô)", "PhotoBooth 4 ảnh", "#694A4B"),
    ("pb_khung4_cham_bi_den", "⚫ Chấm Bi Đen (4 ô)", "PhotoBooth 4 ảnh", "#242424"),
    ("pb_khung4_likeble", "💛 Likeble (4 ô)", "PhotoBooth 4 ảnh", "#B39C57"),
    ("pb_khung4_razzle", "📸 Razzle Dazzle (4 ô)", "PhotoBooth 4 ảnh", "#806044"),
    ("pb_khung4_your_title", "📰 Your Title (4 ô)", "PhotoBooth 4 ảnh", "#60462D"),
    ("pb_khung4_soulmate_film", "🎞️ Soulmate Film (4 ô)", "PhotoBooth 4 ảnh", "#8C2937"),
    ("pb_khung4_mimi", "📸 Mimi Say Cheese (4 ô)", "PhotoBooth 4 ảnh", "#5D8DBA"),
    ("pb_khung4_fairy_film", "🧚 Fairy Film (4 ô)", "PhotoBooth 4 ảnh", "#344F7B"),
    ("pb_khung4_foto_lush", "📷 Foto Lush (4 ô)", "PhotoBooth 4 ảnh", "#6F6A63"),
    ("pb_khung4_photoism", "📷 Photoism (4 ô)", "PhotoBooth 4 ảnh", "#242424"),
    ("pb_khung4_twinkle_booth", "⭐ Twinkle Booth (4 ô)", "PhotoBooth 4 ảnh", "#674323"),
    ("pb_khung4_equinox", "🎞️ Equinox Studio (4 ô)", "PhotoBooth 4 ảnh", "#174C9B"),
    ("pb_khung4_i_love_you", "💌 I Love You (4 ô)", "PhotoBooth 4 ảnh", "#795D3D"),
    ("pb_khung4_film", "🎞️ Cuộn Phim 35mm (4 ô)", "PhotoBooth 4 ảnh", "#1C1C1C"),
    ("pb_khung4_dream_cream", "🧥 Denim & Kem (4 ô)", "PhotoBooth 4 ảnh", "#405978"),
    ("pb_khung4_scrapbook", "📒 Scrapbook Kỷ Niệm (4 ô)", "PhotoBooth 4 ảnh", "#C9B08A"),
    ("pb_khung4_so_cool", "🩷 So Cool (4 ô)", "PhotoBooth 4 ảnh", "#D85C9A"),
    ("pb_khung4_berry_days", "🍓 Berry Days (4 ô)", "PhotoBooth 4 ảnh", "#FFB6C1"),
    ("pb_khung4_happy_snap", "💜 Happy Snap (4 ô)", "PhotoBooth 4 ảnh", "#5F5098"),
    ("pb_khung4_sky_diary", "☁️ Sky Diary (4 ô)", "PhotoBooth 4 ảnh", "#73815B"),
    ("pb_khung4_4cut", "🎀 Photobooth 4 ô", "PhotoBooth 4 ảnh", "#FFD6E0"),
    ("pb_khung4_holo_4cut", "💿 Photobooth Y2K Holo (4 ô)", "PhotoBooth 4 ảnh", "#C4B5FD"),
    ("pb_khung4_scrapbook_ripped_4cut", "📜 Photobooth Scrapbook (4 ô)", "PhotoBooth 4 ảnh", "#D6A36A"),
    ("pb_khung4_ripped_paper_4cut", "📄 Photobooth Ripped Paper (4 ô)", "PhotoBooth 4 ảnh", "#8D2424"),
    ("pb_khung4_denim_ripped_2x2", "👖 Photobooth Denim 4 ô", "PhotoBooth 4 ảnh", "#315574"),
    ("pb_khung4_dem_day_sao", "🌌 Đêm Đầy Sao (4 ô)", "PhotoBooth 4 ảnh", "#204C9A"),
    ("pb_khung4_vit_da_ngoai", "🦆 Vịt Đi Dã Ngoại (4 ô)", "PhotoBooth 4 ảnh", "#E5B35B"),
    ("pb_khung4_bo_xanh", "🥑 Bơ Xanh Mơ Màng (4 ô)", "PhotoBooth 4 ảnh", "#99B65A"),
    ("pb_khung4_snoopy", "🐶 Snoopy & Bạn Bè (4 ô)", "PhotoBooth 4 ảnh", "#556D80"),
    ("pb_khung4_hoi_ban_hoat_hinh", "🎨 Hội Bạn Hoạt Hình (4 ô)", "PhotoBooth 4 ảnh", "#EEA5BB"),
    ("pb_khung4_khung_long_pastel", "🦖 Khủng Long Pastel (4 ô)", "PhotoBooth 4 ảnh", "#B99ED8"),
    ("pb_khung4_bt21_tim", "💜 BT21 Disco Tím (4 ô)", "PhotoBooth 4 ảnh", "#9F85DC"),
    ("pb_khung4_gau_cookie", "🍪 Gấu Bánh Cookie (4 ô)", "PhotoBooth 4 ảnh", "#B9793E"),
    ("pb_khung4_capybara_tra_sua", "🧋 Capybara Trà Sữa (4 ô)", "PhotoBooth 4 ảnh", "#BD8969"),
    ("pb_khung4_pudding_vang", "🍮 Tiệm Pudding Vàng (4 ô)", "PhotoBooth 4 ảnh", "#D6A447"),
    ("pb_khung4_meo_tiem_banh", "🥐 Tiệm Bánh Mèo Mơ (4 ô)", "PhotoBooth 4 ảnh", "#DC9971"),
    ("pb_khung4_cinnamoroll_may_xanh", "☁️ Cinnamoroll Mây Xanh (4 ô)", "PhotoBooth 4 ảnh", "#75B6DF"),
    ("pb_khung4_minions", "🍌 Minions Tinh Nghịch (4 ô)", "PhotoBooth 4 ảnh", "#E5C545"),
    ("pb_khung4_tiem_banh_mat_ong", "🍯 Tiệm Bánh Mật Ong (4 ô)", "PhotoBooth 4 ảnh", "#D79D52"),
    ("pb_khung4_totoro_rung_xanh", "🌿 Totoro Rừng Xanh (4 ô)", "PhotoBooth 4 ảnh", "#8EAA61"),
    ("pb_khung4_kuromi_no_tim", "🖤 Kuromi Nơ Tím (4 ô)", "PhotoBooth 4 ảnh", "#8B64A1"),
    ("pb_khung4_cho_vang_cau_vong", "🌈 Cún Vàng Cầu Vồng (4 ô)", "PhotoBooth 4 ảnh", "#D4B74C"),
    ("pb_khung4_conan_trinh_tham", "🔍 Conan Thám Tử Nhí (4 ô)", "PhotoBooth 4 ảnh", "#274C82"),
    ("pb_khung4_tho_dau_tay", "🍓 Thỏ Dâu Tây (4 ô)", "PhotoBooth 4 ảnh", "#DF8CA2"),
    ("pb_khung4_cinnamoroll_thien_than", "👼 Cinnamoroll Thiên Thần (4 ô)", "PhotoBooth 4 ảnh", "#E6A1C7"),
    ("pb_khung4_bt21_do", "❤️ BT21 Rực Rỡ (4 ô)", "PhotoBooth 4 ảnh", "#DB5260"),
    ("pb_khung4_capybara_ca_phe", "☕ Capybara Tiệm Cà Phê (4 ô)", "PhotoBooth 4 ảnh", "#AF805D"),
    ("pb_khung4_my_melody_hong", "🎀 My Melody Hồng (4 ô)", "PhotoBooth 4 ảnh", "#DC84AD"),
    ("pb_khung4_loopy_tra_sua", "🧋 Loopy Trà Sữa (4 ô)", "PhotoBooth 4 ảnh", "#D991AB"),
    ("pb_khung4_koala_may_xanh", "🐨 Koala Ngủ Trên Mây (4 ô)", "PhotoBooth 4 ảnh", "#8FAFD7"),
    ("pb_khung4_totoro", "🌱 Totoro Khu Vườn Nhỏ (4 ô)", "PhotoBooth 4 ảnh", "#91A766"),
    ("pb_khung4_kuromi_tim", "💜 Kuromi Tím Mộng Mơ (4 ô)", "PhotoBooth 4 ảnh", "#A377C2"),
    ("pb_khung4_gau_ngu_trang_sao", "🌙 Gấu Ngủ Trăng Sao (4 ô)", "PhotoBooth 4 ảnh", "#A899D6"),
    ("pb_khung4_bt21_party", "🎉 BT21 Party (4 ô)", "PhotoBooth 4 ảnh", "#BE88C0"),
    ("pb_khung4_scrapbook_xanh", "📘 Scrapbook Xanh Dịu (4 ô)", "PhotoBooth 4 ảnh", "#9DAEC9"),
    ("pb_khung4_vit_vuon_hoa", "🌼 Vịt Trong Vườn Hoa (4 ô)", "PhotoBooth 4 ảnh", "#A8C576"),
    ("pb_khung4_bts", "💜 BTS Tím Yêu Thương (4 ô)", "PhotoBooth 4 ảnh", "#A67AD1"),
    ("pb_khung4_conan", "🕵️ Conan Phá Án (4 ô)", "PhotoBooth 4 ảnh", "#28578C"),
    ("pb_khung4_cortis", "🩵 CORTIS Xanh Thanh Xuân (4 ô)", "PhotoBooth 4 ảnh", "#9AB7DB"),
    ("pb_khung4_doraemon", "🔔 Doraemon & Hội Bạn (4 ô)", "PhotoBooth 4 ảnh", "#62ACDB"),
    ("pb_khung4_dragon_ball", "🐉 Dragon Ball Bùng Nổ (4 ô)", "PhotoBooth 4 ảnh", "#E49C36"),
    ("pb_khung4_one_piece", "🏴‍☠️ One Piece Ra Khơi (4 ô)", "PhotoBooth 4 ảnh", "#DAAA58"),
    ("pb_khung4_thuy_thu_mat_trang", "🌙 Thủy Thủ Mặt Trăng (4 ô)", "PhotoBooth 4 ảnh", "#E69ABF"),
    ("pb_khung4_shin_cau_vong", "🌈 Shin Cậu Bé Bút Chì (4 ô)", "PhotoBooth 4 ảnh", "#D8AF4A"),

    # --- PhotoBooth 2 ảnh ---
    ("pb_khung2_Polaroid_vintage", "🎞️ Polaroid Vintage (2 ô)", "PhotoBooth 2 ảnh", "#8D7B66"),
    ("pb_khung2_merry_christmas", "🎄 Giáng Sinh Len Ấm (2 ô)", "PhotoBooth 2 ảnh", "#97312F"),
    ("pb_khung2_soulmate", "🖤 Soulmate (2 ô)", "PhotoBooth 2 ảnh", "#353535"),
    ("pb_khung2_monkey", "🐵 Đôi Bạn Monkey (2 ô)", "PhotoBooth 2 ảnh", "#514D29"),
    ("pb_khung2_love_postcard", "💌 Love Postcard (2 ô)", "PhotoBooth 2 ảnh", "#673C52"),
    ("pb_khung2_camera_pic", "📷 Camera Kỷ Niệm (2 ô)", "PhotoBooth 2 ảnh", "#11182C"),
    ("pb_khung2_anhdep", "📸 Hai Tấm Xinh Xinh (2 ô)", "PhotoBooth 2 ảnh", "#7F0000"),
    ("pb_khung2_anhco", "🎞️ Ký Ức Polaroid (2 ô)", "PhotoBooth 2 ảnh", "#303030"),
    ("pb_khung2_di_choi_thoi", "🚶 Hẹn Nhau Đi Chơi (2 ô)", "PhotoBooth 2 ảnh", "#9B292D"),
    ("pb_khung2_len_do", "👗 Lên Đồ Đi Chơi (2 ô)", "PhotoBooth 2 ảnh", "#300020"),
    ("pb_khung2_tin_nong", "📰 Tin Nóng Hôm Nay (2 ô)", "PhotoBooth 2 ảnh", "#E0C080"),
    ("pb_khung2_thang_ngay_ben_nhau", "❤️ Tháng Ngày Bên Nhau (2 ô)", "PhotoBooth 2 ảnh", "#C00000"),
    ("pb_khung2_may_anh", "📷 Góc Máy Thanh Xuân (2 ô)", "PhotoBooth 2 ảnh", "#77776F"),
    ("pb_khung2_ki_niem", "💜 Kỷ Niệm Chúng Mình (2 ô)", "PhotoBooth 2 ảnh", "#E080F0"),
    ("pb_khung2_khi_tinh_iu_den", "💙 Khi Tình Yêu Đến (2 ô)", "PhotoBooth 2 ảnh", "#0040E0"),
    ("pb_khung2_khi_e_vang", "🖤 Khi Em Vắng Anh (2 ô)", "PhotoBooth 2 ảnh", "#252525"),
    ("pb_khung2_dieu_em_uoc_ao", "⭐ Điều Em Ước Ao (2 ô)", "PhotoBooth 2 ảnh", "#B66ABB"),
    ("pb_khung2_thelove", "📰 The Love Times (2 ô)", "PhotoBooth 2 ảnh", "#111111"),
    ("pb_khung2_outfit", "👕 Outfit Check (2 ô)", "PhotoBooth 2 ảnh", "#2C2C2C"),
    ("pb_khung2_thu_tinh", "💌 Thư Tình Ngọt Ngào (2 ô)", "PhotoBooth 2 ảnh", "#F3C7CF"),
    ("pb_khung2_cuoi_vespa", "🛵 Cưới Vespa (2 ô)", "PhotoBooth 2 ảnh", "#159AAF"),
    ("pb_khung2_cinnamoroll", "☁️ Cinnamoroll Đôi Mình (2 ô)", "PhotoBooth 2 ảnh", "#99B7D5"),

    # --- PhotoBooth 3 ảnh ---
    ("pb_khung3_christmas1", "🦌 Giáng Sinh Tuần Lộc (3 ô)", "PhotoBooth 3 ảnh", "#900D13"),
    ("pb_khung3_christmas2", "🎄 Giáng Sinh Selfie (3 ô)", "PhotoBooth 3 ảnh", "#AF3038"),
    ("pb_khung3_christmas3", "🎅 Ho Ho Ho! (3 ô)", "PhotoBooth 3 ảnh", "#9E1714"),
    ("pb_khung3_we_are_friend", "🩷 Chúng Mình Là Bạn (3 ô)", "PhotoBooth 3 ảnh", "#D76A9A"),
    ("pb_khung3_taste_of_love", "💙 Hương Vị Tình Yêu (3 ô)", "PhotoBooth 3 ảnh", "#415C9E"),
    ("pb_khung3_google", "🔍 Google: Tình Yêu Là Gì? (3 ô)", "PhotoBooth 3 ảnh", "#4285F4"),
    ("pb_khung3_photo_iphone", "📱 Photo iPhone (3 ô)", "PhotoBooth 3 ảnh", "#CAC9D2"),
    ("pb_khung3_polaroid2", "🎞️ Polaroid Kỷ Niệm (3 ô)", "PhotoBooth 3 ảnh", "#32312E"),
    ("pb_khung3_fruit", "🍓 Hội Trái Cây (3 ô)", "PhotoBooth 3 ảnh", "#E97B91"),
    ("pb_khung3_da_bao", "🐆 Da Báo (3 ô)", "PhotoBooth 3 ảnh", "#694C35"),
    ("pb_khung3_mothaiba", "✌️ Một Hai Ba (3 ô)", "PhotoBooth 3 ảnh", "#7296BE"),
    ("pb_khung3_ngay_mai_tuoi_sang", "☀️ Ngày Mai Tươi Sáng (3 ô)", "PhotoBooth 3 ảnh", "#242424"),
    ("pb_khung3_memory", "🌲 Memory Lane (3 ô)", "PhotoBooth 3 ảnh", "#103020"),
    ("pb_khung3_Vinyl", "🎵 Vinyl Memories (3 ô)", "PhotoBooth 3 ảnh", "#581C24"),
    ("pb_khung3_Polaroid", "📸 Polaroid Nhật Ký (3 ô)", "PhotoBooth 3 ảnh", "#DC2626"),
    ("pb_khung3_photodump", "✨ Photo Dump Hôm Nay (3 ô)", "PhotoBooth 3 ảnh", "#C49A6C"),
    ("pb_khung3_hoi_ban_than", "👯 Hội Bạn Thân (3 ô)", "PhotoBooth 3 ảnh", "#A0B060"),
    ("pb_khung3_hen_nha", "💕 Hẹn Nhau Nha (3 ô)", "PhotoBooth 3 ảnh", "#E0B0B0"),
    ("pb_khung3_love_so_much", "❤️ Love So Much (3 ô)", "PhotoBooth 3 ảnh", "#7A0010"),

    # --- Khung 1 ảnh & Trend Hot ---
    ("pb_khung1_color", "🌈 Cầu Vồng Kẹo Ngọt", "Khung 1 ảnh", "#D968A1"),
    ("pb_khung1_meow", "🐱 Meow", "Khung 1 ảnh", "#AB773F"),
    ("pb_khung1_sao_nen_trang", "⭐ Sao Nền Trắng", "Khung 1 ảnh", "#515B69"),
    ("pb_khung1_nen_mua", "🌧️ Nền Mưa", "Khung 1 ảnh", "#657D92"),
    ("pb_khung1_meme_meo", "😹 Mèo Meme", "Khung 1 ảnh", "#826751"),
    ("pb_khung1_faker", "🏆 Faker", "Khung 1 ảnh", "#282622"),
    ("pb_khung1_mona_lisa", "🖼️ Mona Lisa", "Khung 1 ảnh", "#5D512B"),
    ("pb_khung1_locket_camera", "📸 Locket Camera", "Khung 1 ảnh", "#202020"),
    ("pb_khung1_spotifyPC", "🎧 Spotify PC", "Khung 1 ảnh", "#23282B"),
    ("pb_khung1_spotify_hong", "🩷 Spotify Hồng", "Khung 1 ảnh", "#C83978"),
    ("pb_khung1_camfuji", "📷 Fuji Film", "Khung 1 ảnh", "#161616"),
    ("pb_khung1_messi", "🏆 Messi Cúp", "Khung 1 ảnh", "#258599"),
    ("pb_khung1_ronaldo_cup", "🏆 Ronaldo Cúp", "Khung 1 ảnh", "#A82432"),
    ("pb_khung1_menu_ios", "📱 Menu iOS", "Khung 1 ảnh", "#36343D"),
    ("pb_khung1_the_hinh", "💪 Thể Hình", "Khung 1 ảnh", "#6E4634"),
    ("pb_khung1_iphone", "🎵 Now Playing", "Khung 1 ảnh", "#303A43"),
    ("pb_khung1_tivi", "📺 Ký Ức Màn Hình", "Khung 1 ảnh", "#686962"),
    ("pb_khung1_the_gioi_cua_2_ta", "💕 Thế Giới Của Hai Ta", "Khung 1 ảnh", "#222222"),
    ("pb_khung1_selflove", "🤍 Self Love Club", "Khung 1 ảnh", "#383530"),
    ("pb_khung1_ptb", "📼 MIXTAPE VOIL.1", "Khung 1 ảnh", "#222222"),
    ("pb_khung1_oi_tinh_yeu", "💚 Ôi, Tình Yêu!", "Khung 1 ảnh", "#90F000"),
    ("pb_khung1_card", "🪪 Thẻ Thanh Xuân", "Khung 1 ảnh", "#103060"),
    ("pb_khung1_love_e_nhiu", "💖 Love Em Nhiều", "Khung 1 ảnh", "#E77C30"),
    ("pb_khung1_ki_niem_tuoi_dep", "🖼️ Kỷ Niệm Tươi Đẹp", "Khung 1 ảnh", "#252525"),
    ("pb_khung1_ins", "📷 Instagram Moments", "Khung 1 ảnh", "#343434"),
    ("pb_khung1_hoi_chieu_troi_mua", "🌧️ Hồi Chiều Trời Mưa", "Khung 1 ảnh", "#C02030"),
    ("pb_khung1_dia", "💿 Chiếc Đĩa Kỷ Niệm", "Khung 1 ảnh", "#8B641E"),
    ("pb_khung1_chuong_cuoi", "📖 Chương Cuối Thanh Xuân", "Khung 1 ảnh", "#515151"),
    ("pb_khung1_maytinh", "🖥️ Màn Hình Hoài Niệm", "Khung 1 ảnh", "#706050"),
    ("pb_khung1_mat_tin_hieu", "📡 No Signal", "Khung 1 ảnh", "#402060"),
    ("pb_khung1_Camera_iPhone", "📷 Camera iPhone", "Khung 1 ảnh", "#7A1F1F"),
    ("pb_khung1_khong_buong", "🎵 Không Buông", "Khung 1 ảnh", "#355C7D"),
    ("pb_khung1_chua_som", "💬 Chửa Sớm", "Trend", "#252525"),
    ("trend_bang_tin_khan", "🚨 Bảng Tin Khẩn", "Trend", "#D62828"),
    ("trend_ve_giu_xe", "🎫 Vé Gửi Xe", "Trend", "#6F8750"),
    ("trend_vo_hoc_sinh", "📓 Vở Học Sinh", "Trend", "#D94742"),
    ("trend_giao_vien_cham_bai", "✏️ Giáo Viên Chấm Bài", "Trend", "#C83232"),
    ("trend_nhiem_vu_hom_nay_la", "✅ Nhiệm Vụ Hôm Nay", "Trend", "#65846A"),
    ("trend_hoa_don_di_choi", "🧾 Hóa Đơn Đi Chơi", "Trend", "#A67C52"),
    ("trend_binh_luan_duoc_ghim", "📌 Bình Luận Được Ghim", "Trend", "#9CA3AF"),
    ("trend_camera_an_ninh", "📹 Camera An Ninh", "Trend", "#374151"),
    ("trend_thong_bao_ngan_hang", "💳 Thông Báo Ngân Hàng", "Trend", "#16A34A"),
    ("trend_chat_nhom_leak", "💬 Chat Nhóm Leak", "Trend", "#1559E8"),
    ("pb_khung1_photobooth_cute", "🎀 Photobooth Cute", "Frames", "#FFD6E0"),
    ("pb_khung1_frame_classic_pb", "🎞️ Photobooth Cổ Điển", "Frames", "#FF758C"),
    ("pb_khung1_hello_kitty_pastel_ngot_ngao", "🐱 Hello Kitty Ngọt Ngào", "Frames", "#FF758C"),
    ("pb_khung1_hello_kitty_hong_pastel", "🎀 Khung Hello Kitty Hồng", "Frames", "#FF758C"),
    ("pb_khung1_pastel_vien_ren", "🎀 Nơ Pastel Viền Ren", "Frames", "#FF758C"),
    ("pb_khung1_hoa_pastel_vien_xanh_xinh", "🌼 Hoa Xinh Pastel", "Frames", "#51e6e4"),
    ("pb_khung1_spiderred", "🕷️ Nhện Đỏ", "Frames", "#8F1D28"),
    ("pb_khung1_khong_gian_xanh_pastel", "🌙 Không Gian Xanh", "Frames", "#66BDE6"),
    ("pb_khung1_ngoi_sao_hong_pastel", "⭐ Ngôi Sao Hồng", "Frames", "#EF82BB"),
    ("pb_khung1_pastel_so_hai_cau", "🦭 Sò Hải Cẩu Pastel", "Frames", "#8DC6F0"),
    ("pb_khung1_shin_chan", "🖍️ Shin-Chan (1 ô)", "Frames", "#f00008"),
    ("pb_khung1_anh_hellokitty_v_sao", "⭐ Hello Kitty & Sao", "Frames", "#780c23"),
    ("pb_khung1_xanh_tay_sao_vang", "⭐ Sao Vàng Xanh", "Frames", "#6fb1d3"),
    ("pb_khung1_sinh_nhat_hello_kitty", "🎂 Sinh Nhật Hello Kitty", "Frames", "#B94C49"),
    ("pb_khung1_y2k_silver_holo", "💿 Khung Y2K Silver Holo", "Frames", "#C4B5FD"),
    ("pb_khung1_denim_ripped", "👖 Khung Denim Cá Tính", "Frames", "#294D75"),
    ("pb_khung1_film_nostalgia", "🎞️ Khung Film Hoài Cổ", "Frames", "#D6A36A"),
    ("pb_khung1_thu_tinh", "💌 Thư Tình Gửi Cậu", "Khung 1 ảnh", "#E8A9B5"),
    ("pb_khung1_cute", "🎀 Cute Hết Cứu", "Khung 1 ảnh", "#FF9BCB"),
    ("pb_khung1_anh_tho", "🤡 Ảnh Thờ", "Khung 1 ảnh", "#C78B38"),
    ("pb_khung1_matmoc", "🤪 Mặt Mộc", "Khung 1 ảnh", "#383538"),
    ("pb_khung1_luffy", "🏴‍☠️ Truy Nã", "Khung 1 ảnh", "#D9C3A7"),

    # --- Comment TikTok ---
    ("cmt_phai_luon_tu_te", "💬 Phải Luôn Tử Tế", "Comment TikTok", "#31343B"),
    ("cmt_chi_can_mot_vet_xuoc", "💬 Chỉ Cần Một Vết Xước", "Comment TikTok", "#145B83"),
    ("cmt_siuu", "⚽ Ronaldo SIUUU", "Comment TikTok", "#344B5B"),
    ("cmt_binh_luan_minh_tue", "💬 Trend Tíc Tóc", "Comment TikTok", "#557C77"),
    ("cmt_locket", "💛 Locket Việt Nam", "Comment TikTok", "#D99D17"),
    ("cmt_sontung", "🎤 Sơn Tùng MTP", "Comment TikTok", "#344C47"),
    ("cmt_xinh", "💬 Ai Cho Xinh Vậy", "Comment TikTok", "#F43F5E"),
    ("cmt_posst", "💬 Tấm Cuối Đáng Đăng", "Comment TikTok", "#EF4444"),
    ("cmt_flash", "⚡ Flash Đổi Nhân Cách", "Comment TikTok", "#06B6D4"),
    ("cmt_duanma", "👻 Dự Án Ma", "Comment TikTok", "#EF4444"),
    ("cmt_dichup", "📸 Chụp 3 Tấm Lựa 3 Tiếng", "Comment TikTok", "#06B6D4"),
    ("cmt_chuano", "🌸 Đừng Khinh Thường Hoa", "Comment TikTok", "#06B6D4"),
    ("cmt_anhdim", "📸 Bạn Thân Giữ Ảnh Dìm", "Comment TikTok", "#EF4444"),

    # --- Tâm trạng & Cà khịa ---
    ("pb_khung1_khong_can_ai_duyet", "💬 Không Cần Ai Duyệt", "Tâm Trạng & Cà Khịa", "#414141"),
    ("pb_khung1_ban_la_gi_ma_toi_phai_ban_tam", "💬 Bạn Là Gì?", "Tâm Trạng & Cà Khịa", "#292929"),
    ("pb_khung1_ong_troi_that_bat_cong", "💬 Ông Trời Thật Bất Công", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_yeu_giau_chu_co_phai_yeu_dau_dau_ma_doi_ghen", "💬 Yêu Giấu Chứ Có Phải Yêu Dấu", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_me_con_dien", "💬 Mẹ Con Điên", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_thieu_vang_ngot_ngao_cua_em", "💬 Thiếu Vắng Ngọt Ngào Của Em", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_loi_cua_tao_a", "💬 Lỗi Của Tao À?", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_tao_song_sao", "💬 Tao Sống Sao Kệ Tao?", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_tuyet_vong", "💬 Tuyệt Vọng", "Tâm Trạng & Cà Khịa", "#242424"),
    ("pb_khung1_dech_quan_tam", "💬 Đếch Quan Tâm", "Tâm Trạng & Cà Khịa", "#607EA9"),
    ("pb_khung1_met5_ma_cai_toi5m1", "💬 Mét 5 Mà Cái Tôi 5m1", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_99_phan_tram_co_the_la_ngai", "💬 99% Cơ Thể Là Ngại", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_noi_ko_buon_la_noi_doi", "💬 Nói Không Buồn Là Nói Dối", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_mo_long_lan_nao_la_du_ma_lan_do", "💬 Mở Lòng Lần Nào...", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_uoc_gi_buon_cung_ra_tien", "💬 Ước Gì Buồn Cũng Ra Tiền", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_han_toan", "💬 Hận Toán", "Tâm Trạng & Cà Khịa", "#DC2626"),
    ("pb_khung1_khong_tin_dan_ong", "💬 Không Tin Đàn Ông", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_kho_do_danh", "💬 Khó Dỗ Dành", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_xinh_gai_tinh_quai", "💬 Xinh Gái Tinh Quái", "Tâm Trạng & Cà Khịa", "#343434"),
    ("pb_khung1_song_basic", "💬 Sống Basic Cho Đời Cơ Bản", "Tâm Trạng & Cà Khịa", "#CF0875"),
    ("pb_khung1_hoang_tu_am_o", "💬 Hoàng Tử Ẩm Ơ", "Tâm Trạng & Cà Khịa", "#343434"),
]


def download_png_bytes(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X)"},
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read()


def upload_to_imgbb(api_key: str, png_bytes: bytes, name: str) -> str:
    payload = urllib.parse.urlencode({
        "key": api_key,
        "name": name,
        "image": base64.b64encode(png_bytes).decode("ascii"),
    }).encode("utf-8")
    req = urllib.request.Request("https://api.imgbb.com/1/upload", data=payload, method="POST")
    with urllib.request.urlopen(req, timeout=35) as r:
        j = json.loads(r.read().decode("utf-8"))
    if not j.get("success"):
        raise RuntimeError(f"imgbb error: {j}")
    return j["data"]["url"]


def main() -> None:
    api_key = os.environ.get("IMGBB_API_KEY", "").strip() or "e86707af2d0c798e25b5cf8fcfe5c63d"
    if not api_key:
        raise SystemExit("❌ Thiếu IMGBB_API_KEY!")

    frames: dict = {}
    if FRAMES_JSON.exists():
        loaded = json.loads(FRAMES_JSON.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            frames = loaded

    total = len(NEW_FRAMES)
    done_now = 0
    for idx, (fid, name, cat, bg) in enumerate(NEW_FRAMES, 1):
        if fid in frames and str(frames[fid].get("url", "")).startswith("https://i.ibb.co/"):
            continue
        src_url = BASE_IMG_URL.format(fid=fid)
        try:
            png_bytes = download_png_bytes(src_url)
            new_url = upload_to_imgbb(api_key, png_bytes, fid)
            frames[fid] = {
                "name": name,
                "category": cat,
                "url": new_url,
                "bg": bg,
            }
            done_now += 1
            print(f"[{idx}/{total}] ✅ {fid} -> {new_url}")
            if done_now % 5 == 0:
                FRAMES_JSON.write_text(json.dumps(frames, ensure_ascii=False, indent=2), encoding="utf-8")
            time.sleep(0.45)
        except Exception as e:
            print(f"[{idx}/{total}] ⚠️ Lỗi {fid}: {e}")
            time.sleep(1.0)

    FRAMES_JSON.write_text(json.dumps(frames, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n🎉 Hoàn tất! Tổng khung trong frames.json: {len(frames)} (vừa thêm mới: {done_now})")

    subprocess.run(["git", "add", "frames.json"], check=False)
    st = subprocess.run(["git", "status", "--porcelain"], text=True, capture_output=True)
    if st.stdout.strip():
        subprocess.run(["git", "commit", "-m", f"Update frames.json ({len(frames)} frames)"], check=False)
        push_res = subprocess.run(["git", "push"], text=True, capture_output=True)
        if push_res.returncode == 0:
            print("🚀 Đã tự động git push frames.json lên repo!")
        else:
            print("⚠️ Chưa git push được:", push_res.stderr.strip())


if __name__ == "__main__":
    main()
