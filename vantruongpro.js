[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com, *.vn
dns-server = 45.90.28.222, 1.1.1.1
tun-surrogated-dns = 1.1.1.1

[Rule]
# Chặn quảng cáo YouTube (UDP Reject để ép về TCP giúp Script xử lý)
AND,((DOMAIN-SUFFIX,googlevideo.com),(PROTOCOL,UDP)),REJECT
AND,((DOMAIN,youtubei.googleapis.com),(PROTOCOL,UDP)),REJECT
# Chặn các domain quảng cáo cứng
DOMAIN,ads.youtube.com,REJECT
DOMAIN,s.youtube.com,REJECT
# Quy tắc mặc định
# Tối ưu hóa luồng Video & Chặn Ads YouTube
FINAL,DIRECT

[Header Rewrite]
# Xóa Etag để tránh RevenueCat phát hiện đã dùng Script
http-request ^https?://api.revenuecat.com/.+/(receipts$|subscribers/?(.*?)*$) header-del x-revenuecat-etag
http-request ^https?://api.revenuecat.com/.+/(receipts$|subscribers/?(.*?)*$) header-del X-RevenueCat-ETag

# ===== Spotify iOS15 Header Rewrite =====
http-request ^https:\/\/(spclient\.wg\.spotify\.com|.*-spclient\.spotify\.com(:443)?)\/user-customization-service\/v1\/customize$ header-del if-none-match

[Map Local]
# Giả lập phản hồi sạch cho YouTube
^https?:\/\/[\w-]+\.googlevideo\.com\/initplayback.+&oad data-type=text data="" status-code=200

[Script]
# 1. SoundCloud Go+ (Mở khóa nghe nhạc giới hạn)
SoundCloudGo = type=http-response,pattern=https://api-mobile.soundcloud.com/configuration/ios,requires-body=1,script-path=https://raw.githubusercontent.com/duyvinh09/Module_IOS/refs/heads/main/js/SoundCloudGoPlus.js

# 2. Wink (Làm nét video/ảnh VIP)
WinkVip = type=http-response,pattern=^https?:\/\/api-sub\.meitu\.com\/v2\/user\/vip_info_by_group\.json,requires-body=1,script-path=https://raw.githubusercontent.com/duyvinh09/Module_IOS/refs/heads/main/js/WinkVipCrack.js

#Locket
revenuecat = type=http-response, pattern=^https:\/\/api\.revenuecat\.com\/.+\/(receipts$|subscribers\/[^/]+$), script-path=https://raw.githubusercontent.com/truongphp/V-n-Tr-ng/refs/heads/main/vantruong.js, requires-body=true, max-size=-1, timeout=60

# 4. YouTube Premium (Chặn quảng cáo, Phát trong nền, Music Premium)
YT_Req = type=http-request,pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|reel\/reel_watch_sequence|get_watch),requires-body=1,max-size=-1,binary-body-mode=1,script-path=https://raw.githubusercontent.com/duyvinh09/Module_IOS/refs/heads/main/js/youtube.response.js
YT_Res = type=http-response,pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/(browse|next|player|search|reel\/reel_watch_sequence|guide|account\/get_setting|get_watch),requires-body=1,max-size=-1,binary-body-mode=1,script-path=https://raw.githubusercontent.com/duyvinh09/Module_IOS/refs/heads/main/js/youtube.response.js,argument="{"lyricLang":"vi","captionLang":"vi","blockUpload":true,"blockImmersive":true,"debug":false}"

# ===== Spotify iOS15 (app2smile) =====
#!name=Spotify(iOS15)
#!desc=部分解锁premium,建议重新登录,音质不能设置为超高
# 1. 搜索界面 歌单/歌曲可以随意切换完全播放
# 2. 音乐库已点赞歌曲随意切换完全播放

spotify-json = type=http-request,pattern=^https:\/\/(spclient\.wg\.spotify\.com|.*-spclient\.spotify\.com(:443)?)\/(artistview\/v1\/artist|album-entity-view\/v2\/album)\/,requires-body=0,script-path=https://raw.githubusercontent.com/app2smile/rules/master/js/spotify-json.js
spotify-proto = type=http-response,pattern=^https:\/\/(spclient\.wg\.spotify\.com|.*-spclient\.spotify\.com(:443)?)\/(bootstrap\/v1\/bootstrap|user-customization-service\/v1\/customize)$,requires-body=1,binary-body-mode=1,max-size=0,script-path=https://raw.githubusercontent.com/app2smile/rules/master/js/spotify-proto.js,script-update-interval=0

# 5. Xóa Header chống phát hiện (RevenueCat)
DelHeader = type=http-request, pattern=^https:\/\/api\.revenuecat\.com\/.+\/(receipts|subscribers), script-path=https://raw.githubusercontent.com/vuong2023/shad/main/js/deleteHeader.js, timeout=60

[MITM]
hostname = %APPEND% api.revenuecat.com,*.revenuecat.com,api-mobile.soundcloud.com,*.googlevideo.com,youtubei.googleapis.com,www.youtube.com,s.youtube.com,  api-sub.meitu.com,spclient.wg.spotify.com, *spclient.spotify.com
