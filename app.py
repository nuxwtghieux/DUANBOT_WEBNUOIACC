import random
import string
import json
import time
import requests
import uuid
import base64
import io
import struct
import re
import os
import threading
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Tắt cảnh báo SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder='.')
CORS(app)

DB_FILE = 'accounts.json'

# ==========================================================
# PHẦN 1: HÀM XỬ LÝ PROXY & LẤY THÔNG TIN IP
# ==========================================================
def phan_tich_proxy(p):
    if not p or p.strip() == "": return None
    p = p.strip()
    scheme = "http"
    if "://" in p:
        scheme, p = p.split("://", 1)
    user = pw = None
    if "@" in p:
        auth, hostport = p.rsplit("@", 1)
        if ":" in auth: user, pw = auth.split(":", 1)
        else: user = auth
        p = hostport
    parts = p.split(":")
    if len(parts) == 2: ip, port = parts
    elif len(parts) == 4: ip, port, user, pw = parts
    elif len(parts) == 3: ip, port, user = parts; pw = ""
    else: return {"scheme": scheme, "host": p, "port": "80", "user": user, "pass": pw}
    return {"scheme": scheme, "host": ip, "port": port, "user": user, "pass": pw}

def tao_proxy(p):
    info = phan_tich_proxy(p)
    if not info: return None
    if info.get("user"): 
        url = f"{info['scheme']}://{info['user']}:{info['pass'] or ''}@{info['host']}:{info['port']}"
    else: 
        url = f"{info['scheme']}://{info['host']}:{info['port']}"
    return {"http": url, "https": url}

def kiem_tra_proxy(p, timeout=12):
    proxies = tao_proxy(p)
    if not proxies: return False, "Proxy rỗng"
    try:
        r = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=timeout, verify=False)
        if r.status_code == 200: return True, r.json().get("ip", "?")
        return False, f"HTTP {r.status_code}"
    except Exception as e: return False, str(e)

# Hàm tự động lấy Quốc gia, Múi giờ từ IP Proxy
def get_ip_info(proxies=None):
    try:
        # Gọi API lấy thông tin IP (dựa vào IP của proxy)
        r = requests.get("http://ip-api.com/json", proxies=proxies, timeout=10, verify=False)
        if r.status_code == 200:
            data = r.json()
            return {
                "country_code": data.get("countryCode", "VN"),
                "timezone": data.get("timezone", "Asia/Ho_Chi_Minh"),
                "lang": "en_US" if data.get("countryCode") != "VN" else "vi_VN"
            }
    except:
        pass
    return {"country_code": "VN", "timezone": "Asia/Ho_Chi_Minh", "lang": "vi_VN"}


# ==========================================================
# PHẦN 2: CODE LOGIN FB (TỐI ƯU ẨN MÔI TRƯỜNG TUYỆT ĐỐI)
# ==========================================================

class FacebookPasswordEncryptor:
    @staticmethod
    def get_public_key(proxies=None):
        try:
            url = 'https://b-graph.facebook.com/pwd_key_fetch'
            params = {
                'version': '2', 'flow': 'CONTROLLER_INITIALIZATION', 'method': 'GET',
                'fb_api_req_friendly_name': 'pwdKeyFetch', 'fb_api_caller_class': 'com.facebook.auth.login.AuthOperations',
                'access_token': '438142079694454|fc0a7caa49b192f64f6f5a6d9643bb28'
            }
            response = requests.post(url, params=params, proxies=proxies, timeout=15, verify=False).json()
            return response.get('public_key'), str(response.get('key_id', '25'))
        except Exception as e:
            print(f"[Encrypt] Lỗi lấy Public Key: {e}")
            return None, "25"

    @staticmethod
    def encrypt(password, public_key=None, key_id="25", proxies=None):
        if public_key is None:
            public_key, key_id = FacebookPasswordEncryptor.get_public_key(proxies)
        if not public_key:
            return password

        try:
            rand_key = get_random_bytes(32)
            iv = get_random_bytes(12)
            pubkey = RSA.import_key(public_key)
            cipher_rsa = PKCS1_v1_5.new(pubkey)
            encrypted_rand_key = cipher_rsa.encrypt(rand_key)
            cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
            current_time = int(time.time())
            cipher_aes.update(str(current_time).encode("utf-8"))
            encrypted_passwd, auth_tag = cipher_aes.encrypt_and_digest(password.encode("utf-8"))

            buf = io.BytesIO()
            buf.write(bytes([1, int(key_id)]))
            buf.write(iv)
            buf.write(struct.pack("<h", len(encrypted_rand_key)))
            buf.write(encrypted_rand_key)
            buf.write(auth_tag)
            buf.write(encrypted_passwd)

            encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
            return f"#PWD_FB4A:2:{current_time}:{encoded}"
        except Exception as e:
            return password

class FacebookAppTokens:
    APPS = {
        'FB_ANDROID': {'name': 'Facebook For Android', 'app_id': '350685531728'},
        'MESSENGER_ANDROID': {'name': 'Facebook Messenger For Android', 'app_id': '256002347743983'},
        'FB_LITE': {'name': 'Facebook For Lite', 'app_id': '275254692598279'},
        'MESSENGER_LITE': {'name': 'Facebook Messenger For Lite', 'app_id': '200424423651082'},
        'ADS_MANAGER_ANDROID': {'name': 'Ads Manager App For Android', 'app_id': '438142079694454'},
        'PAGES_MANAGER_ANDROID': {'name': 'Pages Manager For Android', 'app_id': '121876164619130'}
    }

    @staticmethod
    def get_app_id(app_key):
        app = FacebookAppTokens.APPS.get(app_key)
        return app['app_id'] if app else None

    @staticmethod
    def get_all_app_keys():
        return list(FacebookAppTokens.APPS.keys())

    @staticmethod
    def extract_token_prefix(token):
        for i, char in enumerate(token):
            if char.islower():
                return token[:i]
        return token


class FacebookLogin:
    API_URL = "https://b-graph.facebook.com/auth/login"
    ACCESS_TOKEN = "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
    API_KEY = "882a8490361da98702bf97a021ddc14d"
    SIG = "214049b9f17c38bd767de53752b53946"

    def __init__(self, uid_phone_mail, password, machine_id=None, convert_all_tokens=False, twofactor_code=None, proxies=None):
        self.uid_phone_mail = uid_phone_mail
        self.twofactor_code = twofactor_code
        self.proxies = proxies

        # TỰ ĐỘNG LẤY THÔNG TIN IP PROXY ĐỂ ĐỒNG BỘ
        self.ip_info = get_ip_info(proxies)
        print(f"[*] Thiết lập môi trường giả lập theo IP: {self.ip_info['country_code']} | {self.ip_info['lang']}")

        if password.startswith("#PWD_FB4A"):
            self.password = password
        else:
            self.password = FacebookPasswordEncryptor.encrypt(password, proxies=self.proxies)

        self.convert_token_to = FacebookAppTokens.get_all_app_keys() if convert_all_tokens else []
        
        self.session = requests.Session()
        if self.proxies: self.session.proxies.update(self.proxies)

        # RANDOM THIẾT BỊ
        self.device_models = [
            {"model": "SM-G998B", "brand": "samsung", "os": "13", "build": "TP1A.220624.014", "density": "3.0", "width": "1440", "height": "3200"},
            {"model": "M2101K7AG", "brand": "Xiaomi", "os": "12", "build": "SKQ1.211006.001", "density": "2.75", "width": "1080", "height": "2400"},
            {"model": "CPH2451", "brand": "OPPO", "os": "13", "build": "TP1A.220905.001", "density": "2.75", "width": "1080", "height": "2412"},
            {"model": "Pixel 7", "brand": "google", "os": "14", "build": "UQ1A.231205.015", "density": "2.625", "width": "1080", "height": "2400"},
            {"model": "V2207", "brand": "vivo", "os": "13", "build": "TP1A.220624.014", "density": "2.75", "width": "1080", "height": "2400"}
        ]
        self.device = random.choice(self.device_models)
        self.fb_ver = random.choice(["430.0.0.35.114", "435.0.0.34.112", "440.0.0.32.110", "450.0.0.44.110"])
        
        self.device_id = str(uuid.uuid4())
        self.adid = str(uuid.uuid4())
        self.secure_family_device_id = str(uuid.uuid4())
        self.machine_id = machine_id if machine_id else self._generate_machine_id()
        self.jazoest = ''.join(random.choices(string.digits, k=5))
        self.sim_serial = ''.join(random.choices(string.digits, k=20))

        self.headers = self._build_headers()
        self.data = self._build_data()

    @staticmethod
    def _generate_machine_id():
        return ''.join(random.choices(string.ascii_letters + string.digits, k=24))

    def _build_headers(self):
        ua = f"Dalvik/2.1.0 (Linux; U; Android {self.device['os']}; {self.device['model']} Build/{self.device['build']}) [FBAN/FB4A;FBAV/{self.fb_ver};FBPN/com.facebook.katana;FBLC/{self.ip_info['lang']};FBBV/480086274;FBCR/MobiFone;FBMF/{self.device['brand']};FBBD/{self.device['brand']};FBDV/{self.device['model']};FBSV/{self.device['os']};FBCA/x86:armeabi-v7a;FBDM/{{density={self.device['density']},width={self.device['width']},height={self.device['height']}}};FB_FW/1;FBRV/0;]"
        
        return {
            "content-type": "application/x-www-form-urlencoded",
            "x-fb-net-hni": "45201", "zero-rated": "0", "x-fb-sim-hni": "45201",
            "x-fb-connection-quality": "EXCELLENT", "x-fb-friendly-name": "authenticate",
            "x-fb-connection-bandwidth": "78032897", "x-tigon-is-retry": "False",
            "authorization": "OAuth null", "x-fb-connection-type": "WIFI",
            "x-fb-device-group": "3342", "priority": "u=3,i",
            "x-fb-http-engine": "Liger", "x-fb-client-ip": "True", "x-fb-server-cluster": "True",
            "x-fb-request-analytics-tags": '{"network_tags":{"product":"350685531728","retry_attempt":"0"},"application_tags":"unknown"}',
            "user-agent": ua
        }

    def _build_data(self):
        return {
            "format": "json", "email": self.uid_phone_mail, "password": self.password, "credentials_type": "password",
            "generate_session_cookies": "1", "locale": self.ip_info['lang'], "client_country_code": self.ip_info['country_code'], 
            "api_key": self.API_KEY, "access_token": self.ACCESS_TOKEN, "adid": self.adid, "device_id": self.device_id, 
            "generate_analytics_claim": "1", "community_id": "", "linked_guest_account_userid": "", "cpl": "true", "try_num": "1", 
            "family_device_id": self.device_id, "secure_family_device_id": self.secure_family_device_id, 
            "sim_serials": f'["{self.sim_serial}"]', "openid_flow": "android_login", "openid_provider": "google", 
            "openid_tokens": "[]", "account_switcher_uids": f'["{self.uid_phone_mail}"]', "enroll_misauth": "false", 
            "error_detail_type": "button_with_disabled", "source": "login", "machine_id": self.machine_id,
            "jazoest": self.jazoest, "meta_inf_fbmeta": "V2_UNTAGGED", "advertiser_id": self.adid, "encrypted_msisdn": "",
            "currently_logged_in_userid": "0", "fb_api_req_friendly_name": "authenticate", "fb_api_caller_class": "Fb4aAuthHandler",
            "sig": self.SIG
        }

    def _convert_token(self, access_token, target_app):
        try:
            app_id = FacebookAppTokens.get_app_id(target_app)
            if not app_id: return None
            response = requests.post('https://api.facebook.com/method/auth.getSessionforApp', data={
                'access_token': access_token, 'format': 'json', 'new_app_id': app_id, 'generate_session_cookies': '1'
            }, proxies=self.proxies, timeout=15, verify=False)
            result = response.json()
            if 'access_token' in result:
                token = result['access_token']
                prefix = FacebookAppTokens.extract_token_prefix(token)
                cookies_dict = {}
                cookies_string = ""
                if 'session_cookies' in result:
                    for cookie in result['session_cookies']:
                        cookies_dict[cookie['name']] = cookie['value']
                        cookies_string += f"{cookie['name']}={cookie['value']}; "
                return {'token_prefix': prefix, 'access_token': token, 'cookies': {'dict': cookies_dict, 'string': cookies_string.rstrip('; ')}}
            return None
        except: return None

    def _handle_2fa(self, error_data):
        if not self.twofactor_code:
            return {'success': False, 'error': 'Tài khoản yêu cầu 2FA nhưng bạn chưa nhập mã.'}
        
        data_2fa = self._build_data()
        data_2fa.update({
            "credentials_type": "two_factor", "twofactor_code": self.twofactor_code, 
            "first_factor": error_data.get('login_first_factor'), "userid": error_data.get('uid')
        })
        try:
            res = self.session.post(self.API_URL, headers=self.headers, data=data_2fa, verify=False).json()
            if 'access_token' in res: return self._parse_success_response(res)
            return {'success': False, 'error': res.get('error', {}).get('message', 'Mã 2FA sai')}
        except Exception as e:
            return {'success': False, 'error': f'Lỗi 2FA: {e}'}

    def _parse_success_response(self, response_json):
        original_token = response_json.get('access_token')
        original_prefix = FacebookAppTokens.extract_token_prefix(original_token)

        result = {
            'success': True,
            'original_token': {'token_prefix': original_prefix, 'access_token': original_token},
            'cookies': {}
        }

        if 'session_cookies' in response_json:
            cookies_dict = {}
            cookies_string = ""
            for cookie in response_json['session_cookies']:
                cookies_dict[cookie['name']] = cookie['value']
                cookies_string += f"{cookie['name']}={cookie['value']}; "
            result['cookies'] = {'dict': cookies_dict, 'string': cookies_string.rstrip('; ')}

        if self.convert_token_to:
            result['converted_tokens'] = {}
            for target_app in self.convert_token_to:
                converted = self._convert_token(original_token, target_app)
                if converted:
                    result['converted_tokens'][target_app] = converted

        return result

    def login(self):
        try:
            response = self.session.post(self.API_URL, headers=self.headers, data=self.data, verify=False)
            response_json = response.json()

            if 'access_token' in response_json:
                return self._parse_success_response(response_json)

            if 'error' in response_json:
                err_data = response_json['error'].get('error_data', {})
                if 'login_first_factor' in err_data and 'uid' in err_data:
                    return self._handle_2fa(err_data)
                return {'success': False, 'error': response_json['error'].get('message', 'Unknown error')}

            return {'success': False, 'error': 'Unknown response format'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


# ==========================================================
# PHẦN 3: CODE NUÔI ACC (Giữ nguyên)
# ==========================================================

class FacebookAIBot:
    def __init__(self, api_key, model_ai, api_url, proxies=None):
        self.api_key = api_key
        self.model = model_ai
        self.api_url = api_url
        self.proxies = proxies

    def _goi_ai(self, prompt):
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.9, "max_tokens": 200}
        for attempt in range(3):
            try:
                res = requests.post(self.api_url, headers=headers, json=payload, timeout=20, proxies=self.proxies, verify=False)
                if res.status_code == 200: return res.json()["choices"][0]["message"]["content"].strip()
                elif res.status_code == 429: time.sleep(15)
                else: break
            except: time.sleep(5)
        return None

    def phan_tich_bai_viet(self, text):
        if not text or len(text) < 10: return "LIKE", "Hay quá!"
        prompt = f"""
        Bạn là một người dùng Facebook GenZ thực thụ, nói chuyện tự nhiên, có thể viết tắt (teencode) nhẹ và dùng icon chính xác với ngữ cảnh.
        Bài viết vừa đọc: "{text}"
        Nhiệm vụ:
        1. Chọn 1 cảm xúc phù hợp (chỉ được chọn: LIKE, LOVE, HAHA, WOW, SAD, ANGRY - BẮT BUỘC VIẾT HOA).
        2. Viết 1 câu bình luận ngắn (dưới 15 chữ).
        Trả về ĐÚNG định dạng JSON (không kèm markdown):
        {{"reaction": "CẢM_XÚC_VIẾT_HOA", "comment": "NỘI_DUNG"}}
        """
        ket_qua = self._goi_ai(prompt)
        if ket_qua:
            try:
                data = json.loads(ket_qua.replace("```json", "").replace("```", "").strip())
                return data.get("reaction", "LIKE"), data.get("comment", "Hay quá!")
            except: pass
        return "LIKE", "Hay quá bạn ơi! ❤️"

    def tao_bai_dang(self, chu_de):
        prompt = f"""
        Bạn là một người dùng Facebook GenZ Việt Nam.
        Viết bài đăng Facebook về chủ đề: "{chu_de}".
        Yêu cầu: 3-5 câu, phong cách GenZ, tình cảm, tự nhiên, có thể dùng teencode. Thêm icon chính xác.
        TUYỆT ĐỐI KHÔNG tự bịa hashtag linh tinh. Cuối bài CHỈ ĐƯỢC PHÉP dùng duy nhất hashtag: #teungheui_bot09
        """
        ket_qua = self._goi_ai(prompt)
        return ket_qua if ket_qua else f"Hôm nay thật tuyệt! #teungheui_bot09"

def tao_phien(c_dict, proxies=None):
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9"})
    for k, v in c_dict.items(): s.cookies.set(k, v, domain=".facebook.com")
    if proxies: s.proxies.update(proxies)
    return s

def lay_metadata(s, proxies=None):
    meta = {"fb_dtsg": None, "lsd": None}
    try:
        r = s.get("https://www.facebook.com/", timeout=15, proxies=proxies, verify=False)
        m = re.search(r'"DTSGInitialData":\{"token":"(.*?)"', r.text) or re.search(r'\["DTSGInitialData",\[\],\{"token":"(.*?)"\}', r.text)
        if m: meta["fb_dtsg"] = m.group(1)
        m = re.search(r'"LSD":\{"token":"(.*?)"', r.text) or re.search(r'\["LSD",\[\],\{"token":"(.*?)"\}', r.text)
        if m: meta["lsd"] = m.group(1)
    except: pass
    if not meta["fb_dtsg"]:
        try:
            r = s.get("https://business.facebook.com/", timeout=15, proxies=proxies, verify=False)
            m = re.search(r'name="fb_dtsg" value="([^"]+)"', r.text) or re.search(r'"DTSGInitialData",\[\],\{"token":"([^"]+)"', r.text)
            if m: meta["fb_dtsg"] = m.group(1)
        except: pass
    return meta

def get_feed_posts(session, uid, fb_dtsg, jazoest, lsd, proxies=None):
    url = "https://www.facebook.com/api/graphql/"
    headers = {"content-type": "application/x-www-form-urlencoded", "x-fb-friendly-name": "CometNewsFeedPaginationQuery", "x-fb-lsd": lsd if lsd else "", "origin": "https://www.facebook.com", "referer": "https://www.facebook.com/"}
    variables = {"count": 10, "cursor": None, "feedLocation": "NEWSFEED", "feedbackSource": 1, "orderby": ["TOP_STORIES"], "renderLocation": "homepage_stream", "scale": 3, "stream_initial_count": 1, "useDefaultActor": False}
    data = {"av": uid, "fb_dtsg": fb_dtsg, "jazoest": jazoest, "lsd": lsd, "__user": uid, "__a": "1", "fb_api_caller_class": "RelayModern", "fb_api_req_friendly_name": "CometNewsFeedPaginationQuery", "variables": json.dumps(variables, separators=(',', ':')), "doc_id": "29228242493495109", "server_timestamps": "true"}
    try:
        res = session.post(url, headers=headers, data=data, timeout=15, proxies=proxies, verify=False)
        posts = []
        for line in res.text.splitlines():
            try: obj = json.loads(line)
            except: continue
            def extract(o):
                if isinstance(o, dict):
                    if "post_id" in o and isinstance(o["post_id"], str):
                        msg = ""
                        if isinstance(o.get("message"), dict) and "text" in o["message"]:
                            msg = o["message"]["text"]
                        posts.append((o["post_id"], msg))
                    for v in o.values(): extract(v)
                elif isinstance(o, list):
                    for i in o: extract(i)
            extract(obj)
        unique_posts = []
        seen = set()
        for pid, msg in posts:
            if pid not in seen:
                seen.add(pid)
                unique_posts.append((pid, msg))
        return unique_posts
    except: return []

def graph_dang_bai(caption_text, token, proxies=None):
    url = "https://graph.facebook.com/v26.0/me/feed"
    try:
        res = requests.post(url, data={"caption": caption_text, "access_token": token}, timeout=15, proxies=proxies, verify=False)
        js = res.json()
        if "id" in js: return js["id"] 
        else: return None
    except Exception: return None

def graph_tha_cam_xuc(full_post_id, reaction_type, token, proxies=None):
    url = f"https://graph.facebook.com/v26.0/{full_post_id}/reactions"
    try: return requests.post(url, data={"type": reaction_type, "access_token": token}, timeout=15, proxies=proxies, verify=False).status_code == 200
    except: return False

def graph_comment(full_post_id, message, token, proxies=None):
    url = f"https://graph.facebook.com/v26.0/{full_post_id}/comments"
    try: return requests.post(url, data={"message": message, "access_token": token}, timeout=15, proxies=proxies, verify=False).status_code == 200
    except: return False

# ==========================================================
# PHẦN 4: API FLASK
# ==========================================================

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

@app.route('/api/get_accounts', methods=['GET'])
def get_accounts():
    return jsonify(load_db())

@app.route('/api/add_account', methods=['POST'])
def add_account():
    data = request.json
    uid = data.get('uid')
    password = data.get('pass')
    twofa = data.get('twofa')
    proxy = data.get('proxy', '')

    if not uid or not password:
        return jsonify({'success': False, 'error': 'Thiếu thông tin'})

    accounts = load_db()
    new_acc = {
        'id': str(uuid.uuid4())[:8],
        'uid': uid,
        'password': password,
        'twofa': twofa,
        'proxy': proxy,
        'fb_uid': None,
        'status': 'Mới thêm',
        'token_data': None
    }
    accounts.append(new_acc)
    save_db(accounts)
    return jsonify({'success': True})

@app.route('/api/check_proxy', methods=['POST'])
def api_check_proxy():
    data = request.json
    proxy_str = data.get('proxy')
    if not proxy_str: return jsonify({'success': False, 'error': 'Proxy rỗng'})
    
    proxies = tao_proxy(proxy_str)
    is_live, result = kiem_tra_proxy(proxy_str)
    if is_live:
        info = get_ip_info(proxies)
        return jsonify({'success': True, 'ip': result, 'country': info['country_code'], 'timezone': info['timezone']})
    else:
        return jsonify({'success': False, 'error': result})

@app.route('/api/delete_account/<acc_id>', methods=['DELETE'])
def delete_account(acc_id):
    accounts = load_db()
    accounts = [acc for acc in accounts if acc['id'] != acc_id]
    save_db(accounts)
    return jsonify({'success': True})

@app.route('/api/login_and_get_token', methods=['POST'])
def api_login_and_get_token():
    data = request.json
    acc_id = data.get('id')
    
    accounts = load_db()
    acc = next((a for a in accounts if a['id'] == acc_id), None)
    
    if not acc:
        return jsonify({'success': False, 'error': 'Không tìm thấy tài khoản'})

    if acc.get('token_data'):
        return jsonify({'success': True, 'message': 'Đã có session, giữ nguyên đăng nhập'})

    proxies = tao_proxy(acc.get('proxy'))
    if not proxies:
        return jsonify({'success': False, 'error': 'Vui lòng thêm Proxy (Bắt buộc để tránh bị block IP trên Render)'})

    try:
        fb = FacebookLogin(
            uid_phone_mail=acc['uid'], 
            password=acc['password'], 
            convert_all_tokens=True,
            twofactor_code=acc['twofa'],
            proxies=proxies
        )
        result = fb.login()
        
        if result['success']:
            for a in accounts:
                if a['id'] == acc_id:
                    a['fb_uid'] = result['cookies']['dict'].get('c_user', 'Unknown')
                    a['status'] = 'Đã login'
                    a['token_data'] = result
            save_db(accounts)
            return jsonify(result)
        else:
            return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get_token', methods=['POST'])
def api_get_token():
    data = request.json
    acc_id = data.get('id')
    accounts = load_db()
    acc = next((a for a in accounts if a['id'] == acc_id), None)
    
    if not acc: return jsonify({'success': False, 'error': 'Không tìm thấy tài khoản'})
    if not acc.get('token_data'): return jsonify({'success': False, 'error': 'Chưa có token. Vui lòng bấm Start lần đầu để login.'})

    return jsonify(acc['token_data'])

@app.route('/api/start_bot', methods=['POST'])
def start_bot():
    data = request.json
    acc_id = data.get('id')
    
    accounts = load_db()
    acc = next((a for a in accounts if a['id'] == acc_id), None)
    
    if not acc or not acc.get('token_data'):
        return jsonify({'success': False, 'error': 'Vui lòng login lấy token trước khi chạy bot.'})
    
    token_data = acc['token_data']
    token_eaaa = token_data['original_token']['access_token']
    cookie_dict = token_data['cookies']['dict']
    uid = cookie_dict.get("c_user", "0")
    proxies = tao_proxy(acc.get('proxy'))

    def run_bot():
        print(f"\n[{acc['uid']}] Bắt đầu nuôi acc...")
        session = tao_phien(cookie_dict, proxies=proxies)
        meta = lay_metadata(session, proxies=proxies)
        fb_dtsg, lsd = meta.get("fb_dtsg"), meta.get("lsd")
        
        if not fb_dtsg: 
            print(f"[{acc['uid']}] Lỗi: Không lấy được fb_dtsg.")
            return
            
        jazoest = "2" + "".join(str(ord(c)) for c in fb_dtsg)
        ai = FacebookAIBot(
            api_key="mstrl_N4uIpAyBTp3TNxDOPdLAfp64R1Sl9UVx_3DK7oj", 
            model_ai="mistral-tiny", 
            api_url="https://api.mistral.ai/v1/chat/completions",
            proxies=proxies
        )
        
        session_count = 0
        last_post_session = -12 

        while True:
            session_count += 1
            can_post = (session_count - last_post_session) >= 12

            if can_post:
                chu_de = random.choice(["tâm trạng", "tình yêu", "cuộc sống", "sự mệt mỏi", "niềm vui"])
                noi_dung = ai.tao_bai_dang(chu_de)
                if noi_dung:
                    post_id = graph_dang_bai(noi_dung, token_eaaa, proxies=proxies)
                    if post_id:
                        print(f"[{acc['uid']}] Đã đăng bài: {post_id}")
                        last_post_session = session_count
                time.sleep(random.uniform(120, 180)) 
            
            posts = get_feed_posts(session, uid, fb_dtsg, jazoest, lsd, proxies=proxies)
            if posts:
                so_lan_tuong_tac = random.randint(5, 7)
                selected_posts = random.sample(posts, min(len(posts), so_lan_tuong_tac))
                
                for pid, msg in selected_posts:
                    full_pid = f"{uid}_{pid}" if "_" not in pid else pid
                    time.sleep(random.uniform(10, 15))
                    
                    reaction, comment = ai.phan_tich_bai_viet(msg)
                    ok_rx = graph_tha_cam_xuc(full_pid, reaction, token_eaaa, proxies=proxies)
                    time.sleep(random.uniform(2, 4))
                    ok_cmt = graph_comment(full_pid, comment, token_eaaa, proxies=proxies)
                    
                    if ok_rx and ok_cmt:
                        print(f"[{acc['uid']}] Đã tương tác bài: {pid}")
                    
                    time.sleep(random.uniform(240, 300))

    thread = threading.Thread(target=run_bot)
    thread.start()
    
    return jsonify({'success': True, 'message': 'Bot đã bắt đầu chạy ngầm'})

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
