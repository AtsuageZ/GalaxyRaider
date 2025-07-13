import requests
import threading
import time
import os
import uuid
import random
import base64
import json
import string
import websocket
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import tls_client
import mimetypes #pfp
from itertools import cycle
import shutil
import tkinter.messagebox

RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
END = '\033[39m'

spamming = False
spammingOLD = False
stop_spamming = False  # 後のdm spammer
stop_custom_spam = False

PICTURE_FOLDER = 'avatar'

with open('tokens.txt', 'r') as file:
    tokens1 = [line.strip() for line in file]

TIMEnow = datetime.now()
BASE_URL = "https://discord.com/api/v9"
IMAGE_FOLDER = "avatar"

with open('tokens.txt', 'r') as f:
    tokens = [token.strip() for token in f.readlines()]
    
def load_tokens(filename="tokens.txt"):
    if not os.path.exists(filename):
        return []
    with open(filename, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def read_tokens(filename):
    with open(filename, 'r') as file:
        tokens2 = [line.strip() for line in file]
    return tokens2

def read_tokens_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            tokens = file.read().splitlines()
        return tokens
    except Exception as e:
        print(f"Failed to read tokens from file: {e}")
        return []

token_count = len(tokens)

def noncegen():
    return str((int(time.mktime(datetime.now().timetuple())) * 1000 - 1420070400000) * 4194304)

def nowtime():
    return time.strftime("%H:%M:%S")

def extract_invite_code(url):
    try:
        parsed_url = urlparse(url)
        path = parsed_url.path.strip('/')  
        if path.startswith('invite/'):
            return path.split('/')[-1]
        elif path:
            return path
        else:
            return None
    except Exception as e:
        print(f"Error extracting invite code: {e}")
        return None


def gradient_text(text, start_rgb, end_rgb):
    result = ""
    length = len(text)
    for i, char in enumerate(text):
        ratio = i / max(length - 1, 1)
        r = round(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * ratio)
        g = round(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * ratio)
        b = round(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * ratio)
        result += f"\033[38;2;{r};{g};{b}m{char}"
    return result + "\033[0m"

def center_ascii_art(text, start_rgb, end_rgb):
    lines = text.splitlines()
    lines = [line.rstrip() for line in lines if line.strip() != '']
    max_len = max(len(line) for line in lines)
    term_width = shutil.get_terminal_size().columns

    centered_lines = []
    for line in lines:
        padded_line = line.ljust(max_len)
        left_padding = max((term_width - max_len) // 2, 0)
        padded_line = " " * left_padding + padded_line
        colored = gradient_text(padded_line, start_rgb, end_rgb)
        centered_lines.append(colored)

    return "\n".join(centered_lines)

def center_text_by_width(text, width):
    if len(text) >= width:
        return text
    left_padding = (width - len(text)) // 2
    return " " * left_padding + text

def center_block(lines, total_width):
    max_len = max(len(line) for line in lines)
    result = []
    for line in lines:
        left_aligned = line.ljust(max_len)
        centered = left_aligned.center(total_width)
        result.append(centered)
    return "\n".join(result)

def create_session():
    session = tls_client.Session(
        client_identifier="chrome_124",
        random_tls_extension_order=True
    )
    session.headers.update({
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "accept": "*/*",
        "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        "accept-encoding": "gzip, deflate, br",
        "referer": "https://discord.com/",
        "origin": "https://discord.com",
        "x-discord-locale": "ja-JP",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    })

    return session

session = create_session()

def get_headers(token):
    cookies = get_discord_cookies()
    props = get_super_properties()
    return {
        "authority": "discord.com",
        "accept": "*/*",
        "accept-language": "ja-JP,ja;q=0.9",
        "authorization": token,
        "cookie": cookies,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9028 Chrome/108.0.5359.215 Electron/22.3.26 Safari/537.36",
        "x-discord-locale": "ja",
        'x-debug-options': 'bugReporterEnabled',
        "x-super-properties": props,
    }

def headers(token, cookies):
    return {
        "authority": "discord.com",
        "accept": "*/*",
        "accept-language": "ja",
        "authorization": token,
        "cookie": cookies,
        "content-type": "application/json",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "x-discord-locale": "ja",
        'x-debug-options': 'bugReporterEnabled',
        "x-super-properties": properties,
    }


def get_discord_cookies():
    try:
        response = requests.get("https://discord.com")
        if response.status_code == 200:
            return "; ".join(
                [f"{cookie.name}={cookie.value}" for cookie in response.cookies]
            ) + "; locale=en-US"
        else:
            return "__dcfduid=4e0a8d504a4411eeb88f7f88fbb5d20a; __sdcfduid=4e0a8d514a4411eeb88f7f88fbb5d20ac488cd4896dae6574aaa7fbfb35f5b22b405bbd931fdcb72c21f85b263f61400; __cfruid=f6965e2d30c244553ff3d4203a1bfdabfcf351bd-1699536665; _cfuvid=rNaPQ7x_qcBwEhO_jNgXapOMoUIV2N8FA_8lzPV89oM-1699536665234-0-604800000; locale=en-US"
    except Exception as e:
        print(f"(ERR) {e} (get_discord_cookies)")

cookies = get_discord_cookies()

def parse_cookie_string(cookie_str):
    cookies = {}
    for part in cookie_str.split("; "):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k] = v
    return cookies

def get_super_properties():
    try:
        payload = {
            "os": "Windows",
            "browser": "Discord Client",
            "release_channel": "stable",
            "client_version": "1.0.9028",
            "os_version": "10.0.19045",
            "system_locale": "en",
            "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9028 Chrome/108.0.5359.215 Electron/22.3.26 Safari/537.36",
            "browser_version": "22.3.26",
            "client_build_number": 256231,
            "native_build_number": 41936,
            "client_event_source": None,
        }
        properties = base64.b64encode(json.dumps(payload).encode()).decode()
        return properties
    except Exception as e:
        print(f"(ERR) {e} (get_super_properties)")

properties = get_super_properties()

def check_token_in_guild(token, guild_id):
    headers = {"Authorization": token, "Content-Type": "application/json"}
    try:
        response = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}", headers=headers, timeout=5)
        if response.status_code == 200:
            print(GREEN + f"Token {token[:25]}... is in guild {guild_id}" + END)
            return True
        else:
            print(YELLOW + f"Token {token[:25]}... not in guild {guild_id} (Status: {response.status_code})" + END)
            return False
    except requests.exceptions.RequestException as e:
        print(RED + f"Error checking token {token[:25]}...: {e}" + END)
        return False

def check_tokens_in_guild_multithread(tokens, guild_id, max_workers=10):
    valid_tokens = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_token = {executor.submit(check_token_in_guild, token, guild_id): token for token in tokens}

        for future in as_completed(future_to_token):
            token = future_to_token[future]
            try:
                if future.result():
                    valid_tokens.append(token)
            except Exception as e:
                print(RED + f"Exception for token {token[:25]}...: {e}" + END)
    
    return valid_tokens

joined_tokens = []

layor = 0

# クラス系は全部スキッド
class Utils:
    @staticmethod
    def get_ranges(start, step, total):
        ranges = []
        for i in range(start, total, step):
            ranges.append([i, min(i + step - 1, total - 1)])
        return ranges

    @staticmethod
    def parse_member_list_update(decoded):
        data = decoded["d"]
        return {
            "guild_id": data["guild_id"],
            "types": [op["op"] for op in data["ops"]],
            "updates": [op.get("items", []) for op in data["ops"]]
        }

class DiscordSocket(websocket.WebSocketApp):
    def __init__(self, token, guild_id, channel_id):
        self.token = token
        self.guild_id = guild_id
        self.channel_id = channel_id
        self.blacklisted_ids = {"1100342265303547924", "1190052987477958806", "833007032000446505", 
                                "1273658880039190581", "1308012310396407828", "1326906424873193586", 
                                "1334512667456442411"}
        self.members = {}
        self.guilds = {}
        self.ranges = [[0, 0]]
        self.last_range = 0
        self.packets_recv = 0
        self.end_scraping = False

        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }

        super().__init__(
            "wss://gateway.discord.gg/?encoding=json&v=9",
            header=headers,
            on_open=self.on_open,
            on_message=self.on_message,
            on_close=self.on_close,
            on_error=self.on_error,
        )

    def run(self):
        print(f"Starting WebSocket for guild {self.guild_id} with token {self.token[:25]}...")
        self.run_forever()
        self.save_members_to_file()
        return self.members

    def save_members_to_file(self):
        try:
            os.makedirs("pings", exist_ok=True)
            filepath = f"pings/{self.guild_id}.txt"
            with open(filepath, "w", encoding="utf-8") as f:
                if not self.members:
                    print(YELLOW + f"No members scraped for guild {self.guild_id}" + END)
                    f.write("")
                else:
                    for user_id in self.members.keys():
                        f.write(f"{user_id}\n")
                    print(GREEN + f"Saved {len(self.members)} member IDs to {filepath}" + END)
        except Exception as e:
            print(RED + f"Failed to save members to file: {e}" + END)

    def scrape_users(self):
        if not self.end_scraping:
            print(f"Scraping users with range {self.ranges}")
            self.send(json.dumps({
                "op": 14,
                "d": {
                    "guild_id": self.guild_id,
                    "typing": True,
                    "activities": True,
                    "threads": True,
                    "channels": {self.channel_id: self.ranges}
                }
            }))

    def on_open(self, ws):
        print(GREEN + "WebSocket connection opened" + END)
        self.send(json.dumps({
            "op": 2,
            "d": {
                "token": self.token,
                "capabilities": 125,
                "properties": {
                    "os": "Windows",
                    "browser": "Chrome",
                    "browser_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                },
                "presence": {"status": "online", "since": 0, "activities": [], "afk": False},
                "compress": False,
            }
        }))

    def heartbeat_thread(self, interval):
        while not self.end_scraping:
            self.send(json.dumps({"op": 1, "d": self.packets_recv}))
            time.sleep(interval)

    def on_message(self, ws, message):
        decoded = json.loads(message)
        if not decoded:
            return
        self.packets_recv += decoded["op"] != 11
        if decoded["op"] == 10:
            threading.Thread(target=self.heartbeat_thread, args=(decoded["d"]["heartbeat_interval"] / 1000,), daemon=True).start()
            print(f"Heartbeat interval set to {decoded['d']['heartbeat_interval'] / 1000} seconds")
        if decoded["t"] == "READY":
            self.guilds.update({guild["id"]: {"member_count": guild["member_count"]} for guild in decoded["d"]["guilds"]})
            print(f"Guilds loaded: {self.guilds}")
        if decoded["t"] == "READY_SUPPLEMENTAL":
            self.ranges = Utils.get_ranges(0, 100, self.guilds.get(self.guild_id, {"member_count": 0})["member_count"])
            self.scrape_users()
        elif decoded["t"] == "GUILD_MEMBER_LIST_UPDATE":
            parsed = Utils.parse_member_list_update(decoded)
            if parsed["guild_id"] == self.guild_id:
                self.process_updates(parsed)

    def process_updates(self, parsed):
        if "SYNC" in parsed["types"] or "UPDATE" in parsed["types"]:
            for i, update_type in enumerate(parsed["types"]):
                if update_type in {"SYNC", "UPDATE"}:
                    if not parsed["updates"][i]:
                        self.end_scraping = True
                        print(YELLOW + "No more updates, ending scrape" + END)
                        break
                    self.process_members(parsed["updates"][i])
                self.last_range += 1
                self.ranges = Utils.get_ranges(self.last_range, 100, self.guilds.get(self.guild_id, {"member_count": 0})["member_count"])
                time.sleep(0.65)
                self.scrape_users()
        if self.end_scraping:
            self.close()

    def process_members(self, updates):
        for item in updates:
            member = item.get("member")
            if member:
                user = member.get("user", {})
                user_id = user.get("id")
                if user_id and user_id not in self.blacklisted_ids and not user.get("bot"):
                    self.members[user_id] = {"tag": f"{user.get('username')}#{user.get('discriminator')}", "id": user_id}
        print(f"Processed members, current count: {len(self.members)}")

    def on_close(self, ws, close_code, close_msg):
        print(GREEN + f"WebSocket closed. Scraped {len(self.members)} members" + END)

    def on_error(self, ws, error):
        print(RED + f"WebSocket error: {error}" + END)

def load_members_from_file(guild_id):
    filepath = f"pings/{guild_id}.txt"
    member_ids = []
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            member_ids = [line.strip() for line in f if line.strip()]
        print(GREEN + "[SUCCESS]" + gradient_text(f" Loaded {len(member_ids)} member IDs from {filepath}", (180, 0, 255), (255, 255, 255)))
    else:
        print(YELLOW + "[WARNING]" + gradient_text(f" Member file not found for guild {guild_id}", (255, 165, 0), (255, 255, 255)))
    return member_ids

def join_discord_server(token, invite):
    session = create_session()
    payload = {"session_id": uuid.uuid4().hex}
    hide_token = token[:25].rstrip() + '#'

    try:
        response = session.post(
            f"https://discord.com/api/v9/invites/{invite}",
            headers=get_headers(token),
            json=payload
        )

        if response.status_code == 200:
            guild = response.json().get('guild', {}).get('name', 'Unknown Server')
            status = GREEN + "[SUCCESS]" + gradient_text(f" {hide_token} {invite} | {guild}", (180, 0, 255), (255, 255, 255))
        elif response.status_code == 400:
            status = YELLOW + "[CAPTCHA]" + gradient_text(f" {hide_token} {invite}", (255, 165, 0), (255, 255, 255))
        elif response.status_code == 429:
            status = YELLOW + "[RATELIMIT]" + gradient_text(f" {hide_token} {invite}", (255, 165, 0), (255, 255, 255))
        else:
            status = RED + "[ERROR]" + gradient_text(f" {hide_token} {invite} | Status: {response.status_code} - {response.text}", (255, 0, 0), (255, 255, 255))

    except Exception as e:
        status = RED + "[EXCEPTION]" + gradient_text(f" {hide_token} {invite} | {str(e)}", (255, 0, 0), (255, 255, 255))

    return status

def joiner(tokens, invite_code, delay=2, max_workers=10):
    print(CYAN + "[INFO]" + gradient_text(" Starting join process...", (255, 165, 0), (255, 255, 255)))
    results = []

    def worker(token):
        status = join_discord_server(token, invite_code)
        time.sleep(delay)
        return status

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(worker, token): token for token in tokens}
        for future in as_completed(futures):
            try:
                result = future.result()
                print(result)
                results.append(result)
            except Exception as e:
                print(RED + "[THREAD ERROR]" + gradient_text(f" {str(e)}", (255, 0, 0), (255, 255, 255)))

    return results

spamming = False

def generate_random_string(length=6):
    return ''.join(random.choices(string.ascii_letters, k=length))



def spammer(channel_id, message, guild_id=None, mass_ping=False, ping_count=0, random_string=False):
    os.system('title Galaxy Raider - Spammer discord.gg/hikakin')
    global spamming
    spamming = True

    valid_tokens = check_tokens_in_guild_multithread(tokens, guild_id) if guild_id else tokens
    if not valid_tokens:
        print(RED + "No valid tokens found for this guild. Aborting." + END)
        return

    member_ids = []
    if mass_ping and guild_id:
        member_ids = load_members_from_file(guild_id)
        if not member_ids:
            print(YELLOW + "No members found. Scraping now with a valid token..." + END)
            socket = DiscordSocket(valid_tokens[0], guild_id, channel_id)
            threading.Thread(target=socket.run, daemon=True).start()
            time.sleep(15)
            member_ids = list(socket.members.keys())

    def send_message_with_token(token, message_content):
        hide_token = token[:25].rstrip() + '#'
        gradient_hide_token1 = gradient_text(hide_token, (180, 0, 255), (255, 255, 255))
        gradient_hide_token2 = gradient_text(hide_token, (255, 0, 0), (255, 255, 255))
        gradient_hide_token3 = gradient_text(hide_token, (255, 165, 0), (255, 255, 255))
        headers = {'Authorization': token, 'Content-Type': 'application/json'}
        data = {'content': message_content}
        try:
            response = requests.post(f'https://discord.com/api/v9/channels/{channel_id}/messages', headers=headers, json=data)
            if response.status_code == 200:
                print(GREEN + "[Success!]" + gradient_hide_token1 + END)
            elif response.status_code == 429:
                print(YELLOW + "[RATELIMIT] : " + gradient_hide_token3 + END)
            elif response.status_code in [401, 403]:
                print(RED + f'Missing access {gradient_hide_token2}' + END)
            else:
                print(f'Failed to send message with token {hide_token}. Status code: {response.status_code}')
        except requests.exceptions.RequestException as e:
            print(f'Error occurred with token {hide_token}: {str(e)}')

    def spam_loop():
        with ThreadPoolExecutor(max_workers=len(valid_tokens)) as executor:
            while spamming:
                final_messages = []
                for token in valid_tokens:
                    final_message = message
                    if mass_ping and member_ids:
                        pings = [f"<@{random.choice(member_ids)}>" for _ in range(min(ping_count, len(member_ids)))]
                        final_message = f"{message} {' '.join(pings)}"
                    if random_string:
                        final_message = f"{final_message} {generate_random_string()}"
                    final_messages.append((token, final_message))
                futures = [executor.submit(send_message_with_token, t, m) for t, m in final_messages]
                for future in as_completed(futures):
                    pass

    threading.Thread(target=spam_loop, daemon=True).start()

def write_tokens(filename, tokens):
    with open(filename, 'w') as file:
        file.write("\n".join(tokens))

def is_token_valid(token):
    headers = {'Authorization': token}
    try:
        response = requests.get('https://discord.com/api/v9/users/@me/library', headers=headers)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(nowtime() + RED + "[ERROR]" + gradient_text(f" Unable to check token: {token}. {str(e)}", (255, 0, 0), (255, 255, 255)))
        return False

def check_and_remove_invalid_tokens():
    global tokens
    valid_tokens = []
    invalid_tokens = []

    def check_token(token):
        hide_token = token[:25].rstrip() + '#'
        if is_token_valid(token):
            valid_tokens.append(token)
            print(nowtime() + GREEN + "[SUCCESS]" + gradient_text(f" Valid token: {hide_token}", (180, 0, 255), (255, 255, 255)))
        else:
            invalid_tokens.append(token)
            print(nowtime() + RED + "[INVALID]" + gradient_text(f" Token is invalid: {token}", (255, 0, 0), (255, 255, 255)))

    threads = []
    for token in tokens:
        thread = threading.Thread(target=check_token, args=(token,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    write_tokens('tokens.txt', valid_tokens)
    if invalid_tokens:
        with open('invalid_tokens.txt', 'w') as file:
            file.write("\n".join(invalid_tokens))

    removed_count = len(tokens) - len(valid_tokens)
    tkinter.messagebox.showinfo("Info", f"Token check completed. Removed {removed_count} invalid tokens.")

    if removed_count > 0:
        print(YELLOW + "[INFO]" + gradient_text(f" Removed {removed_count} invalid tokens.", (255, 165, 0), (255, 255, 255)))
        tokens = valid_tokens

        with open('tokens.txt', 'w') as f:
            f.write('\n'.join(tokens))

        print(GREEN + "[SUCCESS]" + gradient_text(" tokens.txt has been updated.", (180, 0, 255), (255, 255, 255)))

def leaver(server_id):
    for token in tokens:
        hide_token = token[:25].rstrip() + '#'
        headers = {'Authorization': token}
        try:
            response = requests.delete(
                f'https://discord.com/api/v9/users/@me/guilds/{server_id}',
                headers=headers
            )

            if response.status_code == 204:
                print(f"\033[32m[SUCCESS]\033[0m {gradient_text(f'Left: {hide_token}', (180, 0, 255), (255, 255, 255))}")
            elif response.status_code == 401:
                print(f"\033[31m[INVALID TOKEN]\033[0m {gradient_text(hide_token, (180, 0, 255), (255, 255, 255))}")
            elif response.status_code == 403:
                print(f"\033[31m[FORBIDDEN]\033[0m {gradient_text(hide_token + ' → Access denied', (180, 0, 255), (255, 255, 255))}")
            elif response.status_code == 404:
                print(f"\033[33m[NOT IN GUILD]\033[0m {gradient_text(hide_token + ' → Already left or invalid guild', (180, 0, 255), (255, 255, 255))}")
            elif response.status_code == 429:
                print(f"\033[33m[RATELIMIT]\033[0m {gradient_text(hide_token + ' → Too many requests, slow down', (180, 0, 255), (255, 255, 255))}")
            else:
                print(f"\033[31m[UNKNOWN ERROR]\033[0m {gradient_text(f'{hide_token} → Status: {response.status_code}, Content: {response.text}', (180, 0, 255), (255, 255, 255))}")

        except requests.exceptions.RequestException as e:
            print(f"\033[31m[REQUEST ERROR]\033[0m {gradient_text(hide_token + f' → {str(e)}', (180, 0, 255), (255, 255, 255))}")
    
    
forbidden_channels = set()
    
def get_guild_channels(guild_id, token):
    cookies = get_discord_cookies()
    try:
        response = requests.get(f'https://discord.com/api/v9/guilds/{guild_id}/channels', headers=headers(token, cookies))
        if response.status_code == 200:
            return [channel for channel in response.json() if channel['type'] == 0 or channel['type'] == 5]
        else:
            print(RED + "[ERROR]" + gradient_text(f" Unable to fetch channels with token {token[:25]}... Status code: {response.status_code}", (255, 0, 0), (255, 255, 255)))
            return []
    except requests.exceptions.RequestException as e:
        print(RED + "[ERROR]" + gradient_text(f" Exception while fetching channels with token {token[:25]}: {str(e)}", (255, 0, 0), (255, 255, 255)))
        return []

def send_message(channel_id, header, message):
    nowtime = str(datetime.now())[:-7]
    data = {'content': message}

    try:
        response = requests.post(
            f"https://discord.com/api/v9/channels/{channel_id}/messages",
            headers=header,
            json=data
        )

        if response.status_code == 200:
            print(GREEN + "[SUCCESS]" + gradient_text(f" {nowtime} Message sent to channel {channel_id}", (180, 0, 255), (255, 255, 255)))
        elif response.status_code == 403:
            print(YELLOW + "[WARNING]" + gradient_text(f" {nowtime} No permission to send to channel {channel_id}. Skipping...", (255, 165, 0), (255, 255, 255)))
            forbidden_channels.add(channel_id)
        elif response.status_code == 404:
            print(YELLOW + "[WARNING]" + gradient_text(f" {nowtime} Channel {channel_id} not found. Skipping...", (255, 165, 0), (255, 255, 255)))
            forbidden_channels.add(channel_id)
        elif response.status_code == 429:
            retry_after = response.json().get('retry_after', 1)
            print(YELLOW + "[RATELIMIT]" + gradient_text(f" {nowtime} Retry after {retry_after} seconds...", (255, 165, 0), (255, 255, 255)))
            time.sleep(retry_after)
            send_message(channel_id, header, message)
        else:
            print(RED + "[ERROR]" + gradient_text(f" {nowtime} Failed to send message: {response.status_code} - {response.text}", (255, 0, 0), (255, 255, 255)))
    except requests.exceptions.RequestException as e:
        print(RED + "[ERROR]" + gradient_text(f" {nowtime} Exception while sending message: {str(e)}", (255, 0, 0), (255, 255, 255)))

def worker(channel_id, header, message):
    send_message(channel_id, header, message)

def all_channel_spam(server_id, message, mass_ping=False, ping_count=0, random_string=False, messages_per_second=1.0):
    global stop_spammer
    stop_spammer = False

    if messages_per_second > 10.0:
        print(YELLOW + "[WARNING]" + gradient_text(" Sending more than 10 messages/sec may hit rate limits.", (255, 165, 0), (255, 255, 255)))

    valid_tokens = check_tokens_in_guild_multithread(tokens, server_id)
    if not valid_tokens:
        print(RED + "[ERROR]" + gradient_text(f" No valid tokens found for guild {server_id}. Aborting.", (255, 0, 0), (255, 255, 255)))
        return

    member_ids = []
    if mass_ping:
        member_ids = load_members_from_file(server_id)
        if not member_ids:
            print(YELLOW + "[WARNING]" + gradient_text(f" No members found for guild {server_id}. Scraping now...", (255, 165, 0), (255, 255, 255)))
            valid_token = valid_tokens[0]
            channels = get_guild_channels(server_id, valid_token)
            if not channels:
                print(RED + "[ERROR]" + gradient_text(f" No valid channels found for guild {server_id}. Aborting.", (255, 0, 0), (255, 255, 255)))
                return
            channel_id = channels[0]['id']
            socket = DiscordSocket(valid_token, server_id, channel_id)
            threading.Thread(target=socket.run, daemon=True).start()
            time.sleep(15)
            member_ids = list(socket.members.keys())
            if not member_ids:
                print(RED + "[ERROR]" + gradient_text(f" Failed to scrape members for guild {server_id}. Disabling mass ping.", (255, 0, 0), (255, 255, 255)))
                mass_ping = False

    token_cycle = cycle(valid_tokens)
    max_workers = min(500, len(valid_tokens) * 10)
    sleep_interval = 1.0 / max(messages_per_second, 0.1)

    while not stop_spammer:
        token = next(token_cycle)
        channels = get_guild_channels(server_id, token)
        if not channels:
            print(YELLOW + "[WARNING]" + gradient_text(f" No valid channels found for token {token[:25]}... Skipping.", (255, 165, 0), (255, 255, 255)))
            continue

        text_channels = [ch for ch in channels if ch.get('type') == 0 and ch.get('id') not in forbidden_channels]
        if not text_channels:
            print(YELLOW + "[WARNING]" + gradient_text(f" No valid text channels found for token {token[:25]}...", (255, 165, 0), (255, 255, 255)))
            continue

        final_message = message
        if mass_ping and member_ids:
            pings = [f"<@{random.choice(member_ids)}>" for _ in range(min(ping_count, len(member_ids)))]
            final_message = f"{message} {' '.join(pings)}"
        if random_string:
            final_message = f"{final_message} {generate_random_string()}"

        cookies = get_discord_cookies()
        header = headers(token, cookies)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(send_message, channel['id'], header, final_message)
                for channel in text_channels
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(RED + "[ERROR]" + gradient_text(f" Thread error: {e}", (255, 0, 0), (255, 255, 255)))

        if stop_spammer:
            break
        time.sleep(sleep_interval)

    print(GREEN + "[SUCCESS]" + gradient_text(" All channel spam stopped.", (180, 0, 255), (255, 255, 255)))

def stop_all_channel_spam():
    global stop_spammer
    stop_spammer = True


def change_status(token, activity_name):
    url = "wss://gateway.discord.gg/?v=9&encoding=json"
    
    def on_message(ws, message):
        message_data = json.loads(message)
        
        if message_data.get("op") == 10:
            heartbeat_interval = message_data["d"]["heartbeat_interval"] / 1000
            heartbeat_thread = threading.Thread(target=send_heartbeat, args=(ws, heartbeat_interval))
            heartbeat_thread.start()
            identify_payload = {
                "op": 2,
                "d": {
                    "token": token,
                    "intents": 513, 
                    "properties": {
                        "$os": "linux",
                        "$browser": "chrome",
                        "$device": "pc"
                    },
                    "presence": {
                        "status": "online",
                        "activities": [
                            {
                                "name": activity_name,
                                "type": 0
                            }
                        ]
                    }
                }
            }
            ws.send(json.dumps(identify_payload))
    
    def on_error(ws, error):
        print(f"Error occurred: {error}")
    
    def on_close(ws, close_status_code, close_msg):
        print(f"closed: {close_status_code} - {close_msg}")
    
    def on_open(ws):
        hide_token = token[:25].rstrip() + "#"
        print(f"\033[32m[ONLINED]\033[0m {gradient_text(hide_token, (180, 0, 255), (255, 255, 255))}")
    
    def send_heartbeat(ws, interval):
        while True:
            time.sleep(interval)
            ws.send(json.dumps({"op": 1, "d": None}))
    
    ws = websocket.WebSocketApp(url,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close,
                                on_open=on_open)
    
    ws.run_forever()

def change_status_wrapper(activity_name):
    tokens = read_tokens('tokens.txt')
    for token in tokens:
        threading.Thread(target=change_status, args=(token, activity_name)).start()

def send_vote(token, channel_id, poll_id, answer_ids):
    headers = get_headers(token)
    url = f"https://discord.com/api/v9/channels/{channel_id}/polls/{poll_id}/answers/@me"
    data = {"answer_ids": answer_ids}

    try:
        response = requests.put(url, headers=headers, json=data)
        hide_token = token[:25].rstrip() + "#"
        if response.status_code == [200, 204]:
            print(GREEN + "[VOTE OK]" + MAGENTA + hide_token + END)
        elif response.status_code == 429:
            print(YELLOW + "[RATELIMIT] : " + MAGENTA + hide_token + END)
        elif response.status_code in [401, 403]:
            print(RED + "[DIED TOKEN] " + hide_token + END)
        else:
            print(RED + f"[FAILED] {response.status_code} " + hide_token + END)
    except Exception as e:
        print(RED + f"[ERROR] {str(e)}" + END)

def poll_sender(channel_id, poll_id, answer_id):
    os.system('title Galaxy Raider - Poll Sender discord.gg/hikakin')
    global spamming
    spamming = True
    tokens = load_tokens()

    def loop():
        with ThreadPoolExecutor(max_workers=len(tokens)) as executor:
            while spamming:
                futures = [executor.submit(send_vote, token, channel_id, poll_id, [answer_id]) for token in tokens]
                for future in as_completed(futures):
                    pass
                time.sleep(3)

    threading.Thread(target=loop, daemon=True).start()












#CUICUICUICUICUICUICUICUICUICUICUICUICUICCUICUICUICUICUICUCI
base_input = gradient_text("   root@114.514.1919$~ → ", (180, 0, 255), (255, 255, 255))

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def joiner_cui():
    while True:
        clear()
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))

        invite_link = input(base_input + gradient_text("Invite Link » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        invite_code = extract_invite_code(invite_link)
        if not invite_code:
            print(RED + "Invalid invite link" + END)
            input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
            return

        one_token = input(base_input + gradient_text("Use single token? (y/n) » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        delay_input = input(base_input + gradient_text("Join interval per token (seconds, default: 2) » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        delay = float(delay_input) if delay_input.replace(".", "", 1).isdigit() else 2.0

        print(base_input + gradient_text("Start joining process...", (180, 0, 255), (255, 255, 255)))

        if one_token == 'y':
            token = input(base_input + gradient_text("Token » ", (180, 0, 255), (255, 255, 255))).lower().strip()
            joiner(token, invite_code, delay)
        else:
            print(f"{CYAN}Loaded Tokens: {len(tokens)}{END}")
            for token in tokens:
                joiner(token, invite_code, delay)

        input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
        return

def spam_cui():
    while True:
        clear()
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))

        channel_id = input(base_input + gradient_text("Channel ID » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        message = input(base_input + gradient_text("Message » ", (180, 0, 255), (255, 255, 255))).lower().strip()

        guild_id_input = input(base_input + gradient_text("Mass ping (y/n) » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        if guild_id_input == 'y':
            guild_id = input(base_input + gradient_text("Guild ID » ", (180, 0, 255), (255, 255, 255))).lower().strip()
            mass_ping = True
        else:
            guild_id = None
            mass_ping = False

        ping_count = 0
        if mass_ping:
            ping_count_input = input(base_input + gradient_text("Mention count » ", (180, 0, 255), (255, 255, 255))).lower().strip()
            ping_count = int(ping_count_input) if ping_count_input.isdigit() else 5

        random_str_input = input(base_input + gradient_text("Random string (y/n) » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        random_string = random_str_input == 'y'

        print("\nTerminate with Ctrl+C\n")

        spammer(
            channel_id=channel_id,
            message=message,
            guild_id=guild_id,
            mass_ping=mass_ping,
            ping_count=ping_count,
            random_string=random_string
        )

        input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
        return

def tokenchecker_cui():
    global tokens
    tokens = load_tokens("tokens.txt")

    while True:
        clear()
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))
        print(f"{CYAN}Loaded tokens: {len(tokens)}{END}\n")

        check_and_remove_invalid_tokens()

        input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
        return

def leaver_cui():
    while True:
        clear()
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))

        server_id = input(base_input + gradient_text("Guild ID » ", (180, 0, 255), (255, 255, 255))).strip()
        leaver(server_id)

        input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
        return

def all_channel_spam_cui():
    while True:
        clear()
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))

        server_id = input(base_input + gradient_text("Server ID » ", (180, 0, 255), (255, 255, 255))).strip()
        message = input(base_input + gradient_text("Message » ", (180, 0, 255), (255, 255, 255))).strip()

        mass_ping_input = input(base_input + gradient_text("Mass ping? (y/n) » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        mass_ping = mass_ping_input == 'y'

        ping_count = 0
        if mass_ping:
            ping_count_input = input(base_input + gradient_text("Mention count » ", (180, 0, 255), (255, 255, 255))).strip()
            ping_count = int(ping_count_input) if ping_count_input.isdigit() else 5

        random_str_input = input(base_input + gradient_text("Add random string? (y/n) » ", (180, 0, 255), (255, 255, 255))).lower().strip()
        random_string = random_str_input == 'y'

        rate_input = input(base_input + gradient_text("Messages per second (default: 1.0) » ", (180, 0, 255), (255, 255, 255))).strip()
        messages_per_second = float(rate_input) if rate_input.replace('.', '', 1).isdigit() else 1.0

        print(base_input + gradient_text("Start spamming all text channels...", (180, 0, 255), (255, 255, 255)))
        all_channel_spam(
            server_id=server_id,
            message=message,
            mass_ping=mass_ping,
            ping_count=ping_count,
            random_string=random_string,
            messages_per_second=messages_per_second
        )

        input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
        return

def onliner_cui():
    while True:
        clear()
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))
        activity_name = input(base_input + gradient_text("Activity name » ", (180, 0, 255), (255, 255, 255))).strip()

        change_status_wrapper(activity_name)

        input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
        return

def poll_sender_cui():
    while True:
        clear()
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))

        ch_id = input(base_input + gradient_text("Channel ID » ", (180, 0, 255), (255, 255, 255))).strip()
        poll_id = input(base_input + gradient_text("Poll ID » ", (180, 0, 255), (255, 255, 255))).strip()
        ans_id = input(base_input + gradient_text("Answer ID » ", (180, 0, 255), (255, 255, 255))).strip()

        poll_sender(ch_id, poll_id, ans_id)

        input(base_input + gradient_text("Press Enter to return to the main menu...", (180, 0, 255), (255, 255, 255)))
        return

#MENUMENUMENUMENUMENUMENUMENUMENUMENUMENUMENUMENU    



if __name__ == "__main__":
    ascii_art = r"""
   _____       _                    _____       _     _           
  / ____|     | |                  |  __ \     (_)   | |          
 | |  __  __ _| | __ ___  ___   _  | |__) |__ _ _  __| | ___ _ __ 
 | | |_ |/ _` | |/ _` \ \/ / | | | |  _  // _` | |/ _` |/ _ \ '__|
 | |__| | (_| | | (_| |>  <| |_| | | | \ \ (_| | | (_| |  __/ |   
  \_____|\__,_|_|\__,_/_/\_\\__, | |_|  \_\__,_|_|\__,_|\___|_|   
                             __/ |                                
                            |___/                                                                      
    """

    menu_block = [
        "  [01] » Joiner              [06] » Onliner             [11] »                      [16] »              ",
        "  [02] » Spammer             [07] » Poll Sender         [12] »                      [17] »              ",
        "  [03] » Checker             [08] »                     [13] »                      [18] »              ",
        "  [04] » Leaver              [09] »                     [14] »                      [19] »              ",
        "  [05] » Allchannel Spammer  [10] »                     [15] »                      [20] »              ",
        "",
    ]

    import shutil, os
    from time import sleep

    def clear():
        os.system("cls" if os.name == "nt" else "clear")

    def gradient_text(text, start_rgb, end_rgb):
        result = ""
        length = len(text)
        for i, char in enumerate(text):
            ratio = i / max(length - 1, 1)
            r = round(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * ratio)
            g = round(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * ratio)
            b = round(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * ratio)
            result += f"\033[38;2;{r};{g};{b}m{char}"
        return result + "\033[0m"

    def center_text_by_width(text, width):
        if len(text) >= width:
            return text
        left_padding = (width - len(text)) // 2
        return " " * left_padding + text

    def center_ascii_art(text, start_rgb, end_rgb):
        lines = text.splitlines()
        lines = [line.rstrip() for line in lines if line.strip() != '']
        max_len = max(len(line) for line in lines)
        term_width = shutil.get_terminal_size().columns
        centered_lines = []
        for line in lines:
            padded_line = line.ljust(max_len)
            left_padding = max((term_width - max_len) // 2, 0)
            padded_line = " " * left_padding + padded_line
            colored = gradient_text(padded_line, start_rgb, end_rgb)
            centered_lines.append(colored)
        return "\n".join(centered_lines)

    def center_block(lines, start_rgb, end_rgb):
        term_width = shutil.get_terminal_size().columns
        return "\n".join([gradient_text(center_text_by_width(line, term_width), start_rgb, end_rgb) for line in lines])

    while True:
        clear()
        os.system('title Galaxy Raider - discord.gg/hikakin')
        print(center_ascii_art(ascii_art, (180, 0, 255), (255, 255, 255)))
        print()
        print(center_block(menu_block, (180, 0, 255), (255, 255, 255)))

        prompt_text = gradient_text("   root@114.514.1919$~ » ", (180, 0, 255), (255, 255, 255))
        choice = input(prompt_text).strip()
        if choice == "1" or choice == "01":
            joiner_cui()
        elif choice == "2" or choice == "02":
            spam_cui()
        elif choice == "3" or choice == "03":
            tokenchecker_cui()
        elif choice == "4" or choice == "04":
            leaver_cui()
        elif choice == "5" or choice == "05":
            all_channel_spam_cui()
        elif choice == "6" or choice == "05":
            onliner_cui()
        elif choice == "7" or choice == "05":
            poll_sender_cui()
        elif choice == "0" or choice == "00":
            print("end")
            break
        else:
            print("Invalid selection")
            sleep(1)
