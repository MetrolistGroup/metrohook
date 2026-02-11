import html
import logging
import os
import re
import time
import traceback

import requests
from PIL import Image, ImageDraw, ImageFont
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- CONFIGURATION (loaded at runtime) ---
GITHUB_REPO = None
TELEGRAM_BOT_TOKEN = None
TELEGRAM_CHAT_ID = None
ADMIN_ID = None
AUTHORIZED_USERS = []

# --- SETTINGS ---
CHECK_INTERVAL = 300
COMMAND_CHECK_INTERVAL = 0.5
TIMEOUT = 10
STATE_FILE = "last_id.txt"

# --- DESIGN SETTINGS ---
BACKGROUND_IMAGE = "background.png"
FONT_FILE = "font.ttf"
RIGHT_EDGE_X = 1240
TEXT_Y = 120
FONT_SIZE = 75
TEXT_COLOR = "#e2e3e8"

# --- API URLs ---
TELEGRAM_API_BASE = None
GITHUB_API_URL = None

# --- PATTERNS ---
RE_MD_IMAGE = re.compile(r"!\[.*?\]\(.*?\)")
RE_FULL_CHANGELOG = re.compile(
    r"(\*\*)?Full Changelog(\*\*)?:\s*(https://[^\s]+)", re.IGNORECASE
)
RE_WHATS_CHANGED = re.compile(r"##\s+What(&#x27;|')?s Changed", re.IGNORECASE)

# --- DOWNLOAD MAPPING ---
DOWNLOAD_MAPPING = {
    "Metrolist.apk": "Universal",
    "Metrolist-with-Google-Cast.apk": "Universal (Google Cast)",
    "app-arm64-release.apk": "arm64-v8a",
    "app-arm64-with-Google-Cast.apk": "arm64-v8a (Google Cast)",
    "app-armeabi-release.apk": "armeabi-v7a",
    "app-armeabi-with-Google-Cast.apk": "armeabi-v7a (Google Cast)",
    "app-x86-release.apk": "x86",
    "app-x86-with-Google-Cast.apk": "x86 (Google Cast)",
    "app-x86_64-release.apk": "x86_64",
    "app-x86_64-with-Google-Cast.apk": "x86_64 (Google Cast)",
}

def build_session():
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
    )
    adapter = HTTPAdapter(max_retries=retries)
    sess = requests.Session()
    sess.headers.update({"User-Agent": "metrohook-bot/1.0"})
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess


session = build_session()
last_update_id = 0


def require_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def parse_csv_env(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


def init_config():
    global GITHUB_REPO
    global TELEGRAM_BOT_TOKEN
    global TELEGRAM_CHAT_ID
    global ADMIN_ID
    global AUTHORIZED_USERS
    global CHECK_INTERVAL
    global COMMAND_CHECK_INTERVAL
    global TIMEOUT
    global STATE_FILE
    global BACKGROUND_IMAGE
    global FONT_FILE
    global RIGHT_EDGE_X
    global TEXT_Y
    global FONT_SIZE
    global TEXT_COLOR
    global TELEGRAM_API_BASE
    global GITHUB_API_URL

    GITHUB_REPO = os.getenv("GITHUB_REPO", "MetrolistGroup/Metrolist")
    TELEGRAM_BOT_TOKEN = require_env("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_ID = require_env("TELEGRAM_CHAT_ID")
    ADMIN_ID = require_env("ADMIN_ID")
    AUTHORIZED_USERS = parse_csv_env("AUTHORIZED_USERS", [])

    CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "300"))
    COMMAND_CHECK_INTERVAL = float(os.getenv("COMMAND_CHECK_INTERVAL", "0.5"))
    TIMEOUT = int(os.getenv("TIMEOUT", "10"))
    STATE_FILE = os.getenv("STATE_FILE", "last_id.txt")

    BACKGROUND_IMAGE = os.getenv("BACKGROUND_IMAGE", "background.png")
    FONT_FILE = os.getenv("FONT_FILE", "font.ttf")
    RIGHT_EDGE_X = int(os.getenv("RIGHT_EDGE_X", "1240"))
    TEXT_Y = int(os.getenv("TEXT_Y", "120"))
    FONT_SIZE = int(os.getenv("FONT_SIZE", "75"))
    TEXT_COLOR = os.getenv("TEXT_COLOR", "#e2e3e8")

    TELEGRAM_API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
    GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}"


# --- ADMIN ALERTS ---
def send_alert(message):
    """Sends status updates only to the Admin."""
    try:
        url = f"{TELEGRAM_API_BASE}/sendMessage"
        data = {
            "chat_id": ADMIN_ID,
            "text": f"<b>🔔 System Alert:</b>\n{message}",
            "parse_mode": "HTML",
        }
        session.post(url, data=data, timeout=5)
    except:
        pass  # If we can't alert, stay silent


# --- STATE MANAGEMENT ---
def get_last_event_id():
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE, "r") as f:
        return f.read().strip()


def save_last_event_id(event_id):
    with open(STATE_FILE, "w") as f:
        f.write(str(event_id))


# --- BANNER LOGIC ---
def generate_banner(version_text):
    try:
        if not os.path.exists(BACKGROUND_IMAGE):
            send_alert(f"❌ Error: Missing {BACKGROUND_IMAGE}")
            return None

        with Image.open(BACKGROUND_IMAGE) as img:
            draw = ImageDraw.Draw(img)
            try:
                font = ImageFont.truetype(FONT_FILE, FONT_SIZE)
            except Exception:
                font = ImageFont.load_default()

            text_length = draw.textlength(version_text, font=font)
            final_x = RIGHT_EDGE_X - text_length

            draw.text((final_x, TEXT_Y), version_text, font=font, fill=TEXT_COLOR)

            temp_filename = "temp_banner.png"
            img.save(temp_filename)
        return temp_filename
    except Exception as e:
        send_alert(f"❌ Banner Error: {e}")
        return None


# --- TELEGRAM SENDERS ---
def send_photo(chat_id, caption, image_path):
    url = f"{TELEGRAM_API_BASE}/sendPhoto"
    data = {"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"}
    with open(image_path, "rb") as f:
        try:
            r = session.post(url, data=data, files={"photo": f}, timeout=TIMEOUT)
            if r.status_code != 200:
                send_alert(f"⚠️ Photo Send Failed: {r.text}")
        except Exception as e:
            send_alert(f"⚠️ Network Error (Photo): {e}")
    if os.path.exists(image_path):
        os.remove(image_path)


def send_message(chat_id, text):
    url = f"{TELEGRAM_API_BASE}/sendMessage"
    data = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        r = session.post(url, data=data, timeout=TIMEOUT)
        if r.status_code != 200:
            send_alert(f"⚠️ Message Send Failed: {r.text}")
    except Exception as e:
        send_alert(f"⚠️ Network Error (Message): {e}")


# --- DOWNLOAD LISTS ---
def generate_restricted_download_list(assets):
    links = []
    target_files = [
        ("Metrolist.apk", "Metrolist"),
        ("Metrolist-with-Google-Cast.apk", "Metrolist (with Google Cast)"),
    ]
    asset_map = {a["name"]: a["browser_download_url"] for a in assets}

    for filename, label in target_files:
        if filename in asset_map:
            links.append(f"- <a href='{asset_map[filename]}'>{label}</a>")

    return "\n".join(links)


def generate_full_download_list(assets):
    links = []
    asset_map = {a["name"]: a["browser_download_url"] for a in assets}

    for filename, label in DOWNLOAD_MAPPING.items():
        if filename in asset_map:
            links.append(f"- <a href='{asset_map[filename]}'>{label}</a>")

    if not links:
        return "No APKs found."
    return "\n".join(links)


# --- FORMATTING ---
def format_release_text(release):
    tag_name = release.get("tag_name", "v0.0.0")
    title = html.escape(release.get("name", "") or tag_name)
    release_page_url = release.get("html_url", "")

    raw_body = release.get("body", "") or ""
    raw_body = RE_MD_IMAGE.sub("", raw_body)
    desc = html.escape(raw_body.strip())

    desc = RE_FULL_CHANGELOG.sub(r'<a href="\3">Full Changelog</a>', desc)
    if RE_WHATS_CHANGED.search(desc):
        desc = RE_WHATS_CHANGED.sub("<b>What's Changed</b>", desc)
    else:
        desc = "<b>What's Changed</b>\n" + desc

    if len(desc) > 800:
        desc = desc[:800] + "..."

    download_list = generate_restricted_download_list(release.get("assets", []))
    footer_text = f"Not the architecture you wanted? Get it <a href='{release_page_url}'>here</a>."

    if download_list:
        msg = f"<b>{title}</b>\n\n{desc}\n\n<b>Download:</b>\n{download_list}\n\n{footer_text}"
    else:
        msg = f"<b>{title}</b>\n\n{desc}\n\n{footer_text}"

    return msg


# --- PROCESSORS ---
def process_release(chat_id, release):
    if "tag_name" not in release:
        return
    tag_name = release["tag_name"]
    clean_version = tag_name.lstrip("v").lstrip("V")

    img_path = generate_banner(clean_version)
    caption = format_release_text(release)

    if img_path:
        send_photo(chat_id, caption, img_path)
    else:
        send_message(chat_id, caption)


def process_simple_list(chat_id, release):
    if "tag_name" not in release:
        return
    tag_name = release["tag_name"]
    title = html.escape(release.get("name", "") or tag_name)

    download_list = generate_full_download_list(release.get("assets", []))
    msg = f"<b>{title}</b>\n\n<b>Downloads:</b>\n{download_list}"

    send_message(chat_id, msg)


# --- GITHUB API ---
def get_latest_release_data():
    url = f"{GITHUB_API_URL}/releases/latest"
    try:
        r = session.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                send_alert("⚠️ GitHub Error: Invalid JSON")
                return None
        send_alert(f"⚠️ GitHub Error: {r.status_code}")
        return None
    except Exception as e:
        send_alert(f"⚠️ Network Error (GitHub): {e}")
        return None


# --- COMMAND HANDLER ---
def handle_commands():
    global last_update_id
    url = f"{TELEGRAM_API_BASE}/getUpdates?offset={last_update_id + 1}"

    try:
        resp = session.get(url, timeout=TIMEOUT)
        try:
            data = resp.json()
        except ValueError:
            send_alert("⚠️ Telegram Error: Invalid JSON")
            return
        if not data.get("result"):
            return

        for update in data["result"]:
            last_update_id = update["update_id"]
            if "message" not in update or "text" not in update["message"]:
                continue

            chat_type = update["message"]["chat"].get("type", "private")
            if chat_type == "private":
                continue

            current_chat_id = update["message"]["chat"]["id"]
            text = update["message"]["text"].lower().strip()
            username = update["message"].get("from", {}).get("username", "Unknown")

            # --- COMMAND 1: !latest ---
            if text == "!latest":
                release = get_latest_release_data()
                if release:
                    process_simple_list(current_chat_id, release)
                else:
                    send_message(current_chat_id, "❌ Could not fetch release.")

            # --- COMMAND 2: !test ---
            elif text == "!test":
                if username in AUTHORIZED_USERS:
                    release = get_latest_release_data()
                    if release:
                        process_release(current_chat_id, release)
                else:
                    send_message(
                        current_chat_id,
                        "⛔ <b>Permission denied:</b> You are not an authorised person.",
                    )

    except Exception as e:
        if "Read timed out" not in str(e):
            send_alert(f"⚠️ Polling Error: {e}")


# --- AUTO-UPDATE LOGIC ---
def check_github_activity():
    url = f"{GITHUB_API_URL}/events"
    try:
        resp = session.get(url, timeout=TIMEOUT)
        if resp.status_code != 200:
            return
        try:
            events = resp.json()
        except ValueError:
            send_alert("⚠️ GitHub Error: Invalid JSON")
            return
        last_saved = get_last_event_id()

        if not last_saved:
            if events:
                save_last_event_id(events[0]["id"])
            return

        new_events = []
        for event in events:
            if str(event["id"]) == str(last_saved):
                break
            if (
                event["type"] == "ReleaseEvent"
                and event["payload"]["action"] == "published"
            ):
                new_events.append(event)

        for event in reversed(new_events):
            tag = event["payload"]["release"]["tag_name"]
            send_alert(f"🚀 New Release Detected: {tag}")
            process_release(TELEGRAM_CHAT_ID, event["payload"]["release"])
            save_last_event_id(event["id"])

    except Exception as e:
        send_alert(f"⚠️ Auto-Update Error: {e}")


# --- MAIN LOOP ---
if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        init_config()
    except Exception as exc:
        logging.error("Configuration error: %s", exc)
        raise SystemExit(1)

    send_alert("🤖 Bot is running...")
    last_check = 0
    while True:
        try:
            handle_commands()

            if time.time() - last_check > CHECK_INTERVAL:
                check_github_activity()
                last_check = time.time()

            time.sleep(COMMAND_CHECK_INTERVAL)

        except KeyboardInterrupt:
            send_alert("🛑 Bot stopped manually.")
            break
        except Exception as e:
            send_alert(f"🔥 Critical Crash:\n{traceback.format_exc()}")
            time.sleep(5)
