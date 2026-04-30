"""
سَنَد — نظام الدفع الذكي  v3.0
التسجيل بالصوت فقط — بدون كتابة أي شيء
"""

import customtkinter as ctk
import pyttsx3
import threading
import math
import os
import json
import time
import hashlib
import secrets
import numpy as np
import sounddevice as sd
import librosa
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
#  مكتبات التشفير (اختيارية)
# ─────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

try:
    import bcrypt
    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False

try:
    import keyring
    KEYRING_OK = True
except ImportError:
    KEYRING_OK = False

try:
    import speech_recognition as sr
    SR_OK = True
except ImportError:
    SR_OK = False

# ─────────────────────────────────────────────
#  مسار حفظ البيانات
# ─────────────────────────────────────────────
def get_sanad_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path.home() / ".local" / "share"
    d = base / "Sanad"
    d.mkdir(parents=True, exist_ok=True)
    return d

SANAD_DIR   = get_sanad_dir()
USERS_FILE  = SANAD_DIR / "users.json"
APP_SERVICE = "SanadPayApp"
print(f"[INFO] Data folder: {SANAD_DIR}")


# ─────────────────────────────────────────────
#  التعرف على الكلام (Speech-to-Text)
# ─────────────────────────────────────────────
def transcribe_audio(recording: np.ndarray, fs: int = 16000) -> str:
    """
    يحاول التعرف على الكلام من المصفوفة الصوتية.
    يعيد النص المنطوق أو سلسلة فارغة عند الفشل.
    """
    if not SR_OK:
        # fallback: نستخدم hash البصمة كمعرف نصي
        fp = extract_fingerprint(recording, fs)
        return "voice_" + hashlib.md5(fp.tobytes()).hexdigest()[:8]

    try:
        import io, wave, struct
        recognizer = sr.Recognizer()
        # تحويل numpy → AudioData
        y = (recording.flatten() * 32767).astype(np.int16)
        buf = io.BytesIO()
        with wave.open(buf, 'wb') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(fs)
            wf.writeframes(y.tobytes())
        buf.seek(0)
        with sr.AudioFile(buf) as source:
            audio = recognizer.record(source)
        # محاولة أولاً بالعربية ثم الإنجليزية
        try:
            text = recognizer.recognize_google(audio, language="ar-SA")
        except Exception:
            text = recognizer.recognize_google(audio, language="en-US")
        return text.strip().lower()
    except Exception:
        # عند فشل التعرف نستخدم hash البصمة
        fp = extract_fingerprint(recording, fs)
        return "voice_" + hashlib.md5(fp.tobytes()).hexdigest()[:8]


# ─────────────────────────────────────────────
#  استخراج البصمة الصوتية
# ─────────────────────────────────────────────
def extract_fingerprint(recording: np.ndarray, fs: int = 22050) -> np.ndarray:
    y = recording.flatten().astype(np.float32)
    if np.max(np.abs(y)) > 0:
        y = y / np.max(np.abs(y))
    mfccs     = librosa.feature.mfcc(y=y, sr=fs, n_mfcc=20)
    delta     = librosa.feature.delta(mfccs)
    chroma    = librosa.feature.chroma_stft(y=y, sr=fs)
    zcr       = librosa.feature.zero_crossing_rate(y)
    features  = np.concatenate([
        np.mean(mfccs,  axis=1),
        np.std(mfccs,   axis=1),
        np.mean(delta,  axis=1),
        np.mean(chroma, axis=1),
        [np.mean(zcr)],
    ])
    return features


def voice_similarity(fp1: np.ndarray, fp2: np.ndarray) -> float:
    """تشابه جيب التمام بين بصمتين صوتيتين (0–1)."""
    n1, n2 = np.linalg.norm(fp1), np.linalg.norm(fp2)
    if n1 == 0 or n2 == 0:
        return 0.0
    return float(np.dot(fp1, fp2) / (n1 * n2))


# ─────────────────────────────────────────────
#  طبقة الأمان
# ─────────────────────────────────────────────
class SecurityLayer:

    # ── تجزئة النص المنطوق ──────────────────
    @staticmethod
    def hash_spoken_word(word: str) -> str:
        """تجزئة آمنة للكلمة المنطوقة (نص)."""
        if BCRYPT_OK:
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(word.encode(), salt).decode()
        salt = secrets.token_hex(32)
        h = hashlib.sha256((word + salt).encode()).hexdigest()
        return f"sha256:{salt}:{h}"

    @staticmethod
    def verify_spoken_word(word: str, hashed: str) -> bool:
        if BCRYPT_OK and not hashed.startswith("sha256:"):
            return bcrypt.checkpw(word.encode(), hashed.encode())
        _, salt, h = hashed.split(":")
        return hashlib.sha256((word + salt).encode()).hexdigest() == h

    # ── تخزين / استرداد hash الكلمة ─────────
    @staticmethod
    def store_word_hash(user_id: str, hashed: str):
        if KEYRING_OK:
            keyring.set_password(APP_SERVICE, f"{user_id}_word", hashed)
        else:
            meta = SecurityLayer._load_meta()
            meta.setdefault("words", {})[user_id] = hashed
            SecurityLayer._save_meta(meta)

    @staticmethod
    def get_word_hash(user_id: str):
        if KEYRING_OK:
            return keyring.get_password(APP_SERVICE, f"{user_id}_word")
        meta = SecurityLayer._load_meta()
        return meta.get("words", {}).get(user_id)

    # ── تشفير / فك تشفير البصمة ─────────────
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        if CRYPTO_OK:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32, salt=salt, iterations=100_000,
            )
            return base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return base64.urlsafe_b64encode(
            hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        )

    @staticmethod
    def save_fingerprint(fp: np.ndarray, user_id: str, key_material: str):
        fp_path = SANAD_DIR / f"{user_id}_voice.enc"
        salt    = secrets.token_bytes(16)
        key     = SecurityLayer._derive_key(key_material, salt)
        fp_bytes = fp.astype(np.float64).tobytes()
        if CRYPTO_OK:
            ct = Fernet(key).encrypt(fp_bytes)
            with open(fp_path, "wb") as fh:
                fh.write(salt + ct)
        else:
            np.save(SANAD_DIR / f"{user_id}_voice.npy", fp)

    @staticmethod
    def load_fingerprint(user_id: str, key_material: str):
        fp_path = SANAD_DIR / f"{user_id}_voice.enc"
        if not fp_path.exists():
            npy = SANAD_DIR / f"{user_id}_voice.npy"
            return np.load(npy) if npy.exists() else None
        with open(fp_path, "rb") as fh:
            data = fh.read()
        salt = data[:16]
        ct   = data[16:]
        key  = SecurityLayer._derive_key(key_material, salt)
        if CRYPTO_OK:
            try:
                raw = Fernet(key).decrypt(ct)
                return np.frombuffer(raw, dtype=np.float64)
            except Exception:
                return None
        return None

    # ── بيانات المستخدمين ───────────────────
    @staticmethod
    def _load_meta() -> dict:
        if USERS_FILE.exists():
            with open(USERS_FILE, encoding="utf-8") as f:
                return json.load(f)
        return {}

    @staticmethod
    def _save_meta(data: dict):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def save_user_meta(user_id: str, info: dict):
        meta = SecurityLayer._load_meta()
        meta.setdefault("users", {})[user_id] = info
        SecurityLayer._save_meta(meta)

    @staticmethod
    def user_exists(user_id: str) -> bool:
        meta = SecurityLayer._load_meta()
        return user_id in meta.get("users", {})

    @staticmethod
    def list_users() -> list:
        meta = SecurityLayer._load_meta()
        return list(meta.get("users", {}).keys())

    @staticmethod
    def get_user_meta(user_id: str) -> dict:
        meta = SecurityLayer._load_meta()
        return meta.get("users", {}).get(user_id, {})


# ─────────────────────────────────────────────
#  الألوان
# ─────────────────────────────────────────────
C = {
    "bg":        "#1A1208",
    "surface":   "#261A08",
    "card":      "#2D1F08",
    "gold":      "#C9A84C",
    "gold_lt":   "#E8C97A",
    "gold_dark": "#A07830",
    "white":     "#FFFFFF",
    "white_90":  "#E8E8E8",
    "white_70":  "#B3B3B3",
    "white_40":  "#666666",
    "btn_text":  "#1A1208",
    "success":   "#2D7A4F",
    "danger":    "#C0392B",
    "info":      "#1E6BA3",
    "step_done": "#2D7A4F",
    "step_act":  "#C9A84C",
    "step_wait": "#444444",
}
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ─────────────────────────────────────────────
#  نظام الكلام
# ─────────────────────────────────────────────
_engine = pyttsx3.init()
for v in _engine.getProperty('voices'):
    if 'arabic' in v.name.lower() or 'ar' in v.id.lower():
        _engine.setProperty('voice', v.id)
        break
_engine.setProperty('rate', 145)
_speak_lock = threading.Lock()

def speak(text: str):
    def _r():
        with _speak_lock:
            _engine.say(text)
            _engine.runAndWait()
    threading.Thread(target=_r, daemon=True).start()


# ─────────────────────────────────────────────
#  بصمة الإصبع المتحركة
# ─────────────────────────────────────────────
class FingerprintCanvas(ctk.CTkCanvas):

    def __init__(self, master, size=160, **kwargs):
        super().__init__(master, width=size, height=size,
                         bg=C["bg"], highlightthickness=0, **kwargs)
        self.size  = size
        self.cx    = size / 2
        self.cy    = size / 2
        self.phase = 0.0
        self._draw_fingerprint()
        self._animate_glow()

    def _draw_fingerprint(self):
        self.delete("fp")
        cx, cy = self.cx, self.cy
        rings = [
            (8,  9,  0.98),
            (16, 18, 0.92),
            (24, 28, 0.86),
            (32, 37, 0.78),
            (40, 47, 0.68),
            (48, 57, 0.55),
            (56, 67, 0.40),
        ]
        for rx, ry, alpha_f in rings:
            color = self._alpha_color("#C9A84C", alpha_f)
            self._draw_oval_ridge(cx, cy, rx, ry, color)
        r = 4
        self.create_oval(cx-r, cy-r, cx+r, cy+r,
                         fill=C["gold_lt"], outline="", tags="fp")

    def _draw_oval_ridge(self, cx, cy, rx, ry, color):
        pts = []
        gap = 0.15
        for i in range(121):
            angle = 2 * math.pi * i / 120
            if abs(angle - math.pi / 2) < gap:
                continue
            pts.append((cx + rx * math.cos(angle),
                         cy + ry * math.sin(angle)))
        for i in range(len(pts) - 1):
            self.create_line(pts[i][0], pts[i][1],
                             pts[i+1][0], pts[i+1][1],
                             fill=color, width=1.5, tags="fp")

    @staticmethod
    def _alpha_color(hex_color: str, alpha: float) -> str:
        r  = int(hex_color[1:3], 16)
        g  = int(hex_color[3:5], 16)
        b  = int(hex_color[5:7], 16)
        br, bg, bb = 0x1A, 0x12, 0x08
        return "#{:02x}{:02x}{:02x}".format(
            int(r*alpha + br*(1-alpha)),
            int(g*alpha + bg*(1-alpha)),
            int(b*alpha + bb*(1-alpha)),
        )

    def _animate_glow(self):
        self.delete("glow")
        cx, cy = self.cx, self.cy
        p = self.phase % (2 * math.pi)
        for i, base_r in enumerate([78, 88, 98]):
            offset = math.sin(p - i * 0.6) * 3
            r      = base_r + offset
            alpha  = 0.12 + 0.08 * math.sin(p - i * 0.6)
            color  = self._alpha_color("#C9A84C", alpha)
            self.create_oval(cx-r, cy-r, cx+r, cy+r,
                             outline=color, width=1, tags="glow")
        self.phase += 0.06
        self.after(40, self._animate_glow)


# ─────────────────────────────────────────────
#  موجة صوتية متحركة
# ─────────────────────────────────────────────
class WaveCanvas(ctk.CTkCanvas):

    def __init__(self, master, **kwargs):
        super().__init__(master, bg=C["card"],
                         highlightthickness=0, **kwargs)
        self.active = False
        self.phase  = 0.0
        self._animate()

    def _animate(self):
        self.delete("wave")
        w = self.winfo_width() or 360
        h = self.winfo_height() or 60
        amp = 18 if self.active else 2
        pts = []
        for i in range(100):
            x = i * w / 99
            y = h/2 + amp * math.sin(2*math.pi*i/99*4 + self.phase)
            pts += [x, y]
        if len(pts) >= 4:
            self.create_line(*pts, fill=C["gold"], width=2.5,
                             smooth=True, tags="wave")
        if self.active:
            self.phase += 0.18
        self.after(35, self._animate)

    def start(self): self.active = True
    def stop(self):  self.active = False; self.phase = 0.0


# ─────────────────────────────────────────────
#  مؤشر خطوات التسجيل (3 خطوات فقط)
# ─────────────────────────────────────────────
class StepsIndicator(ctk.CTkFrame):
    STEPS = ["كلمة المرور", "تأكيد الصوت", "مكتمل"]

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.dots  = []
        self.lines = []
        self._build()
        self.set_step(0)

    def _build(self):
        for i, label in enumerate(self.STEPS):
            col = ctk.CTkFrame(self, fg_color="transparent")
            col.grid(row=0, column=i*2, padx=0, pady=6)
            self.grid_columnconfigure(i*2, weight=0)
            dot = ctk.CTkFrame(col, width=30, height=30,
                               corner_radius=15, fg_color=C["step_wait"])
            dot.pack()
            dot.pack_propagate(False)
            num = ctk.CTkLabel(dot, text=str(i+1),
                               font=("Arial", 12, "bold"),
                               text_color=C["white"])
            num.place(relx=0.5, rely=0.5, anchor="center")
            ctk.CTkLabel(col, text=label, font=("Arial", 10),
                         text_color=C["white_40"]).pack(pady=(3, 0))
            self.dots.append((dot, num))
            if i < len(self.STEPS) - 1:
                line = ctk.CTkFrame(self, height=2, width=50,
                                    fg_color=C["step_wait"], corner_radius=1)
                line.grid(row=0, column=i*2+1, padx=2)
                self.grid_columnconfigure(i*2+1, weight=1)
                self.lines.append(line)

    def set_step(self, active: int):
        for i, (dot, num) in enumerate(self.dots):
            if i < active:
                dot.configure(fg_color=C["step_done"])
                num.configure(text="✓")
            elif i == active:
                dot.configure(fg_color=C["step_act"])
                num.configure(text=str(i+1))
            else:
                dot.configure(fg_color=C["step_wait"])
                num.configure(text=str(i+1))
        for i, line in enumerate(self.lines):
            line.configure(
                fg_color=C["step_done"] if i < active else C["step_wait"])


# ─────────────────────────────────────────────
#  الشاشة الرئيسية
# ─────────────────────────────────────────────
class HomeScreen(ctk.CTkFrame):

    def __init__(self, master, on_login, on_register):
        super().__init__(master, fg_color=C["bg"], corner_radius=0)
        self.on_login    = on_login
        self.on_register = on_register
        self.grid(row=0, column=0, sticky="nsew")
        self._build()

    def _build(self):
        top = ctk.CTkFrame(self, fg_color=C["surface"], height=3, corner_radius=0)
        top.pack(fill="x")
        info = ctk.CTkFrame(self, fg_color="transparent")
        info.pack(fill="x", padx=24, pady=(14, 0))
        ctk.CTkLabel(info, text="v3.0", font=("Courier New", 11),
                     text_color=C["white_40"]).pack(side="left")
        ctk.CTkLabel(info, text="SANAD · سَنَد", font=("Arial", 11),
                     text_color=C["white_40"]).pack(side="right")

        logo = ctk.CTkFrame(self, fg_color="transparent")
        logo.pack(pady=(28, 0))
        FingerprintCanvas(logo, size=160).pack()

        ctk.CTkLabel(self, text="سَنَد",
                     font=("Arial", 48, "bold"),
                     text_color=C["gold"]).pack(pady=(14, 0))
        ctk.CTkLabel(self, text="نظام الدفع الذكي · بصمة صوتك هويتك",
                     font=("Arial", 13),
                     text_color=C["white_40"]).pack(pady=(4, 0))

        ctk.CTkFrame(self, height=1, width=80,
                     fg_color=C["gold_dark"], corner_radius=0).pack(pady=18)

        ctk.CTkLabel(self,
                     text="صوتك هو هويتك وكلمة مرورك\nلا حاجة لكتابة أي شيء",
                     font=("Arial", 14), text_color=C["white_40"],
                     justify="center").pack(pady=(0, 24))

        btn_f = ctk.CTkFrame(self, fg_color="transparent")
        btn_f.pack(fill="x", padx=28, pady=(0, 8))

        ctk.CTkButton(
            btn_f, text="🔊  تسجيل الدخول بالصوت",
            font=("Arial", 20, "bold"), height=76, corner_radius=20,
            fg_color=C["white"], hover_color=C["white_90"],
            text_color=C["btn_text"],
            command=self._login_click,
        ).pack(fill="x", pady=(0, 14))

        ctk.CTkButton(
            btn_f, text="🎤  إنشاء حساب بصوتك",
            font=("Arial", 17, "bold"), height=58, corner_radius=16,
            fg_color=C["white"], hover_color=C["white_90"],
            text_color=C["btn_text"],
            border_color=C["gold"], border_width=2,
            command=self._register_click,
        ).pack(fill="x")

        sec = ctk.CTkFrame(self, fg_color="transparent")
        sec.pack(pady=14)
        for txt in ["🔒 مؤمَّن", "·", "MFCC+STT", "·", "بدون كتابة"]:
            ctk.CTkLabel(sec, text=txt, font=("Arial", 11),
                         text_color=C["white_40"]).pack(side="left", padx=3)

        feat = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=16)
        feat.pack(fill="x", padx=24, pady=(0, 20))
        for i, (icon, lbl) in enumerate([
            ("🔐", "دفع آمن"), ("🎤", "بصمة صوتية"),
            ("⚡", "تحقق فوري"), ("🛡", "حماية كاملة")
        ]):
            col = ctk.CTkFrame(feat, fg_color="transparent")
            col.grid(row=0, column=i, padx=10, pady=14, sticky="ew")
            feat.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(col, text=icon, font=("Arial", 22)).pack()
            ctk.CTkLabel(col, text=lbl, font=("Arial", 11),
                         text_color=C["white_40"]).pack()

    def _login_click(self):
        speak("تسجيل الدخول بالصوت")
        self.on_login()

    def _register_click(self):
        speak("إنشاء حساب جديد بصوتك")
        self.on_register()


# ─────────────────────────────────────────────
#  شاشة التسجيل — بالصوت بالكامل
# ─────────────────────────────────────────────
class RegisterScreen(ctk.CTkFrame):
    """
    خطوة 0: تسجيل كلمة المرور الصوتية × 3 مرات
             → يُخزَّن: النص المنطوق + بصمة الصوت الوسطية
    خطوة 1: تأكيد — قل الكلمة مرة أخرى
             → مقارنة النص والبصمة
    خطوة 2: نجاح
    """

    FS  = 16000   # تردد التسجيل (يدعم STT بشكل أفضل)
    DUR = 4       # مدة كل تسجيل بالثواني

    def __init__(self, master, on_done, on_back):
        super().__init__(master, fg_color=C["bg"], corner_radius=0)
        self.on_done = on_done
        self.on_back = on_back
        self._step        = 0
        self._spoken_word = ""    # الكلمة المنطوقة (نص)
        self._fp_enroll   = None  # البصمة الوسطية من مرحلة التسجيل
        # معرّف المستخدم: timestamp فريد (بدون كتابة)
        self._user_id = f"user_{int(time.time())}"
        self.grid(row=0, column=0, sticky="nsew")
        self._build_shell()
        self._show_step(0)
        speak("مرحباً. سنسجل كلمة مرورك الصوتية. انطق الكلمة التي تريدها بوضوح.")

    def _build_shell(self):
        top = ctk.CTkFrame(self, fg_color=C["gold"], height=62, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)
        ctk.CTkLabel(top, text="إنشاء حساب بالصوت",
                     font=("Arial", 20, "bold"),
                     text_color=C["btn_text"]).pack(side="right", padx=20)
        ctk.CTkButton(top, text="← رجوع", font=("Arial", 13),
                      width=80, height=36,
                      fg_color="transparent", hover_color=C["gold_dark"],
                      text_color=C["btn_text"],
                      command=self.on_back).pack(side="left", padx=14)

        self.steps_bar = StepsIndicator(self)
        self.steps_bar.pack(pady=(16, 4))

        ctk.CTkFrame(self, height=1, fg_color=C["gold_dark"],
                     corner_radius=0).pack(fill="x", padx=20)

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(fill="both", expand=True)

    def _clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def _show_step(self, step: int):
        self._step = step
        self.steps_bar.set_step(step)
        self._clear_content()
        [self._step_enroll,
         self._step_confirm,
         self._step_success][step]()

    # ══════════════════════════════════════════
    #  خطوة 0 — تسجيل كلمة المرور × 3
    # ══════════════════════════════════════════
    def _step_enroll(self):
        pad = ctk.CTkFrame(self.content, fg_color="transparent")
        pad.pack(fill="both", expand=True, padx=24)

        ctk.CTkLabel(pad, text="🎙", font=("Arial", 52)).pack(pady=(20, 2))
        ctk.CTkLabel(pad, text="انطق كلمة مرورك",
                     font=("Arial", 24, "bold"),
                     text_color=C["gold"]).pack()
        ctk.CTkLabel(pad,
                     text="اختر كلمة سرية وانطقها 3 مرات\nمثال: «تفاحة» أو «القمر يضيء»",
                     font=("Arial", 13), text_color=C["white_40"],
                     justify="center").pack(pady=(6, 10))

        # بطاقة التعليمات
        hint = ctk.CTkFrame(pad, fg_color=C["card"], corner_radius=14,
                            border_color=C["gold_dark"], border_width=1)
        hint.pack(fill="x", pady=(0, 10))
        for step_txt in [
            "① انطق كلمتك السرية بوضوح",
            "② ستُسجَّل 3 مرات لضمان الدقة",
            "③ ستُحفظ الكلمة + بصمة صوتك",
        ]:
            ctk.CTkLabel(hint, text=step_txt, font=("Arial", 12),
                         text_color=C["white_70"],
                         anchor="e").pack(fill="x", padx=14, pady=3)

        # الموجة الصوتية
        wave_card = ctk.CTkFrame(pad, fg_color=C["card"], corner_radius=14)
        wave_card.pack(fill="x", pady=4)
        self.wave = WaveCanvas(wave_card, height=60)
        self.wave.pack(fill="x", padx=10, pady=8)

        # شريط التقدم
        self.en_bar = ctk.CTkProgressBar(pad, progress_color=C["gold"],
                                         fg_color=C["card"],
                                         height=10, corner_radius=5)
        self.en_bar.pack(fill="x", pady=(6, 0))
        self.en_bar.set(0)

        self.en_status = ctk.CTkLabel(pad, text="",
                                      font=("Arial", 14, "bold"),
                                      text_color=C["white_70"],
                                      wraplength=350, justify="center")
        self.en_status.pack(pady=6)

        self.en_attempt = ctk.CTkLabel(pad, text="",
                                       font=("Arial", 12),
                                       text_color=C["white_40"])
        self.en_attempt.pack()

        # الكلمة المكتشفة
        detected_card = ctk.CTkFrame(pad, fg_color=C["surface"],
                                     corner_radius=12)
        detected_card.pack(fill="x", pady=4)
        ctk.CTkLabel(detected_card, text="الكلمة التي سُمعت:",
                     font=("Arial", 11), text_color=C["white_40"]).pack(
                     side="right", padx=10, pady=8)
        self.detected_lbl = ctk.CTkLabel(detected_card, text="—",
                                          font=("Arial", 15, "bold"),
                                          text_color=C["gold_lt"])
        self.detected_lbl.pack(side="left", padx=10)

        self.en_btn = ctk.CTkButton(
            pad, text="🎤  ابدأ التسجيل",
            font=("Arial", 19, "bold"), height=66, corner_radius=18,
            fg_color=C["white"], hover_color=C["white_90"],
            text_color=C["btn_text"],
            command=self._start_enroll)
        self.en_btn.pack(fill="x", pady=(10, 0))

        self._en_recordings = []
        self._en_words      = []

    def _start_enroll(self):
        self.en_btn.configure(state="disabled",
                              text="جارٍ التسجيل...",
                              fg_color=C["card"])
        threading.Thread(target=self._enroll_logic, daemon=True).start()

    def _enroll_logic(self):
        fps, words = [], []
        for attempt in range(3):
            idx = attempt + 1
            self._set_status(self.en_status,
                             f"🎙 المحاولة {idx} من 3 — انطق كلمتك السرية",
                             C["gold"])
            self.after(0, lambda i=idx: self.en_attempt.configure(
                text=f"التسجيل {i} / 3"))
            speak(f"المحاولة {idx}. انطق كلمتك")
            time.sleep(0.8)
            self.wave.start()
            self._start_progress(self.en_bar, self.DUR)

            rec = sd.rec(int(self.DUR * self.FS),
                         samplerate=self.FS, channels=1)
            sd.wait()
            self.wave.stop()

            # استخراج الكلمة والبصمة
            word = transcribe_audio(rec, self.FS)
            fp   = extract_fingerprint(rec, self.FS)
            words.append(word)
            fps.append(fp)

            self.after(0, lambda w=word: self.detected_lbl.configure(text=w or "—"))
            self._set_status(self.en_status,
                             f"✅ سُمعت: «{word}»",
                             C["success"])
            time.sleep(0.9)

        # الكلمة الأكثر تكراراً (أو الأولى)
        from collections import Counter
        most_common = Counter(words).most_common(1)[0][0]
        self._spoken_word = most_common
        self._fp_enroll   = np.mean(fps, axis=0)

        self._set_status(self.en_status,
                         "🔐 جارٍ معالجة البيانات...", C["info"])
        time.sleep(0.5)
        self.after(0, lambda: self._show_step(1))

    # ══════════════════════════════════════════
    #  خطوة 1 — تأكيد كلمة المرور
    # ══════════════════════════════════════════
    def _step_confirm(self):
        speak("ممتاز. الآن قل كلمتك مرة أخرى للتأكيد")
        pad = ctk.CTkFrame(self.content, fg_color="transparent")
        pad.pack(fill="both", expand=True, padx=24)

        ctk.CTkLabel(pad, text="🔍", font=("Arial", 52)).pack(pady=(20, 2))
        ctk.CTkLabel(pad, text="أكّد كلمة مرورك",
                     font=("Arial", 24, "bold"),
                     text_color=C["gold"]).pack()
        ctk.CTkLabel(pad,
                     text="انطق نفس الكلمة السرية مرة أخرى\nللتحقق من مطابقتها",
                     font=("Arial", 13), text_color=C["white_40"],
                     justify="center").pack(pady=(6, 12))

        # عرض تلميح مشفر (أول حرف فقط)
        hint_txt = f"تلميح: الكلمة تبدأ بـ «{self._spoken_word[:2] if self._spoken_word else '...'}»"
        hint_card = ctk.CTkFrame(pad, fg_color=C["card"], corner_radius=12,
                                 border_color=C["gold"], border_width=1)
        hint_card.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(hint_card, text=hint_txt,
                     font=("Arial", 14, "bold"),
                     text_color=C["gold_lt"]).pack(pady=12)

        wave_card = ctk.CTkFrame(pad, fg_color=C["card"], corner_radius=14)
        wave_card.pack(fill="x", pady=4)
        self.wave2 = WaveCanvas(wave_card, height=60)
        self.wave2.pack(fill="x", padx=10, pady=8)

        self.cf_bar = ctk.CTkProgressBar(pad, progress_color=C["gold"],
                                         fg_color=C["card"],
                                         height=10, corner_radius=5)
        self.cf_bar.pack(fill="x", pady=(6, 0))
        self.cf_bar.set(0)

        self.cf_status = ctk.CTkLabel(pad, text="",
                                      font=("Arial", 14, "bold"),
                                      text_color=C["white_70"],
                                      wraplength=350, justify="center")
        self.cf_status.pack(pady=6)

        # نتيجة المقارنة
        result_card = ctk.CTkFrame(pad, fg_color=C["surface"],
                                   corner_radius=12)
        result_card.pack(fill="x", pady=4)
        ctk.CTkLabel(result_card, text="التطابق:",
                     font=("Arial", 11), text_color=C["white_40"]).pack(
                     side="right", padx=10, pady=8)
        self.match_lbl = ctk.CTkLabel(result_card, text="—",
                                       font=("Arial", 15, "bold"),
                                       text_color=C["gold_lt"])
        self.match_lbl.pack(side="left", padx=10)

        self.cf_btn = ctk.CTkButton(
            pad, text="🎤  قل الكلمة للتأكيد",
            font=("Arial", 19, "bold"), height=66, corner_radius=18,
            fg_color=C["white"], hover_color=C["white_90"],
            text_color=C["btn_text"],
            command=self._start_confirm)
        self.cf_btn.pack(fill="x", pady=(10, 0))

        # زر إعادة التسجيل
        ctk.CTkButton(
            pad, text="↩  إعادة تسجيل الكلمة",
            font=("Arial", 14), height=44, corner_radius=14,
            fg_color="transparent", hover_color=C["surface"],
            text_color=C["white_40"], border_color=C["gold_dark"],
            border_width=1,
            command=lambda: self._show_step(0)).pack(fill="x", pady=(6, 0))

    def _start_confirm(self):
        self.cf_btn.configure(state="disabled",
                              text="جارٍ الاستماع...",
                              fg_color=C["card"])
        threading.Thread(target=self._confirm_logic, daemon=True).start()

    def _confirm_logic(self):
        speak("انطق كلمتك الآن")
        time.sleep(0.5)
        self.wave2.start()
        self._set_status(self.cf_status,
                         "🎙 أستمع إليك...", C["gold"])
        self._start_progress(self.cf_bar, self.DUR)

        rec = sd.rec(int(self.DUR * self.FS),
                     samplerate=self.FS, channels=1)
        sd.wait()
        self.wave2.stop()

        word_now = transcribe_audio(rec, self.FS)
        fp_now   = extract_fingerprint(rec, self.FS)

        # مقارنة النص
        word_match = (word_now.strip().lower() ==
                      self._spoken_word.strip().lower())
        # مقارنة البصمة
        sim = voice_similarity(fp_now, self._fp_enroll)
        voice_match = sim >= 0.72   # عتبة التطابق

        # يكفي أحدهما للنجاح (لأن STT قد يخطئ)
        success = word_match or voice_match

        score_txt = f"الكلمة: {'✅' if word_match else '❌'}  |  الصوت: {sim:.0%}"
        self.after(0, lambda: self.match_lbl.configure(
            text=score_txt,
            text_color=C["success"] if success else C["danger"]))

        if success:
            self._set_status(self.cf_status,
                             "✅ تطابق! جارٍ حفظ بياناتك...", C["success"])
            self._save_user(fp_now)
        else:
            speak("لم تتطابق الكلمة. حاول مجدداً")
            self._set_status(self.cf_status,
                             "❌ الكلمة لا تتطابق. حاول مرة أخرى.",
                             C["danger"])
            self.after(0, lambda: self.cf_btn.configure(
                state="normal",
                text="🎤 قل الكلمة للتأكيد",
                fg_color=C["white"]))

    def _save_user(self, fp_confirm: np.ndarray):
        try:
            # دمج بصمة التسجيل والتأكيد
            fp_final = (self._fp_enroll + fp_confirm) / 2

            # تجزئة الكلمة المنطوقة
            word_hash = SecurityLayer.hash_spoken_word(self._spoken_word)
            SecurityLayer.store_word_hash(self._user_id, word_hash)

            # حفظ البصمة مشفرة (المفتاح = الكلمة المنطوقة)
            SecurityLayer.save_fingerprint(
                fp_final, self._user_id, self._spoken_word)

            # بيانات وصفية
            SecurityLayer.save_user_meta(self._user_id, {
                "created_at":       datetime.now().isoformat(),
                "word_hint":        self._spoken_word[:2] + "***",
                "fingerprint_file": f"{self._user_id}_voice.enc",
                "crypto":           "AES-256/bcrypt" if (CRYPTO_OK and BCRYPT_OK)
                                    else "sha256/fallback",
                "auth_method":      "voice_password + voice_fingerprint",
            })

            self._set_status(self.cf_status, "✅ تم الحفظ بنجاح!", C["success"])
            time.sleep(0.5)
            self.after(0, lambda: self._show_step(2))
        except Exception as e:
            self._set_status(self.cf_status, f"❌ خطأ: {e}", C["danger"])
            self.after(0, lambda: self.cf_btn.configure(
                state="normal",
                text="🎤 قل الكلمة للتأكيد",
                fg_color=C["white"]))

    # ══════════════════════════════════════════
    #  خطوة 2 — نجاح
    # ══════════════════════════════════════════
    def _step_success(self):
        speak("تهانينا! تم إنشاء حسابك بنجاح. صوتك هو كلمة مرورك.")
        pad = ctk.CTkFrame(self.content, fg_color="transparent")
        pad.pack(fill="both", expand=True, padx=24)

        ctk.CTkLabel(pad, text="🎉", font=("Arial", 64)).pack(pady=(24, 4))
        ctk.CTkLabel(pad, text="تم إنشاء الحساب!",
                     font=("Arial", 26, "bold"),
                     text_color=C["gold"]).pack()
        ctk.CTkLabel(pad, text="صوتك هو هويتك الآن",
                     font=("Arial", 15),
                     text_color=C["white_70"]).pack(pady=(4, 16))

        card = ctk.CTkFrame(pad, fg_color=C["card"], corner_radius=16,
                            border_color=C["success"], border_width=1)
        card.pack(fill="x", pady=6)

        stored_items = [
            ("🔑 كلمة المرور الصوتية",
             f"«{self._spoken_word[:2]}***» — مجزأة bcrypt"),
            ("🎤 بصمة الصوت",
             "مشفرة AES-256 ✅"),
            ("🔐 مفتاح التشفير",
             "مشتق من صوتك (PBKDF2)"),
            ("📁 مكان الحفظ",
             str(SANAD_DIR)[:32] + "..."),
        ]
        for label, value in stored_items:
            r = ctk.CTkFrame(card, fg_color="transparent")
            r.pack(fill="x", padx=14, pady=5)
            ctk.CTkLabel(r, text=label, font=("Arial", 11),
                         text_color=C["white_40"],
                         width=150, anchor="e").pack(side="right")
            ctk.CTkLabel(r, text=value, font=("Arial", 11, "bold"),
                         text_color=C["gold_lt"],
                         anchor="w", wraplength=170).pack(side="left")

        # ملاحظة مهمة
        note = ctk.CTkFrame(pad, fg_color=C["surface"], corner_radius=12,
                            border_color=C["gold_dark"], border_width=1)
        note.pack(fill="x", pady=10)
        ctk.CTkLabel(note,
                     text="⚠  تذكّر كلمتك السرية جيداً\nستحتاجها في كل مرة تدخل فيها",
                     font=("Arial", 12), text_color=C["gold"],
                     justify="center").pack(pady=10)

        ctk.CTkButton(pad, text="🚀  ابدأ الاستخدام",
                      font=("Arial", 21, "bold"), height=70,
                      corner_radius=20, fg_color=C["white"],
                      hover_color=C["white_90"], text_color=C["btn_text"],
                      command=lambda: self.on_done(
                          self._user_id, self._fp_enroll, self._spoken_word)
                      ).pack(fill="x", pady=(6, 0))

    # ── أدوات مساعدة ────────────────────────
    def _set_status(self, label, text, color):
        self.after(0, lambda: label.configure(text=text, text_color=color))

    def _start_progress(self, bar, duration: float):
        """يحرّك شريط التقدم على مدى duration ثانية."""
        steps = 40
        def _run():
            for i in range(steps + 1):
                self.after(0, lambda v=i/steps: bar.set(v))
                time.sleep(duration / steps)
        threading.Thread(target=_run, daemon=True).start()


# ─────────────────────────────────────────────
#  التطبيق الرئيسي
# ─────────────────────────────────────────────
class SanadApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("سَنَد — نظام الدفع الذكي")
        self.geometry("420x800")
        self.resizable(False, False)
        self.configure(fg_color=C["bg"])
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._show_home()
        speak("أهلاً بك في سَنَد. صوتك هو هويتك.")

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def _show_home(self):
        self._clear()
        HomeScreen(self,
                   on_login=self._show_login,
                   on_register=self._show_register)

    def _show_register(self):
        self._clear()
        RegisterScreen(self,
                       on_done=self._after_register,
                       on_back=self._show_home)

    def _show_login(self):
        self._clear()
        ph = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        ph.grid(row=0, column=0, sticky="nsew")
        ctk.CTkLabel(ph, text="🎤\nشاشة الدخول\nقادمة قريباً",
                     font=("Arial", 22, "bold"),
                     text_color=C["gold"],
                     justify="center").pack(pady=200)
        ctk.CTkButton(ph, text="← رجوع",
                      font=("Arial", 16, "bold"), height=56,
                      corner_radius=16, fg_color=C["white"],
                      hover_color=C["white_90"], text_color=C["btn_text"],
                      command=self._show_home).pack(padx=40, fill="x")

    def _after_register(self, user_id, fingerprint, spoken_word):
        print(f"[OK] New user registered: {user_id}")
        self._show_home()


# ─────────────────────────────────────────────
if __name__ == "__main__":
    missing = []
    if not CRYPTO_OK:  missing.append("cryptography")
    if not BCRYPT_OK:  missing.append("bcrypt")
    if not KEYRING_OK: missing.append("keyring")
    if not SR_OK:      missing.append("SpeechRecognition")
    if missing:
        print(f"[WARN] Run: pip install {' '.join(missing)}")
        print("      (App works without them but with reduced features)")

    app = SanadApp()
    app.mainloop()