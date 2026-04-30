"""
سَنَد — نظام الدفع الذكي v4.5
التطوير: هانم عماد
التحديث: إصلاح دقة التحقق من كلمة المرور الصوتية (البصمة) في شاشة العمليات
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
# مكتبات التشفير والأمان
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
# إعدادات المجلدات والبيانات
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

# ─────────────────────────────────────────────
# أدوات المعالجة الصوتية
# ─────────────────────────────────────────────
def transcribe_audio(recording: np.ndarray, fs: int = 16000) -> str:
    if not SR_OK:
        fp = extract_fingerprint(recording, fs)
        return "voice_" + hashlib.md5(fp.tobytes()).hexdigest()[:8]
    try:
        import io, wave
        recognizer = sr.Recognizer()
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
        try:
            return recognizer.recognize_google(audio, language="ar-SA").strip().lower()
        except:
            try:
                return recognizer.recognize_google(audio, language="en-US").strip().lower()
            except:
                return ""
    except:
        return ""

def extract_fingerprint(recording: np.ndarray, fs: int = 22050) -> np.ndarray:
    y = recording.flatten().astype(np.float32)
    if np.max(np.abs(y)) > 0: y /= np.max(np.abs(y))
    mfccs = librosa.feature.mfcc(y=y, sr=fs, n_mfcc=20)
    delta = librosa.feature.delta(mfccs)
    chroma = librosa.feature.chroma_stft(y=y, sr=fs)
    features = np.concatenate([
        np.mean(mfccs, axis=1), np.std(mfccs, axis=1),
        np.mean(delta, axis=1), np.mean(chroma, axis=1)
    ])
    return features

def voice_similarity(fp1: np.ndarray, fp2: np.ndarray) -> float:
    n1, n2 = np.linalg.norm(fp1), np.linalg.norm(fp2)
    return float(np.dot(fp1, fp2) / (n1 * n2)) if n1 > 0 and n2 > 0 else 0.0

# ─────────────────────────────────────────────
# طبقة الأمان (SecurityLayer)
# ─────────────────────────────────────────────
class SecurityLayer:
    @staticmethod
    def hash_spoken_word(word: str) -> str:
        if BCRYPT_OK:
            return bcrypt.hashpw(word.encode(), bcrypt.gensalt()).decode()
        salt = secrets.token_hex(16)
        return f"sha256:{salt}:{hashlib.sha256((word+salt).encode()).hexdigest()}"

    @staticmethod
    def verify_spoken_word(word: str, hashed: str) -> bool:
        if not hashed: return False
        if BCRYPT_OK and not hashed.startswith("sha256:"):
            try: return bcrypt.checkpw(word.encode(), hashed.encode())
            except: return False
        parts = hashed.split(":")
        if len(parts) < 3: return False
        return hashlib.sha256((word+parts[1]).encode()).hexdigest() == parts[2]

    @staticmethod
    def store_word_hash(user_id: str, hashed: str):
        if KEYRING_OK: keyring.set_password(APP_SERVICE, f"{user_id}_word", hashed)
        else:
            meta = SecurityLayer._load_meta()
            meta.setdefault("words", {})[user_id] = hashed
            SecurityLayer._save_meta(meta)

    @staticmethod
    def get_word_hash(user_id: str):
        if KEYRING_OK: return keyring.get_password(APP_SERVICE, f"{user_id}_word")
        return SecurityLayer._load_meta().get("words", {}).get(user_id)

    @staticmethod
    def save_fingerprint(fp: np.ndarray, user_id: str, key_material: str):
        fp_path = SANAD_DIR / f"{user_id}_voice.enc"
        salt = secrets.token_bytes(16)
        key = SecurityLayer._derive_key(key_material, salt)
        if CRYPTO_OK:
            ct = Fernet(key).encrypt(fp.astype(np.float64).tobytes())
            with open(fp_path, "wb") as f: f.write(salt + ct)
        else: np.save(SANAD_DIR / f"{user_id}_voice.npy", fp)

    @staticmethod
    def load_fingerprint(user_id: str, key_material: str):
        fp_path = SANAD_DIR / f"{user_id}_voice.enc"
        if not fp_path.exists():
            npy = SANAD_DIR / f"{user_id}_voice.npy"
            return np.load(npy) if npy.exists() else None
        with open(fp_path, "rb") as f: data = f.read()
        key = SecurityLayer._derive_key(key_material, data[:16])
        try: return np.frombuffer(Fernet(key).decrypt(data[16:]), dtype=np.float64)
        except: return None

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def _load_meta():
        if USERS_FILE.exists():
            with open(USERS_FILE, encoding="utf-8") as f: return json.load(f)
        return {}

    @staticmethod
    def _save_meta(data):
        with open(USERS_FILE, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)

    @staticmethod
    def save_user_meta(user_id, info):
        meta = SecurityLayer._load_meta()
        meta.setdefault("users", {})[user_id] = info
        SecurityLayer._save_meta(meta)

    @staticmethod
    def list_users():
        return list(SecurityLayer._load_meta().get("users", {}).keys())

# ─────────────────────────────────────────────
# الألوان والتنسيق
# ─────────────────────────────────────────────
C = {
    "bg": "#1A1208", "surface": "#261A08", "card": "#2D1F08",
    "gold": "#C9A84C", "gold_lt": "#E8C97A", "gold_dark": "#A07830",
    "white": "#FFFFFF", "white_70": "#B3B3B3", "white_40": "#666666",
    "btn_text": "#1A1208", "success": "#2D7A4F", "danger": "#C0392B",
    "info": "#1E6BA3", "step_done": "#2D7A4F", "step_act": "#C9A84C", "step_wait": "#444444"
}
ctk.set_appearance_mode("dark")

# ─────────────────────────────────────────────
# محرك الكلام (TTS)
# ─────────────────────────────────────────────
_engine = pyttsx3.init()
_engine.setProperty('rate', 150)
def speak(text: str):
    def _r(): _engine.say(text); _engine.runAndWait()
    threading.Thread(target=_r, daemon=True).start()

# ─────────────────────────────────────────────
# الواجهات الرسومية[cite: 1]
# ─────────────────────────────────────────────
class FingerprintCanvas(ctk.CTkCanvas):
    def __init__(self, master, size=160, **kwargs):
        super().__init__(master, width=size, height=size, bg=C["bg"], highlightthickness=0, **kwargs)
        self.size, self.phase = size, 0.0
        self._animate()

    def _animate(self):
        self.delete("all")
        cx = self.size/2
        for i, r in enumerate([30, 45, 60]):
            self.create_oval(cx-r, cx-r, cx+r, cx+r, outline=C["gold"], width=2)
        self.phase += 0.1
        self.after(50, self._animate)

class WaveCanvas(ctk.CTkCanvas):
    def __init__(self, master, **kwargs):
        super().__init__(master, bg=C["card"], highlightthickness=0, **kwargs)
        self.active, self.phase = False, 0.0
        self._animate()

    def _animate(self):
        self.delete("wave")
        if self.active:
            w, h = self.winfo_width(), self.winfo_height()
            pts = []
            for x in range(0, w, 5):
                y = h/2 + (15 * math.sin(x*0.05 + self.phase))
                pts.extend([x, y])
            if len(pts) > 4: self.create_line(*pts, fill=C["gold"], width=2, smooth=True, tags="wave")
            self.phase += 0.2
        self.after(30, self._animate)

    def start(self): self.active = True
    def stop(self): self.active = False

class StepsIndicator(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.dots = []
        for i in range(3):
            d = ctk.CTkFrame(self, width=20, height=20, corner_radius=10, fg_color=C["step_wait"])
            d.pack(side="left", padx=10)
            self.dots.append(d)

    def set_step(self, step):
        for i, d in enumerate(self.dots):
            d.configure(fg_color=C["step_done"] if i < step else (C["step_act"] if i == step else C["step_wait"]))

# ─────────────────────────────────────────────
# شاشات التطبيق الأساسية[cite: 1]
# ─────────────────────────────────────────────
class HomeScreen(ctk.CTkFrame):
    def __init__(self, master, on_login, on_register):
        super().__init__(master, fg_color=C["bg"])
        self.pack(fill="both", expand=True)
        FingerprintCanvas(self).pack(pady=40)
        ctk.CTkLabel(self, text="سَنَد", font=("Arial", 42, "bold"), text_color=C["gold"]).pack()
        ctk.CTkButton(self, text="🔊 تسجيل الدخول بالصوت", height=60, corner_radius=15, 
                      fg_color=C["white"], text_color=C["btn_text"], command=on_login).pack(pady=20, padx=40, fill="x")
        ctk.CTkButton(self, text="🎤 إنشاء حساب جديد", height=50, corner_radius=15, 
                      fg_color="transparent", border_color=C["gold"], border_width=2, command=on_register).pack(padx=40, fill="x")

class RegisterScreen(ctk.CTkFrame):
    FS, DUR = 16000, 4
    def __init__(self, master, on_done, on_back):
        super().__init__(master, fg_color=C["bg"])
        self.on_done, self.on_back = on_done, on_back
        self.pack(fill="both", expand=True)
        self.recordings, self.words = [], []
        self._user_id = f"user_{int(time.time())}"
        self._ui()

    def _ui(self):
        self.indicator = StepsIndicator(self); self.indicator.pack(pady=20)
        self.status = ctk.CTkLabel(self, text="انطق كلمتك السرية 3 مرات", font=("Arial", 16))
        self.status.pack(pady=10)
        self.wave = WaveCanvas(self, height=60); self.wave.pack(fill="x", padx=40)
        self.btn = ctk.CTkButton(self, text="🎤 ابدأ التسجيل", command=self._start); self.btn.pack(pady=20)

    def _start(self):
        self.btn.configure(state="disabled")
        threading.Thread(target=self._logic, daemon=True).start()

    def _logic(self):
        for i in range(3):
            self.after(0, lambda x=i: self.status.configure(text=f"المحاولة {x+1} - تحدث الآن"))
            self.wave.start()
            rec = sd.rec(int(self.DUR * self.FS), samplerate=self.FS, channels=1); sd.wait()
            self.wave.stop()
            self.recordings.append(extract_fingerprint(rec, self.FS))
            self.words.append(transcribe_audio(rec, self.FS))
            time.sleep(1)
        
        word = self.words[0]
        fp = np.mean(self.recordings, axis=0)
        SecurityLayer.store_word_hash(self._user_id, SecurityLayer.hash_spoken_word(word))
        SecurityLayer.save_fingerprint(fp, self._user_id, word)
        SecurityLayer.save_user_meta(self._user_id, {"created_at": datetime.now().isoformat(), "original_word": word})
        speak("تم حفظ بصمتك بنجاح")
        self.after(0, self.on_done)

class LoginScreen(ctk.CTkFrame):
    FS, DUR = 16000, 4
    def __init__(self, master, on_success, on_back):
        super().__init__(master, fg_color=C["bg"])
        self.on_success, self.on_back = on_success, on_back
        self.pack(fill="both", expand=True)
        self._ui()

    def _ui(self):
        ctk.CTkLabel(self, text="تحقق من الهوية", font=("Arial", 24, "bold"), text_color=C["gold"]).pack(pady=30)
        self.msg = ctk.CTkLabel(self, text="قل كلمتك السرية للدخول", text_color=C["white_70"])
        self.msg.pack(pady=10)
        self.wave = WaveCanvas(self, height=80); self.wave.pack(fill="x", padx=40)
        self.btn = ctk.CTkButton(self, text="🔊 ابدأ التحقق الصوتي", height=60, fg_color=C["white"], 
                                 text_color=C["btn_text"], command=self._start); self.btn.pack(pady=40, padx=40, fill="x")

    def _start(self):
        self.btn.configure(state="disabled")
        threading.Thread(target=self._logic, daemon=True).start()

    def _logic(self):
        self.wave.start()
        rec = sd.rec(int(self.DUR * self.FS), samplerate=self.FS, channels=1); sd.wait()
        self.wave.stop()
        
        word = transcribe_audio(rec, self.FS)
        fp_now = extract_fingerprint(rec, self.FS)
        
        found_uid = None
        current_word = None
        for uid in SecurityLayer.list_users():
            if SecurityLayer.verify_spoken_word(word, SecurityLayer.get_word_hash(uid)):
                stored_fp = SecurityLayer.load_fingerprint(uid, word)
                if stored_fp is not None and voice_similarity(fp_now, stored_fp) > 0.72:
                    found_uid = uid
                    current_word = word
                    break
        
        if found_uid:
            speak("تم التحقق بنجاح")
            self.after(0, lambda: self.on_success(found_uid, current_word))
        else:
            self.after(0, lambda: self.msg.configure(text="فشل التحقق، حاول مرة أخرى", text_color=C["danger"]))
            self.after(0, lambda: self.btn.configure(state="normal"))

# ─────────────────────────────────────────────
# شاشة العمليات الذكية (Dashboard)[cite: 1]
# ─────────────────────────────────────────────
class DashboardScreen(ctk.CTkFrame):
    FS, DUR = 16000, 4

    def __init__(self, master, user_id, session_word, on_logout):
        super().__init__(master, fg_color=C["bg"])
        self.user_id = user_id
        self.session_word = session_word # كلمة المرور المستخدمة في الدخول
        self.on_logout = on_logout
        self.pack(fill="both", expand=True)
        self.beneficiaries = [] 
        self._ui()
        speak("مرحباً بك في سَنَد. المس زر الدفع للبدء.")

    def _ui(self):
        header = ctk.CTkFrame(self, fg_color=C["surface"], height=60, corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(header, text="لوحة العمليات", font=("Arial", 18, "bold"), text_color=C["gold"]).pack(side="right", padx=20)
        ctk.CTkButton(header, text="خروج", width=60, fg_color=C["danger"], command=self.on_logout).pack(side="left", padx=15)

        card = ctk.CTkFrame(self, fg_color=C["card"], corner_radius=20, border_color=C["gold_dark"], border_width=1)
        card.pack(fill="x", padx=25, pady=20)
        ctk.CTkLabel(card, text="الرصيد المتاح", font=("Arial", 14), text_color=C["white_40"]).pack(pady=(15, 0))
        ctk.CTkLabel(card, text="5,240.00 $", font=("Arial", 32, "bold"), text_color=C["gold"]).pack(pady=(5, 15))

        self.status_msg = ctk.CTkLabel(self, text="نظام الدفع الصوتي نشط", font=("Arial", 15), text_color=C["white_70"])
        self.status_msg.pack(pady=10)

        self.wave = WaveCanvas(self, height=60); self.wave.pack(fill="x", padx=40)

        self.pay_btn = ctk.CTkButton(self, text="💸 دفع صوتي ذكي", height=70, corner_radius=15, 
                                     fg_color=C["gold"], text_color=C["btn_text"], font=("Arial", 18, "bold"),
                                     command=self._smart_payment_flow)
        self.pay_btn.pack(fill="x", padx=25, pady=20)

        ctk.CTkLabel(self, text="المستفيدون المسجلون", font=("Arial", 13), text_color=C["white_40"]).pack(anchor="e", padx=30)
        self.scroll = ctk.CTkScrollableFrame(self, fg_color=C["surface"], height=200)
        self.scroll.pack(fill="both", padx=25, pady=10)

    def _smart_payment_flow(self):
        """التدفق الذكي: البحث والتحقق من كلمة المرور المحدثة[cite: 1]"""
        def task():
            # 1. البحث عن المستفيد
            speak("لمن تود إرسال الأموال؟")
            self._update_status("🎙 اذكر اسم المستفيد الآن", C["gold"])
            self.wave.start()
            rec = sd.rec(int(self.DUR * self.FS), samplerate=self.FS, channels=1); sd.wait()
            self.wave.stop()
            target_name = transcribe_audio(rec, self.FS)

            if not target_name:
                speak("عذراً، لم أسمع الاسم.")
                return

            if target_name in self.beneficiaries:
                self._proceed_to_payment(target_name)
            else:
                # 2. عرض الإضافة إذا لم يوجد[cite: 1]
                speak(f"عذراً، {target_name} غير موجود. هل تود إضافته؟")
                self._update_status(f"❓ إضافة {target_name}؟ (نعم/لا)", C["info"])
                self.wave.start()
                confirm_rec = sd.rec(int(3 * self.FS), samplerate=self.FS, channels=1); sd.wait()
                self.wave.stop()
                answer = transcribe_audio(confirm_rec, self.FS)

                if any(word in answer for word in ["نعم", "yes", "أضف", "اوكي"]):
                    self._add_beneficiary_logic(target_name)
                    speak(f"تمت الإضافة. كم المبلغ لـ {target_name}؟")
                    self._proceed_to_payment(target_name)
                else:
                    speak("تم إلغاء العملية.")
                    self._update_status("تم الإلغاء", C["white_40"])

        threading.Thread(target=task, daemon=True).start()

    def _add_beneficiary_logic(self, name):
        self.beneficiaries.append(name)
        self.after(0, lambda: self._render_beneficiary(name))
        self._update_status(f"✅ تم حفظ {name}", C["success"])

    def _proceed_to_payment(self, name):
        """الدفع وتأكيد البصمة بناءً على كلمة المرور المستخدمة في الدخول[cite: 1]"""
        if not self.status_msg.cget("text").startswith("💰"):
            speak(f"كم هو المبلغ المطلوب لـ {name}؟")
            self._update_status(f"💰 حدد مبلغ لـ {name}", C["gold"])
            self.wave.start()
            rec_amt = sd.rec(int(self.DUR * self.FS), samplerate=self.FS, channels=1); sd.wait()
            self.wave.stop()
            amount = transcribe_audio(rec_amt, self.FS)
        else:
            amount = "المبلغ المذكور"

        if not amount:
            speak("لم أتمكن من تحديد المبلغ.")
            return

        # 3. التأكد من بصمة الصوت (كلمة المرور)[cite: 1]
        speak(f"لتأكيد دفع {amount} لـ {name}، انطق كلمة السر الخاصة بك الآن.")
        self._update_status("🔐 مطلوب بصمة الصوت للتأكيد", C["danger"])
        self.wave.start()
        rec_auth = sd.rec(int(self.DUR * self.FS), samplerate=self.FS, channels=1); sd.wait()
        self.wave.stop()

        # التحقق الأمني بمطابقة الكلمة والخصائص الصوتية[cite: 1]
        word_now = transcribe_audio(rec_auth, self.FS)
        fp_now = extract_fingerprint(rec_auth, self.FS)
        
        # جلب الهوية المسجلة (نتحقق من الكلمة المكتوبة والبصمة الفيزيائية)[cite: 1]
        stored_word_hash = SecurityLayer.get_word_hash(self.user_id)
        is_word_correct = SecurityLayer.verify_spoken_word(word_now, stored_word_hash)
        
        # تحميل البصمة باستخدام الكلمة المسجلة حالياً لفك التشفير[cite: 1]
        stored_fp = SecurityLayer.load_fingerprint(self.user_id, word_now)
        
        if is_word_correct and stored_fp is not None and voice_similarity(fp_now, stored_fp) > 0.70:
            speak(f"تم التحقق بنجاح. تم تحويل {amount} إلى {name}.")
            self._update_status(f"✅ عملية ناجحة لـ {name}", C["success"])
        else:
            speak("عذراً، كلمة السر أو بصمة الصوت غير متطابقة.")
            self._update_status("❌ فشل التحقق الأمني", C["danger"])

    def _render_beneficiary(self, name):
        row = ctk.CTkFrame(self.scroll, fg_color="transparent")
        row.pack(fill="x", pady=2)
        ctk.CTkLabel(row, text="👤", font=("Arial", 16)).pack(side="right", padx=10)
        ctk.CTkLabel(row, text=name, font=("Arial", 14), text_color=C["white"]).pack(side="right")

    def _update_status(self, txt, color):
        self.after(0, lambda: self.status_msg.configure(text=txt, text_color=color))

# ─────────────────────────────────────────────
# التطبيق الرئيسي[cite: 1]
# ─────────────────────────────────────────────
class SanadApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("سَنَد v4.5"); self.geometry("400x700")
        self._show_home()

    def _clear(self):
        for w in self.winfo_children(): w.destroy()

    def _show_home(self):
        self._clear(); HomeScreen(self, self._show_login, self._show_register)

    def _show_register(self):
        self._clear(); RegisterScreen(self, self._show_home, self._show_home)

    def _show_login(self):
        self._clear(); LoginScreen(self, self._on_success, self._show_home)

    def _on_success(self, uid, word):
        self._clear()
        DashboardScreen(self, uid, word, on_logout=self._show_home)

if __name__ == "__main__":
    app = SanadApp(); app.mainloop()