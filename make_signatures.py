# -*- coding: utf-8 -*-
"""
make_signatures.py
يجلب بصمات (SHA-256) عينات البرمجيات الخبيثة المضافة حديثاً (آخر 48 ساعة)
من MalwareBazaar (abuse.ch) ويدمجها مع قائمتك الحالية، ثم ينتج ملف signatures.json
جاهزاً للرفع إلى GitHub.

يحتاج مفتاحاً مجانياً (Auth-Key) من https://auth.abuse.ch
لا ترفع ملف auth_key.txt إلى GitHub أبداً، ولا تشارك المفتاح مع أحد.
"""
import os
import re
import sys
import csv
import json
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
OUT_FILE = os.path.join(HERE, "signatures.json")
KEY_FILE = os.path.join(HERE, "auth_key.txt")
CFG_FILE = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "3yai", "config.json"
)

EXPORT_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
MAX_HASHES = 100000  # الحد الأقصى لحجم القائمة (الأقدم يُحذف أولاً)
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def http_get(url, max_bytes=60 * 1024 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": "3yai-signature-builder"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(max_bytes)


def get_key():
    key = os.environ.get("MB_AUTH_KEY", "").strip()
    if key:
        return key
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
        if key:
            return key
    print("لم يتم العثور على مفتاح abuse.ch.")
    print("احصل عليه مجاناً من: https://auth.abuse.ch (سجّل ثم أنشئ Auth-Key)")
    key = input("الصق المفتاح هنا ثم اضغط Enter: ").strip()
    if not key:
        sys.exit("لا يوجد مفتاح، تم الإيقاف.")
    with open(KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    print("تم حفظ المفتاح في auth_key.txt (لا ترفعه إلى GitHub).")
    return key


def parse_csv(text):
    """يستخرج بصمات SHA-256 من ملف CSV بغض النظر عن ترتيب الأعمدة."""
    found = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        try:
            row = next(csv.reader([line], skipinitialspace=True))
        except Exception:
            continue
        for field in row:
            f = field.strip().strip('"').lower()
            if HEX64.match(f):
                found.append(f)
                break
    return found


def read_list(data):
    """يقرأ قائمة موجودة (version, hashes) مع تنقية الصيغة."""
    try:
        version = int(data.get("version", 0))
        hashes = [h.lower() for h in data.get("hashes", []) if isinstance(h, str) and HEX64.match(h.lower())]
        return version, hashes
    except Exception:
        return 0, []


def load_published():
    """يقرأ القائمة المنشورة حالياً على GitHub (الرابط المحفوظ في إعدادات 3yai)."""
    try:
        with open(CFG_FILE, "r", encoding="utf-8") as f:
            url = json.load(f).get("update_url", "")
        if url.lower().startswith("https://"):
            print("قراءة القائمة المنشورة حالياً...")
            return read_list(json.loads(http_get(url).decode("utf-8")))
    except Exception as e:
        print("تعذرت قراءة القائمة المنشورة (%s)، سأكمل بدونها." % e)
    return 0, []


def load_local():
    try:
        with open(OUT_FILE, "r", encoding="utf-8") as f:
            return read_list(json.load(f))
    except Exception:
        return 0, []


def merge(old_lists, new_hashes):
    """يدمج القوائم بلا تكرار: القديم أولاً ثم الجديد، ويقص الأقدم عند تجاوز الحد."""
    seen = set()
    ordered = []
    for h in [EICAR] + [x for lst in old_lists for x in lst] + list(new_hashes):
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    if len(ordered) > MAX_HASHES:
        ordered = [EICAR] + ordered[-(MAX_HASHES - 1):]
    return ordered


def main():
    key = get_key()
    print("جلب أحدث البصمات من MalwareBazaar...")
    try:
        raw = http_get(EXPORT_URL.format(key=key))
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            sys.exit("المفتاح مرفوض (خطأ %d). تأكد منه، أو احذف auth_key.txt وأعد المحاولة." % e.code)
        sys.exit("فشل الجلب: خطأ %d" % e.code)
    except Exception as e:
        sys.exit("فشل الاتصال: %s" % e)

    text = raw.decode("utf-8", errors="replace")
    new = parse_csv(text)
    if not new:
        print("لم أجد أي بصمات في الرد. بداية الرد:")
        print(text[:300])
        sys.exit("تم الإيقاف دون تغيير أي ملف.")

    pub_v, pub_h = load_published()
    loc_v, loc_h = load_local()
    merged = merge([pub_h, loc_h], new)
    version = max(pub_v, loc_v) + 1

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump({"version": version, "hashes": merged}, f, indent=2)

    print()
    print("تم. بصمات جديدة من MalwareBazaar: %d" % len(new))
    print("إجمالي البصمات في الملف: %d | الإصدار: %d" % (len(merged), version))
    print("الملف: " + OUT_FILE)
    print()
    print("الخطوة التالية: ارفع signatures.json إلى مستودع 3yai-signatures في GitHub")
    print("(Add file ثم Upload files، وسيستبدل الملف القديم).")


if __name__ == "__main__":
    main()
