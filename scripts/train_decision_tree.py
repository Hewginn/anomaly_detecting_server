"""
Decision Tree – Betanító Script
================================
Fájlútvonalak:
  Script helye : /home/kristofejes/kutatas/anomaly_detecting_server/scripts/
  Log adatok   : /home/kristofejes/kutatas/anomaly_detecting_server/scripts/logs/<log_file>
  Loglizer     : /home/kristofejes/kutatas/loglizer/loglizer/models/

Futtatás:
  python train_decision_tree.py
  → bekéri a log fájl nevét (pl. access.log)

Kimenet:
  /home/kristofejes/kutatas/loglizer/loglizer/models/decision_tree_model.pkl

Log formátum:
  <IP> - - <username> [<timestamp>] "<METHOD> <endpoint> HTTP/<ver>" <status> "<UA>" "<label>"
  Pl.: 19.9.81.132 - - roland [2026-03-28 07:43:31.329619] "GET /api/data HTTP/1.1" 200 "python-requests/2.28" "anomaly"
"""

import os
import sys
import re
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from math import log2

# Loglizer útvonal hozzáadása a Python path-hoz
LOGLIZER_PATH = "/home/kristofejes/kutatas/loglizer"
if LOGLIZER_PATH not in sys.path:
    sys.path.insert(0, LOGLIZER_PATH)

from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# ─────────────────────────────────────────────────────────────
# ÚTVONALAK
# ─────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(SCRIPT_DIR, "logs")
MODEL_DIR  = "/home/kristofejes/kutatas/loglizer/loglizer/models"

# ─────────────────────────────────────────────────────────────
# 1. REGEX MINTÁK
# ─────────────────────────────────────────────────────────────

# Log sor formátum – most már tartalmaz username mezőt is
LOG_REGEX = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r' - - '
    r'(?P<username>\S+) '                   # ← ÚJ: username mező (pl. roland, admin, master)
    r'\[(?P<timestamp>[^\]]+)\]'
    r' "(?P<method>\w+) '
    r'(?P<endpoint>\S+) '
    r'HTTP/(?P<http_ver>[\d.]+)"'
    r' (?P<status>\d{3})'
    r' "(?P<user_agent>[^"]*)"'
    r' "(?P<label>normal|anomaly)"'
)

# Ismert bot/scanner user-agent eszközök
BOT_UA_RE = re.compile(
    r'(python-requests|curl|wget|scrapy|nikto|masscan|nmap|zgrab|bot|crawler)',
    re.IGNORECASE
)

# Érzékeny endpoint minták
# random[a-zA-Z0-9]+ → directory/endpoint scanner jel (pl. /randomgtrdz, /randomYjESfY)
SENSITIVE_RE = re.compile(
    r'(admin|config|passwd|\.env|secret|backup|\.php|\.asp|\.git|\.sql'
    r'|random[a-zA-Z0-9]+)',
    re.IGNORECASE
)

# Gyanús usernevek – tipikus brute force célpontok
SUSPICIOUS_USERNAMES = {
    "admin", "master", "root", "administrator", "superuser",
    "sa", "sys", "oracle", "postgres", "ubuntu", "pi",
}

# ─────────────────────────────────────────────────────────────
# 2. UA SEGÉDFÜGGVÉNYEK
# ─────────────────────────────────────────────────────────────

def ua_entropy(ua: str) -> float:
    """
    Shannon entrópia a user-agent string karakterein.
    Normál böngésző UA : ~3.5–4.5 bit
    Random string       : ~5.5–6.0 bit
    Ismétlődő (AAAA...) : ~0 bit
    """
    if not ua:
        return 0.0
    freq = {c: ua.count(c) / len(ua) for c in set(ua)}
    return -sum(p * log2(p) for p in freq.values())


def ua_alpha_ratio(ua: str) -> float:
    """Betűk aránya. Normál UA-ban magas (~0.6–0.8)."""
    if not ua:
        return 0.0
    return sum(c.isalpha() for c in ua) / len(ua)


def ua_digit_ratio(ua: str) -> float:
    """Számjegyek aránya. Random/hash string-ekben magasabb."""
    if not ua:
        return 0.0
    return sum(c.isdigit() for c in ua) / len(ua)


def ua_unique_char_ratio(ua: str) -> float:
    """
    Egyedi karakterek aránya.
    Random hash → közel 1.0
    AAAAAAA...  → nagyon alacsony
    """
    if not ua:
        return 0.0
    return len(set(ua)) / len(ua)


def ua_max_consecutive_same(ua: str) -> int:
    """
    Maximális egymást követő azonos karakterek száma.
    AAAAAAAAAA → 10  (buffer overflow jel)
    Mozilla/5.0 → 2
    """
    if not ua:
        return 0
    max_run = 1
    current_run = 1
    for i in range(1, len(ua)):
        if ua[i] == ua[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    return max_run


# ─────────────────────────────────────────────────────────────
# 3. LOG PARSING
# ─────────────────────────────────────────────────────────────

def parse_line(line: str) -> dict | None:
    """
    Egy nyers log sort értelmez és feature dict-té alakít.
    Ha a sor nem illeszkedik a mintára, None-t ad vissza.
    """
    m = LOG_REGEX.match(line.strip())
    if not m:
        return None

    ip       = m.group("ip")
    username = m.group("username")
    method   = m.group("method")
    endpoint = m.group("endpoint")
    status   = int(m.group("status"))
    ua       = m.group("user_agent")
    label    = m.group("label")

    try:
        ts   = datetime.fromisoformat(m.group("timestamp"))
        hour = ts.hour
    except Exception:
        hour = -1

    # IP oktek
    octs = list(map(int, ip.split(".")))

    # HTTP method → szám
    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
                  "PATCH": 4, "HEAD": 5, "OPTIONS": 6}
    method_num = method_map.get(method, 99)

    # Endpoint jellemzők
    endpoint_depth = len([p for p in endpoint.split("/") if p])
    sensitive_kw   = int(bool(SENSITIVE_RE.search(endpoint)))

    # Status kód flagek
    status_2xx = int(200 <= status < 300)
    status_4xx = int(400 <= status < 500)
    status_5xx = int(500 <= status < 600)
    status_401 = int(status == 401)
    status_403 = int(status == 403)
    status_404 = int(status == 404)
    status_405 = int(status == 405)

    # ── Username feature-ök ───────────────────────────────
    #
    # Az új log formátumban megjelent a username mező.
    # Két feature-t vonunk ki belőle:
    #
    #   username_is_suspicious → az előre definiált gyanús nevek listájában van-e
    #                            (admin, root, master, stb.)
    #   username_len           → a név hossza (nagyon rövid vagy nagyon hosszú = gyanús)

    username_is_suspicious = int(username.lower() in SUSPICIOUS_USERNAMES)
    username_len           = len(username)

    # ── User-Agent feature-ök ─────────────────────────────

    ua_len = len(ua)

    ua_is_known_bot   = int(bool(BOT_UA_RE.search(ua)))
    ua_has_json_chars = int(bool(re.search(r'[{}":]', ua)))
    ua_has_injection  = int(bool(re.search(r"[<>'\"`;\\]", ua)))
    ua_ent            = ua_entropy(ua)
    ua_alpha          = ua_alpha_ratio(ua)
    ua_digit          = ua_digit_ratio(ua)
    ua_unique         = ua_unique_char_ratio(ua)
    ua_max_repeat     = ua_max_consecutive_same(ua)
    ua_no_space       = int(ua_len > 20 and " " not in ua)
    ua_has_mozilla    = int(bool(re.search(r'Mozilla', ua)))
    ua_has_browser_kw = int(bool(re.search(
        r'(Windows|Macintosh|Linux|iPhone|Android|Chrome|Firefox|Safari|Edge)',
        ua, re.IGNORECASE
    )))

    return {
        # Azonosítók (nem kerülnek a feature mátrixba)
        "ip":         ip,
        "username":   username,
        "method":     method,
        "endpoint":   endpoint,
        "user_agent": ua,
        "label":      label,
        # Numerikus feature-ök
        "ip_oct1":               octs[0],
        "ip_oct2":               octs[1],
        "ip_oct3":               octs[2],
        "ip_oct4":               octs[3],
        "method_num":            method_num,
        "endpoint_depth":        endpoint_depth,
        "sensitive_kw":          sensitive_kw,
        "status":                status,
        "status_2xx":            status_2xx,
        "status_4xx":            status_4xx,
        "status_5xx":            status_5xx,
        "status_401":            status_401,
        "status_403":            status_403,
        "status_404":            status_404,
        "status_405":            status_405,
        "username_is_suspicious":username_is_suspicious,
        "username_len":          username_len,
        "ua_len":                ua_len,
        "ua_is_known_bot":       ua_is_known_bot,
        "ua_has_json_chars":     ua_has_json_chars,
        "ua_has_injection":      ua_has_injection,
        "ua_entropy":            ua_ent,
        "ua_alpha_ratio":        ua_alpha,
        "ua_digit_ratio":        ua_digit,
        "ua_unique_ratio":       ua_unique,
        "ua_max_repeat":         ua_max_repeat,
        "ua_no_space":           ua_no_space,
        "ua_has_mozilla":        ua_has_mozilla,
        "ua_has_browser_kw":     ua_has_browser_kw,
        "hour":                  hour,
    }


def load_logs(filepath: str) -> pd.DataFrame:
    """Log fájl beolvasása DataFrame-be. Értelmezhetetlen sorokat kihagyja."""
    rows       = []
    skip_count = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                rows.append(parsed)
            elif line.strip():
                skip_count += 1

    df = pd.DataFrame(rows)
    print(f"  Beolvasva    : {len(df)} sor")
    print(f"  Kihagyva     : {skip_count} értelmezhetetlen sor")
    return df


# ─────────────────────────────────────────────────────────────
# 4. FEATURE MÁTRIX
# ─────────────────────────────────────────────────────────────

FEATURE_COLS = [
    # Hálózat
    "ip_oct1", "ip_oct2", "ip_oct3", "ip_oct4",
    # HTTP kérés
    "method_num", "endpoint_depth", "sensitive_kw",
    # HTTP válasz
    "status", "status_2xx", "status_4xx", "status_5xx",
    "status_401", "status_403", "status_404", "status_405",
    # Username – ÚJ
    "username_is_suspicious",
    "username_len",
    # User-Agent
    "ua_len",
    "ua_is_known_bot",
    "ua_has_json_chars",
    "ua_has_injection",
    "ua_entropy",
    "ua_alpha_ratio",
    "ua_digit_ratio",
    "ua_unique_ratio",
    "ua_max_repeat",
    "ua_no_space",
    "ua_has_mozilla",
    "ua_has_browser_kw",
    # Időbélyeg
    "hour",
    # Log template
    "template_id",
]


def add_template_id(df: pd.DataFrame) -> tuple[pd.DataFrame, object]:
    """Loglizer Drain vagy fallback LabelEncoder alapján template_id feature."""
    try:
        from loglizer import dataloader, preprocessing
        raise ImportError("Drain API version check – fallback")
    except ImportError:
        df = df.copy()
        df["template"] = (
            df["method"] + " " +
            df["endpoint"] + " " +
            df["status"].astype(str)
        )
        enc = LabelEncoder()
        df["template_id"] = enc.fit_transform(df["template"])
        print(f"  Template-ek  : {df['template_id'].nunique()} egyedi sablon "
              f"(loglizer Drain fallback – LabelEncoder)")
        return df, enc


def build_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, StandardScaler]:
    """Feature mátrix és label vektor előállítása StandardScaler normalizálással."""
    X_raw = df[FEATURE_COLS].fillna(0).values.astype(float)

    label_map = {"normal": 0, "anomaly": 1}
    y = df["label"].map(label_map).values

    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw)

    n_normal  = (y == 0).sum()
    n_anomaly = (y == 1).sum()
    print(f"  Feature-ök   : {X.shape[1]} db")
    print(f"  Normal sorok : {n_normal}")
    print(f"  Anomaly sorok: {n_anomaly}")
    print(f"  Arány        : {n_anomaly / len(y):.1%} anomaly")

    return X, y, scaler


# ─────────────────────────────────────────────────────────────
# 5. DECISION TREE BETANÍTÁS
# ─────────────────────────────────────────────────────────────

def train(X: np.ndarray, y: np.ndarray,
          max_depth: int = 10,
          random_state: int = 42) -> tuple[DecisionTreeClassifier, dict]:
    """Decision Tree betanítása és kiértékelése train/test split-tel."""

    min_class = int(np.bincount(y).min())
    stratify  = y if min_class >= 2 else None

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=random_state,
        stratify=stratify,
    )

    print(f"  Train méret  : {len(X_train)} sor")
    print(f"  Test méret   : {len(X_test)} sor")

    model = DecisionTreeClassifier(
        max_depth=max_depth,
        class_weight="balanced",
        min_samples_leaf=2,
        random_state=random_state,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n  Classification report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["normal", "anomaly"],
        zero_division=0,
    ))

    cm = confusion_matrix(y_test, y_pred)
    print("  Confusion matrix:")
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}   (normált jól/rosszul)")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}   (anomaly jól/rosszul)")

    try:
        auc = roc_auc_score(y_test, y_prob)
        print(f"\n  ROC-AUC: {auc:.4f}")
    except Exception:
        auc = None

    importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
    top10 = importances.sort_values(ascending=False).head(10)
    print("\n  Top-10 feature importance:")
    for feat, val in top10.items():
        bar = "█" * int(val * 30)
        print(f"    {feat:25s} {val:.4f}  {bar}")

    metrics = {
        "confusion_matrix": cm.tolist(),
        "roc_auc":          auc,
    }
    return model, metrics


# ─────────────────────────────────────────────────────────────
# 6. MODELL MENTÉS
# ─────────────────────────────────────────────────────────────

def save(model, scaler, template_enc, feature_cols, metrics, log_filename):
    """Modell és összes szükséges összetevő mentése egyetlen .pkl fájlba."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    out_path = os.path.join(MODEL_DIR, "decision_tree_model.pkl")

    bundle = {
        "model":        model,
        "scaler":       scaler,
        "feature_cols": feature_cols,
        "template_enc": template_enc,
        "metrics":      metrics,
        "trained_on": {
            "file":      log_filename,
            "timestamp": datetime.now().isoformat(),
        },
    }

    with open(out_path, "wb") as f:
        pickle.dump(bundle, f)

    size_kb = os.path.getsize(out_path) / 1024
    print(f"\n  ✓ Modell mentve: {out_path}")
    print(f"    Méret: {size_kb:.1f} KB")
    return out_path


# ─────────────────────────────────────────────────────────────
# 7. MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  DECISION TREE – BETANÍTÓ SCRIPT")
    print("=" * 55)

    log_filename = input("\nAdd meg a log fájl nevét (pl. access.log): ").strip()
    log_path     = os.path.join(DATA_DIR, log_filename)

    if not os.path.isfile(log_path):
        print(f"\n✗ A fájl nem található: {log_path}")
        sys.exit(1)

    print(f"\n[1/4] Log parsing: {log_path}")
    df = load_logs(log_path)

    if df.empty:
        print("✗ Egyetlen érvényes sort sem sikerült beolvasni.")
        sys.exit(1)

    labels_found = df["label"].unique().tolist()
    print(f"  Label-ek     : {labels_found}")
    if "normal" not in labels_found or "anomaly" not in labels_found:
        print("✗ A Decision Tree-hez mindkét label kell (normal + anomaly)!")
        sys.exit(1)

    print("\n[2/4] Template extraction (loglizer / fallback)...")
    df, template_enc = add_template_id(df)

    print("\n[3/4] Feature mátrix építés...")
    X, y, scaler = build_matrix(df)

    print("\n[4/4] Decision Tree betanítás...")
    model, metrics = train(X, y)

    print("\n[Mentés]")
    save(model, scaler, template_enc, FEATURE_COLS, metrics, log_filename)

    print("\n✓ Kész! A modell betöltése inferenciához:")
    print("    import pickle")
    print(f"    bundle = pickle.load(open('{MODEL_DIR}/decision_tree_model.pkl', 'rb'))")
    print("    model  = bundle['model']")
    print("    scaler = bundle['scaler']")


if __name__ == "__main__":
    main()
