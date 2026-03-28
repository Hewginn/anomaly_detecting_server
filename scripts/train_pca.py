"""
PCA – Betanító Script
======================
Fájlútvonalak:
  Script helye : /home/kristofejes/kutatas/anomaly_detecting_server/scripts/
  Log adatok   : /home/kristofejes/kutatas/anomaly_detecting_server/scripts/logs/<log_file>
  Loglizer     : /home/kristofejes/kutatas/loglizer/loglizer/models/

Futtatás:
  python train_pca.py
  → bekéri a log fájl nevét (csak NORMAL logokat tartalmazzon!)

Kimenet:
  /home/kristofejes/kutatas/loglizer/loglizer/models/pca_model.pkl

Log formátum:
  <IP> - - <username> [<timestamp>] "<METHOD> <endpoint> HTTP/<ver>" <status> "<UA>" "<label>"
  Pl.: 10.0.0.5 - - alice [2026-03-28 07:43:33.200000] "POST /api/login HTTP/1.1" 200 "Mozilla/5.0" "normal"

Hogyan működik a PCA anomaly detection?
  1. Csak normal logokon tanul – megtanulja mi a "normál" adatstruktúra
  2. PCA tömörít: n feature → n_components dimenzióra
  3. Majd visszaállítja az eredeti dimenzióra (reconstruction)
  4. Reconstruction error = ||eredeti - visszaállított||²
  5. Normal adat: kis hiba (a PCA jól tudja rekonstruálni)
     Anomália   : nagy hiba (a PCA nem tud mit kezdeni az ismeretlen mintával)
  6. Threshold = a normal hibák 95. percentilise
     Ami felette van → anomália
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

from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler, LabelEncoder
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

LOG_REGEX = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r' - - '
    r'(?P<username>\S+) '
    r'\[(?P<timestamp>[^\]]+)\]'
    r' "(?P<method>\w+) '
    r'(?P<endpoint>\S+) '
    r'HTTP/(?P<http_ver>[\d.]+)"'
    r' (?P<status>\d{3})'
    r' "(?P<user_agent>[^"]*)"'
    r' "(?P<label>normal|anomaly)"'
)

BOT_UA_RE = re.compile(
    r'(python-requests|curl|wget|scrapy|nikto|masscan|nmap|zgrab|bot|crawler)',
    re.IGNORECASE
)

SENSITIVE_RE = re.compile(
    r'(admin|config|passwd|\.env|secret|backup|\.php|\.asp|\.git|\.sql'
    r'|random[a-zA-Z0-9]+)',
    re.IGNORECASE
)

SUSPICIOUS_USERNAMES = {
    "admin", "master", "root", "administrator", "superuser",
    "sa", "sys", "oracle", "postgres", "ubuntu", "pi",
}

# ─────────────────────────────────────────────────────────────
# 2. UA SEGÉDFÜGGVÉNYEK
# ─────────────────────────────────────────────────────────────

def ua_entropy(ua: str) -> float:
    if not ua:
        return 0.0
    freq = {c: ua.count(c) / len(ua) for c in set(ua)}
    return -sum(p * log2(p) for p in freq.values())

def ua_alpha_ratio(ua: str) -> float:
    if not ua:
        return 0.0
    return sum(c.isalpha() for c in ua) / len(ua)

def ua_digit_ratio(ua: str) -> float:
    if not ua:
        return 0.0
    return sum(c.isdigit() for c in ua) / len(ua)

def ua_unique_char_ratio(ua: str) -> float:
    if not ua:
        return 0.0
    return len(set(ua)) / len(ua)

def ua_max_consecutive_same(ua: str) -> int:
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
    """Egy nyers log sort értelmez és feature dict-té alakít."""
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

    octs = list(map(int, ip.split(".")))

    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3,
                  "PATCH": 4, "HEAD": 5, "OPTIONS": 6}
    method_num = method_map.get(method, 99)

    endpoint_depth = len([p for p in endpoint.split("/") if p])
    sensitive_kw   = int(bool(SENSITIVE_RE.search(endpoint)))

    status_2xx = int(200 <= status < 300)
    status_4xx = int(400 <= status < 500)
    status_5xx = int(500 <= status < 600)
    status_401 = int(status == 401)
    status_403 = int(status == 403)
    status_404 = int(status == 404)
    status_405 = int(status == 405)

    username_is_suspicious = int(username.lower() in SUSPICIOUS_USERNAMES)
    username_len           = len(username)

    ua_len            = len(ua)
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
        "ip":         ip,
        "username":   username,
        "method":     method,
        "endpoint":   endpoint,
        "user_agent": ua,
        "label":      label,
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
    """
    Log fájl beolvasása DataFrame-be.
    
    PCA esetén CSAK a normal sorokat használjuk betanításhoz.
    Ha anomaly sorok is vannak a fájlban, azokat kiszűrjük és
    figyelmeztetést írunk ki – de nem állunk le, mert a fájl
    tartalmazhat vegyes adatot is.
    """
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

    # Csak normal sorok a betanításhoz
    n_anomaly = (df["label"] == "anomaly").sum()
    if n_anomaly > 0:
        print(f"  ⚠ Figyelmeztetés: {n_anomaly} anomaly sort kiszűrünk.")
        print(f"    A PCA csak normal logokon tanul!")
        df = df[df["label"] == "normal"].reset_index(drop=True)

    print(f"  Normal sorok : {len(df)} (ezeken tanul a PCA)")
    return df

# ─────────────────────────────────────────────────────────────
# 4. FEATURE MÁTRIX
# ─────────────────────────────────────────────────────────────

FEATURE_COLS = [
    "ip_oct1", "ip_oct2", "ip_oct3", "ip_oct4",
    "method_num", "endpoint_depth", "sensitive_kw",
    "status", "status_2xx", "status_4xx", "status_5xx",
    "status_401", "status_403", "status_404", "status_405",
    "username_is_suspicious", "username_len",
    "ua_len", "ua_is_known_bot", "ua_has_json_chars", "ua_has_injection",
    "ua_entropy", "ua_alpha_ratio", "ua_digit_ratio", "ua_unique_ratio",
    "ua_max_repeat", "ua_no_space", "ua_has_mozilla", "ua_has_browser_kw",
    "hour",
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


def build_matrix(df: pd.DataFrame) -> tuple[np.ndarray, StandardScaler]:
    """
    Feature mátrix előállítása StandardScaler normalizálással.
    
    PCA-nál nincs szükség label vektorra – csak az X mátrix kell.
    """
    X_raw = df[FEATURE_COLS].fillna(0).values.astype(float)

    scaler = StandardScaler()
    X = scaler.fit_transform(X_raw)

    print(f"  Feature-ök   : {X.shape[1]} db")
    print(f"  Minták száma : {X.shape[0]}")
    return X, scaler

# ─────────────────────────────────────────────────────────────
# 5. PCA BETANÍTÁS
# ─────────────────────────────────────────────────────────────

def train_pca(X: np.ndarray,
              n_components: int = 10,
              threshold_percentile: float = 95) -> dict:
    """
    PCA betanítása csak normal adatokon.

    Lépések:
      1. PCA illesztés az X mátrixra (csak normal logok)
      2. Reconstruction error kiszámítása minden sorra:
           error = átlag( (eredeti - visszaállított)² )
      3. Threshold = a hibák <threshold_percentile>. percentilise
         Alapértelmezett 95% → a normal logok 5%-a is "anomáliának" tűnhet,
         de ez elfogadható tűréshatár

    Miért 95% és nem 100%?
      Mert a valódi normal logokban is lehetnek kis eltérések/zajok.
      A 100% threshold túl laza lenne, mindent normalnak mondana.

    Args:
        n_components        : PCA komponensek száma
                              Ökölszabály: annyi hogy az explained variance
                              elérje a 90-95%-ot
        threshold_percentile: hány % alá essen a "normal" zóna
    """
    print(f"\n  PCA komponensek száma: {n_components}")

    pca = PCA(n_components=n_components)
    pca.fit(X)

    # Explained variance – mennyi információt őriz meg a PCA
    explained = pca.explained_variance_ratio_.sum()
    print(f"  Explained variance   : {explained:.3f} "
          f"({explained*100:.1f}% az eredeti információ megőrizve)")

    # Reconstruction error minden normal sorra
    X_reduced       = pca.transform(X)
    X_reconstructed = pca.inverse_transform(X_reduced)
    errors          = np.mean((X - X_reconstructed) ** 2, axis=1)

    print(f"  Reconstruction error (normal logok):")
    print(f"    Min   : {errors.min():.6f}")
    print(f"    Átlag : {errors.mean():.6f}")
    print(f"    Max   : {errors.max():.6f}")

    # Threshold meghatározása
    threshold = float(np.percentile(errors, threshold_percentile))
    print(f"  Threshold ({threshold_percentile}. percentilis): {threshold:.6f}")
    print(f"  → Ennél nagyobb reconstruction error = anomália")

    return {
        "pca":       pca,
        "threshold": threshold,
        "errors":    errors,
        "explained": float(explained),
    }


def validate_with_anomalies(pca_result: dict, scaler: StandardScaler,
                             template_enc: LabelEncoder,
                             val_filepath: str | None) -> None:
    """
    Opcionális validáció: ha megadunk egy vegyes (normal+anomaly) fájlt,
    megmutatja hogy a betanított PCA mennyire teljesít rajta.
    
    Ez NEM befolyásolja a betanítást – csak tájékoztató jellegű.
    """
    if not val_filepath or not os.path.isfile(val_filepath):
        print("\n  (Validációs fájl nem adott meg – kihagyva)")
        return

    print(f"\n  Validáció: {val_filepath}")
    rows = []
    with open(val_filepath, "r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                rows.append(parsed)

    df_val = pd.DataFrame(rows)
    if df_val.empty:
        print("  Validációs fájl üres vagy nem olvasható.")
        return

    # Template ID – az encoder már betanítva, ismeretlen template → 0
    df_val = df_val.copy()
    df_val["template"] = (
        df_val["method"] + " " +
        df_val["endpoint"] + " " +
        df_val["status"].astype(str)
    )
    known = set(template_enc.classes_)
    df_val["template_id"] = df_val["template"].apply(
        lambda t: template_enc.transform([t])[0] if t in known else 0
    )

    X_val = df_val[FEATURE_COLS].fillna(0).values.astype(float)
    X_val_s = scaler.transform(X_val)

    pca = pca_result["pca"]
    X_val_r = pca.inverse_transform(pca.transform(X_val_s))
    val_errors = np.mean((X_val_s - X_val_r) ** 2, axis=1)

    threshold = pca_result["threshold"]
    y_pred = (val_errors > threshold).astype(int)

    label_map = {"normal": 0, "anomaly": 1}
    y_true = df_val["label"].map(label_map).values

    print("\n  Classification report (validáció):")
    print(classification_report(
        y_true, y_pred,
        target_names=["normal", "anomaly"],
        zero_division=0,
    ))
    cm = confusion_matrix(y_true, y_pred)
    print("  Confusion matrix:")
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}   (normált jól/rosszul)")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}   (anomaly jól/rosszul)")
    try:
        auc = roc_auc_score(y_true, val_errors)
        print(f"  ROC-AUC: {auc:.4f}")
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────
# 6. MODELL MENTÉS
# ─────────────────────────────────────────────────────────────

def save(pca_result: dict, scaler: StandardScaler,
         template_enc: LabelEncoder, log_filename: str) -> str:
    """Modell és összes szükséges összetevő mentése egyetlen .pkl fájlba."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    out_path = os.path.join(MODEL_DIR, "pca_model.pkl")

    bundle = {
        "pca":          pca_result["pca"],
        "threshold":    pca_result["threshold"],
        "explained":    pca_result["explained"],
        "scaler":       scaler,
        "feature_cols": FEATURE_COLS,
        "template_enc": template_enc,
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
    print("  PCA ANOMALY DETECTION – BETANÍTÓ SCRIPT")
    print("=" * 55)
    print("  ⚠ Ez a script csak NORMAL logokat vár!")
    print("    Anomaly sorok automatikusan kiszűrésre kerülnek.")

    # ── Betanító fájl ─────────────────────────────────────
    log_filename = input("\nAdd meg a log fájl nevét (pl. normal.log): ").strip()
    log_path     = os.path.join(DATA_DIR, log_filename)

    if not os.path.isfile(log_path):
        print(f"\n✗ A fájl nem található: {log_path}")
        sys.exit(1)

    # ── Opcionális validációs fájl ────────────────────────
    print("\nVan vegyes (normal+anomaly) validációs fájlod? (Enter = kihagyás)")
    val_filename = input("Validációs fájl neve: ").strip()
    val_path = os.path.join(DATA_DIR, val_filename) if val_filename else None

    # ── 1. Parsing ────────────────────────────────────────
    print(f"\n[1/4] Log parsing: {log_path}")
    df = load_logs(log_path)

    if df.empty:
        print("✗ Nem maradt normal sor a betanításhoz.")
        sys.exit(1)

    # ── 2. Template extraction ────────────────────────────
    print("\n[2/4] Template extraction (loglizer / fallback)...")
    df, template_enc = add_template_id(df)

    # ── 3. Feature mátrix ─────────────────────────────────
    print("\n[3/4] Feature mátrix építés...")
    X, scaler = build_matrix(df)

    # ── 4. PCA betanítás ──────────────────────────────────
    print("\n[4/4] PCA betanítás...")

    # n_components automatikus meghatározása:
    # maximum annyi lehet amennyi a feature-ök száma,
    # de legfeljebb 15 (felesleges több komponens)
    n_components = min(15, X.shape[1], X.shape[0] - 1)
    pca_result = train_pca(X, n_components=n_components, threshold_percentile=75)

    # ── Opcionális validáció ──────────────────────────────
    if val_path:
        print("\n[Validáció]")
        validate_with_anomalies(pca_result, scaler, template_enc, val_path)

    # ── Mentés ────────────────────────────────────────────
    print("\n[Mentés]")
    save(pca_result, scaler, template_enc, log_filename)

    print("\n✓ Kész! A modell betöltése inferenciához:")
    print("    import pickle")
    print(f"    bundle = pickle.load(open('{MODEL_DIR}/pca_model.pkl', 'rb'))")
    print("    pca       = bundle['pca']")
    print("    threshold = bundle['threshold']")
    print("    scaler    = bundle['scaler']")


if __name__ == "__main__":
    main()
