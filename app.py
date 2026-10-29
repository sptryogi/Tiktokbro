import streamlit as st
import requests
import time
import hmac
import hashlib
import pandas as pd
from datetime import datetime, timedelta, timezone, time as dtime
from supabase import create_client, Client
import json
from io import BytesIO
import urllib.parse
from pypdf import PdfReader, PdfWriter

WIB = timezone(timedelta(hours=7))
# =================================================================
# PERUBAHAN UTAMA DI FILE INI (ringkasan):
# 1. generate_signature() sekarang menyertakan REQUEST PATH — ini akar
#    masalah kenapa semua API data gagal padahal otorisasi sukses.
#    Tanpa path, signature-nya selalu invalid. Hasil hash juga dibuat
#    lowercase (bukan .upper()) sesuai contoh resmi TikTok.
# 2. Semua endpoint lama /api/v2/... diganti ke skema versi-tanggal
#    yang berlaku sekarang: /authorization/202309/.., /order/202309/..,
#    /product/202309/.., /finance/202309/.., /affiliate_seller/202405/..
# 3. Parameter pagination/sort (page_size, sort_field, sort_order,
#    page_token) sekarang dikirim sebagai QUERY params, bukan di body
#    JSON — hanya kriteria filter asli yang masuk body.
# 4. get_order_detail (loop 1 order per request ke endpoint yang sudah
#    tidak ada) diganti get_order_details_batch (banyak id sekaligus).
# 5. "Settlements search" sudah tidak ada di API TikTok Shop sekarang.
#    Diganti alur "Statements" (periode) -> "Statement Transactions"
#    (rincian per order di dalam periode itu). Semua nama kolom laporan
#    income yang lama saya PERTAHANKAN, tapi sebagian nilainya sekarang
#    hasil SUM dari sku_transactions di dalam 1 order (supaya grain-nya
#    tetap 1 baris/order seperti sebelumnya). Kolom yang saya tandai
#    "~" di komentar adalah pendekatan terbaik (bukan field yang 100%
#    identik namanya), dan yang saya tandai "—" memang tidak ada
#    padanannya di TikTok Shop API (kelihatannya kolom ini aslinya dari
#    template Tokopedia) sehingga akan selalu kosong/0.
# =================================================================

# ─────────────────────────────────────────────
# KONFIGURASI API & DB
# ─────────────────────────────────────────────
# APP_KEY    = st.secrets["TIKTOK_APP_KEY"]
# APP_SECRET = st.secrets["TIKTOK_APP_SECRET"]
APPS = {"default": {"app_key": st.secrets["TIKTOK_APP_KEY"],
                    "app_secret": st.secrets["TIKTOK_APP_SECRET"]}}
for _name, _cfg in (st.secrets.get("apps") or {}).items():
    APPS[_name] = {"app_key": _cfg["app_key"], "app_secret": _cfg["app_secret"]}

APP_KEY, APP_SECRET = APPS["default"]["app_key"], APPS["default"]["app_secret"]

def use_app(app_name):
    """Pilih app yang dipakai semua fungsi API di bawahnya (dibaca saat dipanggil)."""
    global APP_KEY, APP_SECRET
    cfg = APPS.get(app_name or "default") or APPS["default"]
    APP_KEY, APP_SECRET = cfg["app_key"], cfg["app_secret"]
    
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
REDIRECT_URI = "https://tiktokbro.streamlit.app/"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

BASE_URL        = "https://open-api.tiktokglobalshop.com"
AUTH_URL        = "https://auth.tiktok-shops.com"
AUTH_URL_SELLER = "https://services.tiktokshop.com/open/authorize"


# ─────────────────────────────────────────────
# SIGNATURE
# ─────────────────────────────────────────────
def generate_signature(path: str, params: dict, app_secret: str, body: dict = None) -> str:
    """
    Algoritma resmi TikTok Shop:
      string = app_secret + PATH + sorted(key+value semua query param, exclude sign & access_token)
               + json_body (kalau method-nya bukan GET)
               + app_secret
      sign   = HMAC_SHA256(string, app_secret) -> hex LOWERCASE

    'path' WAJIB diikutkan (contoh: "/order/202309/orders/search"). Ini yang
    hilang di versi sebelumnya sehingga semua request bertanda tangan gagal.
    """
    exclude = {"sign", "access_token"}
    sign_params = {k: v for k, v in params.items()
                   if k not in exclude and v is not None}
    sorted_keys = sorted(sign_params.keys())

    base_string = "".join(f"{key}{sign_params[key]}" for key in sorted_keys)
    base_string = path + base_string

    if body:
        base_string += json.dumps(body, separators=(",", ":"), ensure_ascii=False)

    base_string = app_secret + base_string + app_secret

    signature = hmac.new(
        app_secret.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()  # TANPA .upper() -- contoh resmi TikTok pakai lowercase hex
    return signature


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────
# def get_auth_url() -> str:
#     params = {
#         "app_key":      APP_KEY,
#         "state":        "TiktokbroAuth",
#         "redirect_uri": REDIRECT_URI,
#     }
#     return f"{AUTH_URL_SELLER}?{urllib.parse.urlencode(params)}"
def get_auth_url(app_name="default") -> str:
    params = {
        "app_key":      APPS[app_name]["app_key"],
        "state":        app_name,            # dikembalikan TikTok saat redirect
        "redirect_uri": REDIRECT_URI,
    }
    return f"{AUTH_URL_SELLER}?{urllib.parse.urlencode(params)}"

def exchange_auth_code(auth_code: str) -> dict:
    """
    Endpoint token TIDAK butuh signature (app_secret dikirim langsung di
    query param), jadi bagian ini sudah benar dari awal dan tidak diubah.
    """
    url = f"{AUTH_URL}/api/v2/token/get"
    params = {
        "app_key":    APP_KEY,
        "app_secret": APP_SECRET,
        "auth_code":  auth_code,
        "grant_type": "authorized_code",
    }
    try:
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        return result
    except requests.exceptions.RequestException as e:
        return {"code": -1, "message": str(e), "data": {}}


def refresh_access_token(refresh_token: str) -> dict:
    url = f"{AUTH_URL}/api/v2/token/refresh"
    params = {
        "app_key":       APP_KEY,
        "app_secret":    APP_SECRET,
        "refresh_token": refresh_token,
        "grant_type":    "refresh_token",
    }
    try:
        resp = requests.get(url, params=params, timeout=30)
        return resp.json()
    except Exception as e:
        return {"code": -1, "message": str(e)}


def get_authorized_shops(access_token: str) -> list:
    """
    FIX: path lama /api/v2/seller/permissions sudah tidak ada.
    Endpoint sekarang: GET /authorization/202309/shops
    Response juga berubah bentuk: data.shops[] dengan field 'id' & 'cipher'
    (dulu diasumsikan data.authorized_shops[] dengan 'shop_id'/'shop_cipher').
    Kode di bawah coba keduanya supaya tetap jalan kalau ternyata masih
    dikembalikan dengan nama lama.
    """
    timestamp = str(int(time.time()))
    endpoint = "/authorization/202309/shops"
    params = {
        "app_key":   APP_KEY,
        "timestamp": timestamp,
    }
    params["sign"] = generate_signature(endpoint, params, APP_SECRET, None)
    headers = {"x-tts-access-token": access_token}

    url = f"{BASE_URL}{endpoint}"
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=30)
        result = resp.json()
        if result.get("code") == 0:
            data = result.get("data", {})
            return data.get("shops") or data.get("authorized_shops") or []
        return []
    except Exception as e:
        st.warning(f"Gagal ambil authorized shops: {e}")
        return []


# ─────────────────────────────────────────────
# GENERIC API REQUEST
# ─────────────────────────────────────────────
def make_tiktok_request(
    endpoint: str,
    access_token: str,
    shop_cipher: str = None,
    method: str = "GET",
    body: dict = None,
    **extra_params,
) -> dict:
    """
    extra_params sekarang SELALU jadi query string (termasuk page_size,
    sort_field, sort_order, page_token). Untuk endpoint POST search,
    hanya kriteria filter asli yang boleh masuk 'body'.
    """
    timestamp = str(int(time.time()))
    params = {
        "app_key":   APP_KEY,
        "timestamp": timestamp,
    }
    if shop_cipher:
        params["shop_cipher"] = shop_cipher
    for k, v in extra_params.items():
        if v is not None:
            params[k] = v

    params["sign"] = generate_signature(
        endpoint, params, APP_SECRET, body if method.upper() == "POST" else None
    )

    headers = {
        "Content-Type": "application/json",
        "x-tts-access-token": access_token,
    }

    url = f"{BASE_URL}{endpoint}"
    try:
        if method.upper() == "POST":
            body_str = json.dumps(body, separators=(",", ":"), ensure_ascii=False) if body else None
            resp = requests.post(
                url, params=params,
                data=body_str.encode("utf-8") if body_str else None,
                headers=headers, timeout=30
            )
        else:
            resp = requests.get(url, params=params, headers=headers, timeout=30)
        return resp.json()
    except Exception as e:
        return {"code": -1, "message": str(e)}

_make_tiktok_request_once = make_tiktok_request

def make_tiktok_request(*args, **kwargs):
    """Retry otomatis: rate limit (jeda lebih lama), internal error, timeout."""
    result = {}
    for attempt in range(5):
        result = _make_tiktok_request_once(*args, **kwargs)
        code = result.get("code")
        if code == 36009002:                    # too many requests
            time.sleep(3 * (attempt + 1))
        elif code in (36009003, -1):            # internal error / timeout
            time.sleep(1.5 * (attempt + 1))
        else:
            return result
    return result
    

# ─────────────────────────────────────────────
# WAKTU HELPER
# ─────────────────────────────────────────────
def to_wib(utc_timestamp) -> str:
    if not utc_timestamp:
        return ""
    try:
        if isinstance(utc_timestamp, str):
            utc_time = datetime.fromisoformat(utc_timestamp.replace("Z", "+00:00"))
        else:
            utc_time = datetime.fromtimestamp(utc_timestamp, tz=timezone.utc)
        return (utc_time + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(utc_timestamp)


def epoch_to_wib(epoch_val) -> str:
    if not epoch_val:
        return ""
    try:
        utc_time = datetime.fromtimestamp(epoch_val, tz=timezone.utc)
        return (utc_time + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


# ─────────────────────────────────────────────
# API FETCHERS
# ─────────────────────────────────────────────
def get_all_orders(access_token, shop_cipher, start_time, end_time):
    all_orders, page_token = [], None
    for _ in range(100):
        body = {
            "create_time_ge": int(start_time.timestamp()),
            "create_time_lt": int(end_time.timestamp()),
        }
        query = {
            "page_size":  50,
            "sort_field": "create_time",
            "sort_order": "ASC",
        }
        if page_token:
            query["page_token"] = page_token

        result = make_tiktok_request(
            "/order/202309/orders/search",
            access_token, shop_cipher,
            method="POST",
            body=body,
            **query,
        )

        if result.get("code") == 0:
            data   = result.get("data", {})
            orders = data.get("order_list") or data.get("orders") or []

            all_orders.extend(orders)
            page_token = data.get("next_page_token")
            if not page_token or not orders:
                break
        else:
            st.error(f"Error pesanan: {result.get('message')}")
            st.json(result)
            break
    return all_orders


def get_order_details_batch(access_token, shop_cipher, order_ids, progress_bar=None):
    """
    FIX: endpoint detail per-order yang lama (/api/v2/order/orders/detail)
    sudah tidak ada. Sekarang satu endpoint bisa ambil banyak order sekaligus:
    GET /order/202309/orders?ids=id1,id2,...  (batch, bukan loop per order).
    """
    all_details = []
    order_ids = [oid for oid in order_ids if oid]
    chunks = [order_ids[i:i + 50] for i in range(0, len(order_ids), 50)]

    for idx, chunk in enumerate(chunks):
        result = make_tiktok_request(
            "/order/202309/orders",
            access_token, shop_cipher,
            method="GET",
            ids=",".join(chunk),
        )
        if result.get("code") == 0:
            data = result.get("data", {})
            all_details.extend(data.get("orders") or data.get("order_list") or [])
        else:
            st.error(f"Error detail pesanan: {result.get('message')}")
            st.json(result)

        if progress_bar:
            progress_bar.progress((idx + 1) / len(chunks))

    return all_details


def get_statements(access_token, shop_cipher, start_time, end_time):
    """
    FIX konseptual: 'settlements search' (POST /api/v2/finance/settlements/search)
    sudah tidak ada di API TikTok Shop sekarang. Diganti 'Statements' — daftar
    periode settlement. Rincian per-order ada di get_statement_transactions().
    """
    all_statements, page_token = [], None
    for _ in range(100):
        query = {
            "sort_field":         "statement_time",
            "statement_time_ge":  int(start_time.timestamp()),
            "statement_time_lt":  int(end_time.timestamp()),
            "page_size":          50,
        }
        if page_token:
            query["page_token"] = page_token

        result = make_tiktok_request(
            "/finance/202309/statements",
            access_token, shop_cipher,
            method="GET",
            **query,
        )

        if result.get("code") == 0:
            data = result.get("data", {})
            statements = data.get("statements") or data.get("statement_list") or []
            all_statements.extend(statements)
            page_token = data.get("next_page_token")
            if not page_token or not statements:
                break
        else:
            st.error(f"Error statement: {result.get('message')}")
            st.json(result)
            break
    return all_statements


def get_statement_transactions(access_token, shop_cipher, statement_id):
    """
    Rincian transaksi per-order di dalam 1 statement.
    GET /finance/202309/statements/{statement_id}/statement_transactions
    """
    all_tx, page_token = [], None
    for _ in range(100):
        query = {"sort_field": "order_create_time", "page_size": 50}
        if page_token:
            query["page_token"] = page_token

        result = make_tiktok_request(
            f"/finance/202501/statements/{statement_id}/statement_transactions",
            access_token, shop_cipher,
            method="GET",
            **query,
        )

        if result.get("code") == 0:
            data = result.get("data", {})
            tx = data.get("transactions") or data.get("statement_transactions") or data.get("list") or []

            all_tx.extend(tx)
            page_token = data.get("next_page_token")
            if not page_token or not tx:
                break
        else:
            st.warning(f"Error statement_transactions ({statement_id}): {result.get('message')}")
            break
    return all_tx

def get_product_title(access_token, shop_cipher, product_id, cache):
    if not product_id:
        return ""
    if product_id not in cache:
        r = make_tiktok_request(f"/product/202309/products/{product_id}",
                                access_token, shop_cipher, method="GET")
        cache[product_id] = (r.get("data") or {}).get("title", "") if r.get("code") == 0 else ""
    return cache[product_id]

def get_product_info(access_token, shop_cipher, product_id, cache):
    """Judul, berat (kg), kategori leaf dari Get Product detail. Pakai cache -> 1 produk 1 panggilan."""
    if not product_id:
        return {}
    if product_id not in cache:
        time.sleep(0.2)
        r = make_tiktok_request(f"/product/202309/products/{product_id}",
                                access_token, shop_cipher, method="GET")
        info = {}
        if r.get("code") == 0:
            d = r.get("data") or {}
            w = d.get("package_weight") or {}
            try:
                wv = float(w.get("value") or 0)
            except (TypeError, ValueError):
                wv = 0
            wkg = wv * 0.4536 if (w.get("unit") or "").upper() == "POUND" else wv
            chains = d.get("category_chains") or []
            leaf = next((c for c in chains if c.get("is_leaf")), chains[-1] if chains else {})
            info = {"title": d.get("title", ""), "weight_kg": round(wkg, 3),
                    "category": leaf.get("local_name", "")}
        cache[product_id] = info
    return cache[product_id]


def get_product_title(access_token, shop_cipher, product_id, cache):   # menggantikan versi sebelumnya
    return get_product_info(access_token, shop_cipher, product_id, cache).get("title", "")


def get_returns_by_orders(access_token, shop_cipher, start_time, order_ids):
    """Tarik semua retur sejak start_time (sedikit panggilan), lalu filter ke order yang ada."""
    wanted = {o for o in order_ids if o}
    body = {"create_time_ge": int(start_time.timestamp()),
            "create_time_lt": int(datetime.now(timezone.utc).timestamp())}
    result_map, shown, page_token = {}, False, None

    for _ in range(100):
        query = {"page_size": 50}
        if page_token:
            query["page_token"] = page_token
        res = make_tiktok_request("/return_refund/202309/returns/search",
                                  access_token, shop_cipher,
                                  method="POST", body=body, **query)
        if res.get("code") != 0:
            st.warning(f"Return API: {res.get('code')} {res.get('message')}")
            break
        data = res.get("data") or {}
        rets = data.get("return_orders") or data.get("returns") or []
        if rets and not shown:
            st.write("🔍 Debug 1 return:", rets[0]); shown = True   # hapus setelah cocok

        for r in rets:
            oid = r.get("order_id")
            if oid not in wanted:
                continue
            status = (r.get("return_status") or r.get("status") or "").upper()
            if "REJECT" in status or "CANCEL" in status:
                continue
            m = result_map.setdefault(oid, {"refund": 0.0, "type": "", "sku_qty": {}})
            ra = r.get("refund_amount") or {}
            m["refund"] += float(ra.get("refund_total") or 0)
            m["type"] = r.get("return_type") or m["type"]
            for li in r.get("return_line_items") or []:
                m["sku_qty"][li.get("sku_id")] = m["sku_qty"].get(li.get("sku_id"), 0) + 1

        page_token = data.get("next_page_token")
        if not page_token or not rets:
            break
        time.sleep(0.5)          # jeda antar halaman
    return result_map

def get_shipping_label_url(access_token, shop_cipher, package_id, size="A6"):
    """Return (doc_url, error). Link berlaku 24 jam, jadi langsung diunduh."""
    res = make_tiktok_request(
        f"/fulfillment/202309/packages/{package_id}/shipping_documents",
        access_token, shop_cipher, method="GET",
        document_type="SHIPPING_LABEL_AND_PACKING_SLIP",   # ← sebelumnya SHIPPING_LABEL
        document_size=size, document_format="PDF",
    )
    if res.get("code") == 0:
        return (res.get("data") or {}).get("doc_url", ""), ""
    return "", f"{res.get('code')} {res.get('message')}"


def build_label_pdf(access_token, shop_cipher, orders, size="A6", progress_bar=None):
    """Gabungkan semua resi jadi 1 PDF. Diurutkan per kurir lalu waktu pesanan."""
    writer, ok, failed, seen = PdfWriter(), 0, [], set()
    orders = sorted(orders, key=lambda o: (o.get("shipping_provider") or "", o.get("create_time") or 0))

    for idx, o in enumerate(orders):
        for pkg in o.get("packages") or []:
            pid = pkg.get("id")
            if not pid or pid in seen:
                continue
            seen.add(pid)

            url, err = get_shipping_label_url(access_token, shop_cipher, pid, size)
            if not url:
                failed.append((o.get("id"), pid, err))
                continue
            try:
                r = requests.get(url, timeout=60)
                r.raise_for_status()
                for page in PdfReader(BytesIO(r.content)).pages:
                    writer.add_page(page)
                ok += 1
            except Exception as e:
                failed.append((o.get("id"), pid, str(e)))
            time.sleep(0.2)

        if progress_bar and orders:
            progress_bar.progress((idx + 1) / len(orders))

    out = BytesIO()
    if ok:
        writer.write(out)
    out.seek(0)
    return out, ok, failed
    
def get_products(access_token, shop_cipher):
    all_products, page_token = [], None
    for _ in range(100):
        body = {"status": "ACTIVATE"}
        query = {"page_size": 50}
        if page_token:
            query["page_token"] = page_token

        result = make_tiktok_request(
            "/product/202309/products/search",
            access_token, shop_cipher,
            method="POST",
            body=body,
            **query,
        )

        if result.get("code") == 0:
            data     = result.get("data", {})
            products = data.get("products") or data.get("product_list") or []

            all_products.extend(products)
            page_token = data.get("next_page_token")
            if not page_token or not products:
                break
        else:
            st.error(f"Error produk: {result.get('message')}")
            st.json(result)
            break
    return all_products

def get_order_finance_transactions(access_token, shop_cipher, order_id):
    result = make_tiktok_request(
        f"/finance/202501/orders/{order_id}/statement_transactions",   # ← 202501
        access_token, shop_cipher, method="GET",
    )
    if result.get("code") != 0:
        return {"_error": f"{result.get('code')} {result.get('message')}"}
    data = result.get("data", {}) or {}
    txs = data.get("statement_transactions")
    if txs:   # bentuk 202501: list -> gabungkan jadi 1 dict
        merged = dict(txs[0])
        merged["sku_transactions"] = [s for t in txs for s in (t.get("sku_transactions") or [])]
        merged.setdefault("currency", data.get("currency", "IDR"))
        return merged
    return data


def get_product_ads_performance(access_token, shop_cipher, start_time, end_time, progress_bar=None):
    orders = get_all_orders(access_token, shop_cipher, start_time, end_time)
    per_product = {}

    def _f(v):
        try:
            return float(v or 0)
        except (TypeError, ValueError):
            return 0.0

    # sku_id -> (product_id, nama produk), dari line_items order
    info_by_sku = {}
    for o in orders:
        for li in o.get("line_items", []):
            info_by_sku[li.get("sku_id")] = (li.get("product_id") or "", li.get("product_name") or "Unknown")

    shown_err = False
    for idx, o in enumerate(orders):
        order_id = o.get("id")
        if order_id:
            detail = get_order_finance_transactions(access_token, shop_cipher, order_id)
            if detail.get("_error") and not shown_err:
                st.warning(f"Finance API error: {detail['_error']}"); shown_err = True

            currency = detail.get("currency", "IDR")
            for sku in detail.get("sku_transactions", []):
                pid, pname = info_by_sku.get(sku.get("sku_id"),
                                             ("", sku.get("product_name") or "Unknown"))
                key = pid or pname
                fee = (sku.get("fee_tax_breakdown") or {}).get("fee") or {}
                row = per_product.setdefault(key, {"product_id": pid, "name": pname,
                                                   "revenue": 0.0, "ad_cost": 0.0,
                                                   "orders": 0, "currency": currency})
                row["revenue"] += _f(sku.get("revenue_amount"))
                row["ad_cost"] += abs(_f(fee.get("gmv_max_ad_fee_amount")))
                row["orders"]  += 1

        if progress_bar and orders:
            progress_bar.progress((idx + 1) / len(orders))
    return per_product

def format_product_ads_excel(per_product):
    cols = ["ID Produk", "Nama Produk", "Pesanan SKU", "Pendapatan Kotor",
            "Biaya", "Biaya per Pesanan", "ROI", "Mata Uang"]
    rows = []
    for d in per_product.values():
        cost, orders, rev = d["ad_cost"], d["orders"], d["revenue"]
        rows.append({
            "ID Produk":         str(d["product_id"]),          # teks, supaya angka panjang tidak rusak di Excel
            "Nama Produk":       d["name"],
            "Pesanan SKU":       orders,
            "Pendapatan Kotor":  rev,
            "Biaya":             cost,
            "Biaya per Pesanan": round(cost / orders, 2) if orders else 0,
            "ROI":               round(rev / cost, 2) if cost else 0,
            "Mata Uang":         d["currency"],
        })
    df = pd.DataFrame(rows, columns=cols)
    return df.sort_values("Pendapatan Kotor", ascending=False).reset_index(drop=True)

ADS_BASE = "https://business-api.tiktok.com/open_api/v1.3"


def get_gmv_max_stores(cfg):
    """Bantu cari store_id: daftar store yang terhubung ke advertiser."""
    try:
        return requests.get(f"{ADS_BASE}/gmv_max/store/list/",
                            params={"advertiser_id": cfg["advertiser_id"]},
                            headers={"Access-Token": cfg["access_token"]}, timeout=30).json()
    except Exception as e:
        return {"error": str(e)}


def _gmv_report(cfg, dimensions, metrics, start_date, end_date, filtering=None):
    rows, page = [], 1
    while page <= 50:
        params = {
            "advertiser_id": cfg["advertiser_id"],
            "store_ids":     json.dumps([str(cfg["store_id"])]),
            "dimensions":    json.dumps(dimensions),
            "metrics":       json.dumps(metrics),
            "start_date":    f"{start_date:%Y-%m-%d}",
            "end_date":      f"{end_date:%Y-%m-%d}",
            "page": page, "page_size": 1000,
        }
        if filtering:
            params["filtering"] = json.dumps(filtering)
        try:
            res = requests.get(f"{ADS_BASE}/gmv_max/report/get/", params=params,
                               headers={"Access-Token": cfg["access_token"]}, timeout=60).json()
        except Exception as e:
            st.error(f"GMV Max request gagal: {e}"); break
        if res.get("code") != 0:
            st.error(f"GMV Max API: {res.get('code')} {res.get('message')}"); break
        data = res.get("data") or {}
        rows.extend(data.get("list") or [])
        if page >= (data.get("page_info") or {}).get("total_page", 1):
            break
        page += 1
        time.sleep(0.3)
    return rows


def get_gmv_max_product_report(cfg, start_date, end_date):
    promo = ["PRODUCT"]
    # 1) campaign yang punya aktivitas (biaya / pesanan) di periode ini
    camp_rows = _gmv_report(cfg, ["campaign_id"], ["cost", "orders", "gross_revenue", "roi"], start_date, end_date,
                            {"gmv_max_promotion_types": promo})
    camp_ids = [(r.get("dimensions") or {}).get("campaign_id") for r in camp_rows]
    camp_ids = [c for c in dict.fromkeys(camp_ids) if c]
    n_cost = sum(1 for r in camp_rows if float((r.get("metrics") or {}).get("cost") or 0) > 0)
    st.caption(f"{len(camp_ids)} campaign GMV Max ditemukan di periode ini ({n_cost} berbiaya)")

    # 2) per campaign: laporan level produk
    rows = []
    for cid in camp_ids:
        rows.extend(_gmv_report(
            cfg, ["item_group_id"],
            ["cost", "orders", "cost_per_order", "gross_revenue", "roi"],
            start_date, end_date,
            {"campaign_ids": [cid]},          # ← hanya campaign_ids
        ))
        time.sleep(0.3)
    return rows


def format_gmv_max_excel(rows, access_token, shop_cipher, only_cost=False):
    agg = {}
    for r in rows:
        d, m = r.get("dimensions") or {}, r.get("metrics") or {}
        pid = str(d.get("item_group_id") or "")
        a = agg.setdefault(pid, {"orders": 0.0, "cost": 0.0, "rev": 0.0, "cur": m.get("currency") or "IDR"})
        a["orders"] += float(m.get("orders") or 0)
        a["cost"]   += float(m.get("cost") or 0)
        a["rev"]    += float(m.get("gross_revenue") or 0)

    cache, out = {}, []
    for pid, a in agg.items():
        out.append({
            "ID Produk":         pid,   # teks, supaya angka panjang tidak rusak di Excel
            "Nama Produk":       get_product_title(access_token, shop_cipher, pid, cache) or "(nama tidak ditemukan)",
            "Pesanan SKU":       int(a["orders"]),
            "Pendapatan Kotor":  a["rev"],
            "Biaya":             a["cost"],
            "Biaya per Pesanan": round(a["cost"] / a["orders"], 2) if a["orders"] else 0,
            "ROI":               round(a["rev"] / a["cost"], 2) if a["cost"] else 0,
            "Mata Uang":         a["cur"],
        })
    cols = ["ID Produk", "Nama Produk", "Pesanan SKU", "Pendapatan Kotor",
            "Biaya", "Biaya per Pesanan", "ROI", "Mata Uang"]
    df = pd.DataFrame(out, columns=cols)
    if only_cost:
        df = df[df["Biaya"] > 0]
    return df.sort_values(["Biaya", "Pendapatan Kotor"], ascending=False).reset_index(drop=True)

def get_affiliate_orders(access_token, shop_cipher, start_time, end_time):
    all_orders, page_token = [], None
    for _ in range(100):
        body = {
            "create_time_ge": int(start_time.timestamp()),
            "create_time_lt": int(end_time.timestamp()),
        }
        # PASTIKAN parameter query ini sesuai dokumentasi TikTok Shop Affiliate
        query = {"page_size": 50} 
        if page_token:
            query["page_token"] = page_token

        result = make_tiktok_request(
            "/affiliate_seller/202410/orders/search", # Pastikan path ini benar
            access_token, shop_cipher,
            method="POST",
            body=body,
            **query,
        )

        if result.get("code") == 0:
            data   = result.get("data", {})
            # TikTok API mengembalikan key 'orders' atau 'order_list'
            orders = data.get("orders") or data.get("order_list") or []
            all_orders.extend(orders)
            page_token = data.get("next_page_token")
            if not page_token or not orders:
                break
        else:
            st.warning(f"Affiliate API Error: {result.get('message')}")
            st.json(result)
            break
    return all_orders


# ─────────────────────────────────────────────
# FORMATTING → DATAFRAME
# ─────────────────────────────────────────────
# def format_orders_excel(orders_data, order_details):
#     rows         = []
#     details_dict = {d.get("order_id"): d for d in order_details if d}

#     for order in orders_data:
#         order_id  = order.get("order_id")
#         detail    = details_dict.get(order_id, {})

#         created_time   = epoch_to_wib(order.get("create_time"))
#         paid_time      = epoch_to_wib(order.get("paid_time"))
#         rts_time       = epoch_to_wib(order.get("rts_time"))
#         shipped_time   = epoch_to_wib(order.get("shipped_time"))
#         delivered_time = epoch_to_wib(order.get("delivered_time"))
#         cancelled_time = epoch_to_wib(order.get("cancelled_time"))

#         buyer_info     = detail.get("buyer_info", {})
#         recipient_info = detail.get("recipient_info", {})
#         payment_info   = detail.get("payment_info", {})
#         shipping_info  = detail.get("shipping_info", {})
#         items          = detail.get("item_list", [])

#         base = {
#             "Order ID":              order_id,
#             "Order Status":          order.get("order_status", ""),
#             "Order Substatus":       order.get("order_sub_status", ""),
#             "Shipping Fee After Discount":   order.get("shipping_fee", 0),
#             "Original Shipping Fee":         order.get("original_shipping_fee", 0),
#             "Order Refund Amount":           order.get("refund_amount", 0),
#             "Order Amount":                  order.get("total_amount", 0),
#             "Created Time":          created_time,
#             "Paid Time":             paid_time,
#             "RTS Time":              rts_time,
#             "Shipped Time":          shipped_time,
#             "Delivered Time":        delivered_time,
#             "Cancelled Time":        cancelled_time,
#             "Cancel By":             order.get("cancel_user", ""),
#             "Cancel Reason":         order.get("cancel_reason", ""),
#             "Fulfillment Type":      shipping_info.get("fulfillment_type", ""),
#             "Warehouse Name":        shipping_info.get("warehouse_name", ""),
#             "Tracking ID":           shipping_info.get("tracking_number", ""),
#             "Delivery Option":       shipping_info.get("delivery_option", ""),
#             "Shipping Provider Name": shipping_info.get("shipping_provider_name", ""),
#             "Buyer Message":         buyer_info.get("buyer_message", ""),
#             "Buyer Username":        buyer_info.get("buyer_nickname", ""),
#             "Recipient":             recipient_info.get("name", ""),
#             "Phone #":               recipient_info.get("phone", ""),
#             "Zipcode":               recipient_info.get("zipcode", ""),
#             "Country":               recipient_info.get("country", ""),
#             "Province":              recipient_info.get("state", ""),
#             "Regency and City":      recipient_info.get("city", ""),
#             "Districts":             recipient_info.get("district", ""),
#             "Villages":              recipient_info.get("village", ""),
#             "Detail Address":        recipient_info.get("full_address", ""),
#             "Additional address information": recipient_info.get("address_detail", ""),
#             "Payment Method":        payment_info.get("payment_method", ""),
#             "Purchase Channel":      order.get("purchase_channel", ""),
#             "Seller Note":           order.get("seller_note", ""),
#             "Tokopedia Invoice Number": order.get("tokopedia_invoice", ""),
#         }

#         if not items:
#             rows.append({
#                 **base,
#                 "Cancelation/Return Type":  "",
#                 "Normal or Pre-order":      "Normal",
#                 "SKU ID": "", "Seller SKU": "", "Product Name": "",
#                 "Variation": "", "Quantity": 0, "Sku Quantity of return": 0,
#                 "SKU Unit Original Price": 0, "SKU Subtotal Before Discount": 0,
#                 "SKU Platform Discount": 0, "SKU Seller Discount": 0,
#                 "SKU Subtotal After Discount": 0,
#                 "Shipping Fee Seller Discount": 0, "Shipping Fee Platform Discount": 0,
#                 "Distance Shipping Fee": 0, "Distance Fee": 0,
#                 "Payment platform discount": 0, "Buyer Service Fee": 0,
#                 "Handling Fee": 0, "Shipping Insurance": 0, "Item Insurance": 0,
#                 "Weight(kg)": 0, "Product Category": "", "Package ID": "",
#                 "Checked Status": "", "Checked Marked by": "",
#             })
#         else:
#             for item in items:
#                 rows.append({
#                     **base,
#                     "Cancelation/Return Type": item.get("return_type", ""),
#                     "Normal or Pre-order": "Pre-order" if item.get("is_pre_order") else "Normal",
#                     "SKU ID":       item.get("sku_id", ""),
#                     "Seller SKU":   item.get("seller_sku", ""),
#                     "Product Name": item.get("product_name", ""),
#                     "Variation":    item.get("variation_name", ""),
#                     "Quantity":     item.get("quantity", 0),
#                     "Sku Quantity of return": item.get("return_quantity", 0),
#                     "SKU Unit Original Price":        item.get("original_price", 0),
#                     "SKU Subtotal Before Discount":   item.get("subtotal_before_discount", 0),
#                     "SKU Platform Discount":          item.get("platform_discount", 0),
#                     "SKU Seller Discount":            item.get("seller_discount", 0),
#                     "SKU Subtotal After Discount":    item.get("subtotal_after_discount", 0),
#                     "Shipping Fee Seller Discount":   item.get("shipping_fee_seller_discount", 0),
#                     "Shipping Fee Platform Discount": item.get("shipping_fee_platform_discount", 0),
#                     "Distance Shipping Fee":          item.get("distance_shipping_fee", 0),
#                     "Distance Fee":                   item.get("distance_fee", 0),
#                     "Payment platform discount":      item.get("payment_platform_discount", 0),
#                     "Buyer Service Fee":              item.get("buyer_service_fee", 0),
#                     "Handling Fee":                   item.get("handling_fee", 0),
#                     "Shipping Insurance":             item.get("shipping_insurance", 0),
#                     "Item Insurance":                 item.get("item_insurance", 0),
#                     "Weight(kg)":        item.get("weight", 0) / 1000 if item.get("weight") else 0,
#                     "Product Category":  item.get("category_name", ""),
#                     "Package ID":        item.get("package_id", ""),
#                     "Checked Status":    item.get("checked_status", ""),
#                     "Checked Marked by": item.get("checked_by", ""),
#                 })
#     return pd.DataFrame(rows)
def _district(district_info, level_name):
    for d in district_info or []:
        if (d.get("address_level_name") or "").lower() == level_name.lower():
            return d.get("address_name", "")
    return ""

def _merge_items(items):
    """Gabungkan line_item dengan sku_id & package yang sama jadi 1 baris + qty."""
    out = {}
    for it in items:
        k = (it.get("sku_id"), it.get("package_id"))
        m = out.setdefault(k, {**it, "_qty": 0, "_orig": 0.0, "_plat": 0.0,
                               "_sell": 0.0, "_sale": 0.0, "_bsf": 0.0})
        m["_qty"]  += 1
        m["_orig"] += float(it.get("original_price") or 0)
        m["_plat"] += float(it.get("platform_discount") or 0)
        m["_sell"] += float(it.get("seller_discount") or 0)
        m["_sale"] += float(it.get("sale_price") or 0)
        m["_bsf"]  += float(it.get("buyer_service_fee") or 0)
    return list(out.values())

def _substatus(o):
    s = (o.get("status") or "").upper()
    if o.get("is_on_hold_order"):
        return "On hold (under review)"
    mapping = {
        "UNPAID":              "Awaiting buyer payment",
        "ON_HOLD":             "On hold (under review)",
        "AWAITING_SHIPMENT":   "To ship - needs to be arranged",
        "PARTIALLY_SHIPPING":  "Partially shipped",
        "AWAITING_COLLECTION": "Shipment arranged - awaiting courier pickup",
        "IN_TRANSIT":          "Shipped - in transit",
        "DELIVERED":           "Delivered - awaiting completion",
        "COMPLETED":           "Completed",
    }
    if s == "CANCELLED":
        who = o.get("cancellation_initiator") or "UNKNOWN"
        return f"Cancelled by {who.title()}"
    return mapping.get(s, s)
    
def format_orders_excel(orders_data, order_details, returns=None, products=None):
    rows = []
    details_dict = {d.get("id"): d for d in order_details if d}

    for order in orders_data:
        o = {**order, **details_dict.get(order.get("id"), {})}  # detail nimpa order kalau ada

        ret = (returns or {}).get(o.get("id"), {})
        payment    = o.get("payment", {})
        recipient  = o.get("recipient_address", {})
        district   = recipient.get("district_info", [])
        items      = o.get("line_items", [])

        base = {
            "Order ID":              o.get("id", ""),
            "Order Status":          o.get("status", ""),
            "Order Substatus": _substatus(o),
            "Shipping Fee After Discount":   payment.get("shipping_fee", 0),
            "Original Shipping Fee":         payment.get("original_shipping_fee", 0),
            "Order Refund Amount": ret.get("refund", 0),
            "Order Amount":                  payment.get("total_amount", 0),
            "Created Time":          epoch_to_wib(o.get("create_time")),
            "Paid Time":             epoch_to_wib(o.get("paid_time")),
            "RTS Time":              epoch_to_wib(o.get("rts_time")),
            "Shipped Time":    epoch_to_wib(o.get("collection_time")),      # sebelumnya shipped_time
            "Delivered Time":  epoch_to_wib(o.get("delivery_time")),        # sebelumnya delivered_time
            "Cancelled Time":  epoch_to_wib(o.get("cancel_time")),          # sebelumnya cancelled_time
            "Cancel By":       o.get("cancellation_initiator", ""),         # sebelumnya cancel_user
            "Cancel Reason":   o.get("cancel_reason", ""),
            "Fulfillment Type":      o.get("fulfillment_type", ""),
            "Warehouse Name":        o.get("warehouse_id", ""),  # cuma ID, nama gudang nggak tersedia
            "Tracking ID":           o.get("tracking_number", ""),
            "Delivery Option":       o.get("delivery_option_name", ""),
            "Shipping Provider Name": o.get("shipping_provider", ""),
            "Buyer Message":         o.get("buyer_message", ""),
            "Buyer Username":        o.get("buyer_email", ""),  # nickname nggak ada, email dipakai sbg identitas
            "Recipient":             recipient.get("name", ""),
            "Phone #":               recipient.get("phone_number", ""),
            "Zipcode":               recipient.get("postal_code", ""),
            "Country":               _district(district, "Country"),
            "Province":              _district(district, "province"),
            "Regency and City": _district(district, "city") or _district(district, "regency"),
            "Districts":             _district(district, "Sub-district"),
            "Villages":        _district(district, "Urban Community") or _district(district, "Village"),
            "Detail Address":        recipient.get("address_detail", ""),
            "Additional address information": recipient.get("full_address", ""),
            "Payment Method":        o.get("payment_method_name", ""),
            "Purchase Channel":      o.get("commerce_platform", ""),
            "Seller Note":           o.get("seller_note", ""),
            "Tokopedia Invoice Number": "",  # kolom Tokopedia, tidak ada di TikTok
        }

        if not items:
            rows.append({
                **base,
                "Cancelation/Return Type": "", "Normal or Pre-order": "Normal",
                "SKU ID": "", "Seller SKU": "", "Product Name": "",
                "Variation": "", "Quantity": 0, "Sku Quantity of return": 0,
                "SKU Unit Original Price": 0, "SKU Subtotal Before Discount": 0,
                "SKU Platform Discount": 0, "SKU Seller Discount": 0,
                "SKU Subtotal After Discount": 0,
                "Shipping Fee Seller Discount": 0, "Shipping Fee Platform Discount": 0,
                "Distance Shipping Fee": 0, "Distance Fee": 0,
                "Payment platform discount": 0, "Buyer Service Fee": 0,
                "Handling Fee": 0, "Shipping Insurance": 0, "Item Insurance": 0,
                "Weight(kg)": 0, "Product Category": "", "Package ID": "",
                "Checked Status": "", "Checked Marked by": "",
            })
        else:
            for item in _merge_items(items):
                pinfo = (products or {}).get(item.get("product_id"), {})
                rows.append({
                    **base,
                    "Cancelation/Return Type": "Cancel" if o.get("status") == "CANCELLED" else ret.get("type", ""),
                    "Normal or Pre-order": "Pre-order" if item.get("sku_type") == "PRE_ORDER" else "Normal",
                    "SKU ID":       item.get("sku_id", ""),
                    "Seller SKU":   item.get("seller_sku", ""),
                    "Product Name": item.get("product_name", ""),
                    "Variation":    item.get("sku_name", ""),
                    "Quantity":                     item["_qty"],
                    "Sku Quantity of return":  ret.get("sku_qty", {}).get(item.get("sku_id"), 0),
                    "SKU Unit Original Price":      item["_orig"] / item["_qty"],
                    "SKU Subtotal Before Discount": item["_orig"],
                    "SKU Platform Discount":        item["_plat"],
                    "SKU Seller Discount":          item["_sell"],
                    "SKU Subtotal After Discount":  item["_sale"],
                    "Shipping Fee Seller Discount":   payment.get("shipping_fee_seller_discount", 0),
                    "Shipping Fee Platform Discount": payment.get("shipping_fee_platform_discount", 0),
                    "Distance Shipping Fee":          0,
                    "Distance Fee":                   0,
                    "Payment platform discount":      payment.get("platform_discount", 0),
                    "Buyer Service Fee":            item["_bsf"],
                    "Handling Fee":                   payment.get("handling_fee", 0),
                    "Shipping Insurance":             0,
                    "Item Insurance":                 0,
                    "Weight(kg)":              pinfo.get("weight_kg", 0),
                    "Product Category":        pinfo.get("category", ""),
                    "Package ID":        item.get("package_id", ""),
                    "Checked Status":    "",
                    "Checked Marked by": "",
                })
    df = pd.DataFrame(rows)
    money_cols = [
        "Shipping Fee After Discount", "Original Shipping Fee", "Order Refund Amount", "Order Amount",
        "SKU Unit Original Price", "SKU Subtotal Before Discount", "SKU Platform Discount",
        "SKU Seller Discount", "SKU Subtotal After Discount", "Shipping Fee Seller Discount",
        "Shipping Fee Platform Discount", "Distance Shipping Fee", "Distance Fee",
        "Payment platform discount", "Buyer Service Fee", "Handling Fee",
        "Shipping Insurance", "Item Insurance", "Weight(kg)",
    ]
    for c in money_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    return df

def _sum_path(sku_transactions, *path):
    """
    Jumlahkan satu field numerik dari SEMUA sku_transactions dalam 1 order,
    supaya baris laporan tetap 1 baris/order (sama seperti skema lama).
    Contoh: _sum_path(tx["sku_transactions"], "fee_tax_breakdown", "fee",
                       "platform_commission_amount")
    """
    total = 0.0
    for sku in sku_transactions or []:
        node = sku
        for key in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        if node is not None:
            try:
                total += float(node)
            except (TypeError, ValueError):
                pass
    return total

def _deep(node, *names, default=0):
    """Cari salah satu key (nama alternatif) di seluruh nested dict, level paling dangkal dulu."""
    queue = [node]
    while queue:
        cur = queue.pop(0)
        if isinstance(cur, dict):
            for n in names:
                v = cur.get(n)
                if v not in (None, "") and not isinstance(v, (dict, list)):
                    try:
                        return float(v)
                    except (TypeError, ValueError):
                        pass
            queue.extend(v for v in cur.values() if isinstance(v, (dict, list)))
        elif isinstance(cur, list):
            queue.extend(cur)
    return default

def format_income_excel(transactions):
    rows = []
    for t in transactions:
        g = lambda *n: _deep(t, *n)

        gross   = g("subtotal_before_discount_amount", "gross_sales_amount")
        sdisc   = g("seller_discount_amount")
        r_gross = g("refund_subtotal_before_discount_amount", "gross_sales_refund_amount")
        r_sdisc = g("seller_discount_refund_amount")

        rows.append({
            "Order/adjustment ID":   str(t.get("order_id") or t.get("adjustment_id") or t.get("id") or ""),
            "Type":                  t.get("type", "ORDER"),
            "Order created time":    epoch_to_wib(t.get("order_create_time")),
            "Order settled time":    epoch_to_wib(t.get("_statement_settled_time")),
            "Currency":              t.get("currency", "IDR"),
            "Total settlement amount":  g("settlement_amount"),
            "Total Revenue":            g("revenue_amount"),
            "Subtotal after seller discounts":  g("subtotal_after_seller_discount_amount", "net_sales_amount") or (gross - abs(sdisc)),
            "Subtotal before discounts":        gross,
            "Seller discounts":                 sdisc,
            "Distance item fee from Horizon+ Program": g("distant_item_fee_amount"),
            "Refund subtotal after seller discounts":  g("refund_subtotal_after_seller_discount_amount") or (r_gross - abs(r_sdisc)),
            "Refund subtotal before seller discounts": r_gross,
            "Refund of seller discounts":       r_sdisc,
            "Total Fees":                         g("fee_and_tax_amount", "fee_tax_amount", "fee_amount"),
            "Platform commission fee":          g("platform_commission_amount"),
            "Pre-order service fee":            g("pre_order_service_fee_amount"),
            "Mall service fee":                 g("mall_service_fee_amount"),
            "Payment Fee":                      g("transaction_fee_amount", "payment_fee_amount"),
            "Shipping cost":                    g("shipping_cost_amount"),
            "Shipping costs passed on to logistics": g("actual_shipping_fee_amount"),
            "Replacement shipping fee":         g("replacement_shipping_fee_amount"),
            "Exchange shipping fee":            g("exchange_shipping_fee_amount"),
            "Shipping cost borne by platform":  g("platform_shipping_fee_discount_amount", "shipping_fee_discount_amount"),
            "Shipping cost paid by customer":   g("customer_paid_shipping_fee_amount"),
            "Refunded shipping cost by customer": g("refunded_customer_shipping_fee_amount"),
            "Return shipping costs":            g("return_shipping_fee_amount"),
            "Shipping cost subsidy":            g("shipping_fee_subsidy_amount"),
            "Distance shipping fee Horizon+":     g("distant_shipping_fee_amount"),
            "Affiliate Commission":             g("affiliate_commission_amount"),
            "Affiliate partner commission":     g("affiliate_partner_commission_amount"),
            "Affiliate Shop Ads commission":    g("affiliate_ads_commission_amount", "affiliate_shop_ads_commission_amount"),
            "Affiliate Partner shop ads commission": g("tap_shop_ads_commission"),
            "Shipping Fee Program service fee": g("sfp_service_fee_amount"),
            "Dynamic commission":               g("dynamic_commission_amount"),
            "Bonus cashback service fee":       g("bonus_cashback_service_fee_amount"),
            "LIVE Specials service fee":        g("live_specials_fee_amount", "live_specials_service_fee_amount"),
            "Voucher Xtra service fee":         g("voucher_xtra_service_fee_amount"),
            "Order processing fee":               g("vn_fix_infrastructure_fee", "order_processing_fee_amount"),
            "EAMS Program service fee":         g("eams_program_service_fee_amount"),
            "Flash Sale service fee":           g("flash_sales_service_fee_amount", "flash_sale_service_fee_amount"),
            "Dilayani Tokopedia fee":           0,
            "Dilayani Tokopedia handling fee":    g("dt_handling_fee_amount"),
            "PayLater program fee":               g("seller_paylater_handling_fee_amount"),
            "Campaign resource fee":            g("campaign_resource_fee_amount"),
            "Installation service fee":           g("installation_service_fee"),
            "Article 22 Income Tax withheld":     g("article_22_income_tax_withheld"),
            "Platform special service fee":     g("platform_special_service_fee_amount"),
            "GMV Max ad fee":                   g("gmv_max_ad_fee_amount"),
            "Adjustment amount":                g("adjustment_amount"),
            "Related order ID":                 str(t.get("adjustment_order_id") or ""),
            "Customer payment":                 g("customer_payment_amount"),
            "Customer refund":                  g("customer_refund_amount"),
            "Seller co-funded voucher discount":   g("seller_cofunded_voucher_discount_amount"),
            "Refund of seller co-funded voucher":  g("seller_cofunded_voucher_discount_refund_amount"),
            "Platform discounts":               g("platform_discount_amount"),
            "Refund of platform discounts":     g("platform_discount_refund_amount"),
            "Platform co-funded voucher discounts":  g("platform_cofunded_voucher_discount_amount"),
            "Refund of platform co-funded voucher":  g("platform_cofunded_voucher_discount_refund_amount"),
            "Seller shipping cost discount":    g("seller_shipping_fee_discount_amount"),
            "Estimated package weight (g)":     g("estimated_package_weight", "estimated_weight"),
            "Actual package weight (g)":        g("actual_package_weight", "actual_weight"),
            "Shopping center items":            "",
            "Order Source":                     "",
        })
    return pd.DataFrame(rows)


def format_product_excel(products_data):
    rows = []
    for p in products_data:
        skus = p.get("skus", [])
        prices = [float(s.get("price", {}).get("tax_exclusive_price", 0) or 0) for s in skus]
        stock  = sum(inv.get("quantity", 0) for s in skus for inv in s.get("inventory", []))
        currency = skus[0].get("price", {}).get("currency", "IDR") if skus else "IDR"

        rows.append({
            "ID produk":         p.get("id", ""),
            "Nama produk":       p.get("title", ""),
            "Status":            p.get("status", ""),
            "Jumlah SKU":        len(skus),
            "Total Stok":        stock,
            "Harga Terendah":    min(prices) if prices else 0,
            "Harga Tertinggi":   max(prices) if prices else 0,
            "Mata uang":         currency,
            "Wilayah Jual":      ", ".join(p.get("sales_regions", [])),
            "Dibuat":            epoch_to_wib(p.get("create_time")),
            "Diperbarui":        epoch_to_wib(p.get("update_time")),
        })
    return pd.DataFrame(rows)


def _amt(d, key, default=0):
    """Ambil angka dari {"amount": "22000", "currency": "IDR"}; kalau {} / kosong -> default."""
    v = d.get(key)
    if isinstance(v, dict):
        v = v.get("amount")
    try:
        return float(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        return default


def format_creator_orders_excel(affiliate_orders):
    rows = []
    for o in affiliate_orders:
        for s in (o.get("skus") or [{}]):
            qty   = s.get("quantity", 0) or 0
            price = _amt(s, "price")
            rows.append({
                "ID Pesanan":        o.get("id", ""),
                "ID Produk":         s.get("product_id", ""),
                "Produk":            "",   # tidak ada di response (lihat catatan)
                "SKU":               s.get("sku_name", ""),
                "ID Sku":            s.get("sku_id", ""),
                "Penjual Sku":       s.get("seller_sku", ""),
                "Harga":             price,
                "Payment Amount":    price * qty,
                "Mata Uang":         (s.get("price") or {}).get("currency", "IDR"),
                "Kuantitas":         qty,
                "Metode Pembayaran": "",   # tidak ada
                "Status Pesanan":    s.get("settlement_status", ""),
                "Nama pengguna kreator": s.get("creator_username", ""),
                "Jenis Konten":      s.get("content_type", ""),
                "ID Konten":         s.get("content_id", ""),
                "commission model":  s.get("commission_model", ""),
                "Persentase komisi standar": float(s.get("commission_rate") or 0) / 100,  # "500" = 5%
                "Est. Acuan Komisi":                   _amt(s, "estimated_commission_base"),
                "Perkiraan pembayaran komisi standar": _amt(s, "estimated_paid_commission"),
                "Acuan Komisi Aktual":                 _amt(s, "actual_commission_base"),
                "Pembayaran Komisi Aktual":            _amt(s, "actual_paid_commission"),
                "Persentase komisi Iklan Toko":        0,   # tidak ada
                "Perkiraan pembayaran komisi Iklan Toko": _amt(s, "estimated_paid_shop_ads_commission"),
                "Pembayaran komisi Iklan Toko aktual":    _amt(s, "actual_paid_shop_ads_commission"),
                "Perkiraan bonus kreator":   _amt(s, "estimated_cofunded_creator_bonus_amount"),
                "Bonus aktual kreator":      _amt(s, "actual_cofunded_creator_bonus_amount"),
                "Pengembalian barang":       s.get("fully_return", ""),
                "Pengembalian dana":         0,   # tidak ada
                "Waktu Dibuat":              epoch_to_wib(o.get("create_time")),
                "Waktu Pembayaran":          "",
                "Waktu Pesanan Siap Dikirim": "",
                "Order Delivery Time":       epoch_to_wib(o.get("delivery_time")),
                "Waktu Pesanan Selesai":     "",
                "Waktu Komisi Dibayar":      "",
                "Platform":                  "TikTok",
                "agreement_type":            "Open" if s.get("open_collaboration_id") else ("Target" if s.get("target_collaboration_id") else ""),
            })
    return pd.DataFrame(rows)

def to_excel_download(df: pd.DataFrame) -> BytesIO:
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Data")
    output.seek(0)
    return output


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
def save_token_to_db(token_data: dict, shop_info: dict, seller_name: str = "Unknown", app_name: str = "default"):
    """
    Simpan token ke Supabase.

    FIX: shop_info sekarang bisa datang dari skema baru ('id'/'cipher')
    ataupun lama ('shop_id'/'shop_cipher') -- dicoba dua-duanya.

    Kolom Supabase yang diperlukan:
      shop_id TEXT PRIMARY KEY, shop_cipher TEXT, shop_name TEXT,
      access_token TEXT, refresh_token TEXT,
      access_token_expire_in INT, refresh_token_expire_in INT,
      updated_at TIMESTAMPTZ
    """
    try:
        shop_id     = str(shop_info.get("id") or shop_info.get("shop_id") or "unknown")
        shop_cipher = str(shop_info.get("cipher") or shop_info.get("shop_cipher") or shop_id)
        shop_name   = (shop_info.get("name") or shop_info.get("shop_name")
                       or shop_info.get("shop_nickname") or seller_name)

        data = {
            "shop_id":                 shop_id,
            "shop_cipher":             shop_cipher,
            "shop_name":               shop_name,
            "access_token":            token_data.get("access_token", ""),
            "refresh_token":           token_data.get("refresh_token", ""),
            "access_token_expire_in":  token_data.get("access_token_expire_in", 86400),
            "refresh_token_expire_in": token_data.get("refresh_token_expire_in", 2592000),
            "app_name": app_name,
            "updated_at":              datetime.now(timezone.utc).isoformat(),
        }

        st.write(f"🔍 Debug simpan toko **{shop_name}**:", data)

        result = supabase.table("tiktok_shops").upsert(data, on_conflict="shop_id").execute()
        return result
    except Exception as e:
        st.error(f"Database error: {str(e)}")
        return None


def get_shop_tokens():
    try:
        result = supabase.table("tiktok_shops").select("*").execute()
        return result.data or []
    except Exception as e:
        st.error(f"Error mengambil daftar toko: {str(e)}")
        return []


def try_refresh_if_expired(shop: dict) -> dict:
    """Refresh token jika hampir expired, kembalikan shop dengan token baru."""
    use_app(shop.get("app_name"))
    try:
        exp = float(shop.get("access_token_expire_in") or 0)
        if exp < 1e9:                      # data lama berbentuk durasi (detik)
            updated_at = datetime.fromisoformat(shop["updated_at"].replace("Z", "+00:00"))
            exp = updated_at.timestamp() + exp

        if time.time() >= exp - 600:       # refresh 10 menit sebelum habis
            result = refresh_access_token(shop["refresh_token"])
            if result.get("code") == 0:
                new_data  = result.get("data", {})
                shop_info = {
                    "shop_id":     shop["shop_id"],
                    "shop_cipher": shop["shop_cipher"],
                    "shop_name":   shop["shop_name"],
                }
                save_token_to_db(new_data, shop_info, shop["shop_name"],
                                 shop.get("app_name") or "default")
                shop["access_token"] = new_data.get("access_token", shop["access_token"])
                st.success("🔄 Token berhasil diperbarui otomatis.")
            else:
                st.warning(f"Refresh token gagal ({result.get('message')}). Hubungkan ulang toko ini.")
    except Exception:
        pass
    return shop


# ─────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────
st.set_page_config(page_title="Tiktokbro — TikTok Shop", layout="wide")
st.title("🚀 Tiktokbro Data Extractor")
st.markdown("### Integrasi TikTok Shop Seller API · Timezone WIB (UTC+7)")

# ── Handle OAuth redirect ──────────────────
query_params = st.query_params
auth_code = query_params.get("code")

if auth_code and str(query_params.get("state")) != "ads":
    auth_code = str(auth_code)

    app_name = str(query_params.get("state") or "default")
    if app_name not in APPS:
        app_name = "default"
    use_app(app_name)

    # STEP 1: Tukar auth_code → access_token
    with st.spinner("Menukar kode otorisasi dengan access token..."):
        token_response = exchange_auth_code(auth_code)

    if token_response.get("code") != 0:
        st.error(f"❌ Gagal tukar auth code: {token_response.get('message', 'Unknown error')}")
        st.json(token_response)
    else:
        token_data  = token_response.get("data", {})
        seller_name = token_data.get("seller_name", "Toko Baru")
        access_token_new = token_data.get("access_token", "")

        # STEP 2: Ambil daftar toko (shop_id + shop_cipher) yang diotorisasi
        # Karena response token TIDAK berisi shop_cipher — harus fetch terpisah
        with st.spinner("Mengambil daftar toko yang diotorisasi..."):
            authorized_shops = get_authorized_shops(access_token_new)

        if not authorized_shops:
            st.warning("⚠️ Tidak bisa ambil data toko. Menyimpan dengan ID sementara...")
            # Fallback: simpan dengan open_id sebagai shop_id, cipher kosong
            fallback_shop_info = {
                "shop_id":     token_data.get("open_id", "unknown"),
                "shop_cipher": token_data.get("open_id", "unknown"),
                "shop_name":   seller_name,
            }
            result = save_token_to_db(token_data, fallback_shop_info, seller_name, app_name)
        else:
            # Simpan semua toko yang diotorisasi (biasanya hanya 1)
            results = []
            for shop_info in authorized_shops:
                r = save_token_to_db(token_data, shop_info, seller_name, app_name)
                results.append(r)
            result = any(r is not None for r in results)

        if result:
            total = len(authorized_shops) if authorized_shops else 1
            st.success(f"✅ **{seller_name}** berhasil dihubungkan! ({total} toko tersimpan)")
            st.balloons()
            st.query_params.clear()
        else:
            st.error("❌ Gagal menyimpan ke database. Cek debug di atas.")

ADS_APP = st.secrets.get("ads_app") or {}

def get_ads_auth_url(state="ads"):
    return "https://business-api.tiktok.com/portal/auth?" + urllib.parse.urlencode(
        {"app_id": ADS_APP.get("app_id", ""), "state": state, "redirect_uri": REDIRECT_URI})

def exchange_ads_auth_code(auth_code):
    r = requests.post("https://business-api.tiktok.com/open_api/v1.3/oauth2/access_token/",
                      json={"app_id": ADS_APP["app_id"], "secret": ADS_APP["secret"],
                            "auth_code": auth_code}, timeout=30)
    return r.json()

# Tangkap redirect dari otorisasi Ads (parameter auth_code; Shop memakai "code")
ads_auth_code = st.query_params.get("auth_code")
if ads_auth_code:
    code_str = str(ads_auth_code)
    if st.session_state.get("ads_code_done") != code_str:
        st.session_state["ads_code_done"] = code_str
        res = exchange_ads_auth_code(code_str)
        if res.get("code") == 0:
            d = res.get("data", {})
            st.success("✅ Token Ads didapat. Salin ke secrets.")
            st.code(f'access_token = "{d.get("access_token")}"\n# advertiser_ids: {d.get("advertiser_ids")}')
        else:
            st.error(res)
        st.query_params.clear()
      
# ── Sidebar ────────────────────────────────
with st.sidebar:
    st.header("⚙️ Konfigurasi Toko")

    shops = get_shop_tokens()

    if not shops:
        st.warning("Belum ada toko terhubung.")
        selected_shop = None
    else:
        shop_options  = {s["shop_name"]: s for s in shops}
        selected_name = st.selectbox("Pilih Toko", list(shop_options.keys()))
        selected_shop = shop_options[selected_name]
        selected_shop = try_refresh_if_expired(selected_shop)
        st.info(f"Shop ID: ...{selected_shop['shop_id'][-6:]}")

    st.markdown("---")
    st.subheader("📅 Filter Waktu (WIB)")
    time_preset = st.radio("Rentang", ["Kemarin", "7 Hari", "30 Hari", "Custom"], horizontal=True)

    now_wib = datetime.now(WIB)
    today0  = now_wib.replace(hour=0, minute=0, second=0, microsecond=0)

    if time_preset == "Kemarin":
        start_date = today0 - timedelta(days=1)                 # kemarin 00:00:00
        end_date   = today0 - timedelta(seconds=1)              # kemarin 23:59:59
    elif time_preset == "7 Hari":
        this_monday = today0 - timedelta(days=today0.weekday())
        start_date  = this_monday - timedelta(days=7)           # Senin minggu lalu 00:00:00
        end_date    = this_monday - timedelta(seconds=1)        # Minggu 23:59:59
    elif time_preset == "30 Hari":
        start_date = today0 - timedelta(days=30)                # 30 hari penuh
        end_date   = today0 - timedelta(seconds=1)              # sampai kemarin 23:59:59
    else:
        col1, col2 = st.columns(2)
        with col1:
            sd = st.date_input("Dari", (today0 - timedelta(days=7)).date())
        with col2:
            ed = st.date_input("Sampai", (today0 - timedelta(days=1)).date())
        start_date = datetime.combine(sd, dtime(0, 0, 0),   tzinfo=WIB)
        end_date   = datetime.combine(ed, dtime(23, 59, 59), tzinfo=WIB)

    # Ke UTC untuk API. End dibuat eksklusif (+1 detik) karena API pakai *_lt
    start_utc = start_date.astimezone(timezone.utc)
    end_utc   = (end_date + timedelta(seconds=1)).astimezone(timezone.utc)
    st.info(f"🕒 WIB: {start_date:%Y-%m-%d %H:%M} — {end_date:%Y-%m-%d %H:%M}\n\n"
            f"🌍 UTC: {start_utc:%Y-%m-%d %H:%M} — {end_utc:%Y-%m-%d %H:%M}")
    st.markdown("---")

    # if st.button("🔗 Hubungkan Toko Baru", use_container_width=True):
    #     auth_url = get_auth_url()
    #     st.markdown(f"[**Klik untuk Otorisasi TikTok Shop**]({auth_url})")
    app_choice = st.selectbox("App untuk toko baru", list(APPS.keys()))
    if st.button("🔗 Hubungkan Toko Baru", use_container_width=True):
        auth_url = get_auth_url(app_choice)
        st.markdown(f"[**Klik untuk Otorisasi TikTok Shop**]({auth_url})")
        st.markdown(f"[🔗 Otorisasi Akun Iklan]({get_ads_auth_url()})")

# ── Main Tabs ──────────────────────────────
if selected_shop:
    access_token = selected_shop["access_token"]
    shop_cipher  = selected_shop.get("shop_cipher") or selected_shop["shop_id"]
    date_suffix  = f"{start_date:%Y%m%d}_{end_date:%Y%m%d}"

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💰 Income/Settlement",
        "📦 Semua Pesanan",
        "👥 Creator Orders",
        "🛍️ Product Data (Iklan)",
        "🧾 Resi (A6)",
    ])

    # ── TAB 1: INCOME ──────────────────────
    with tab1:
        st.subheader("Laporan Income & Settlement")
        st.caption(f"WIB: {start_date:%d %b %Y %H:%M} — {end_date:%d %b %Y %H:%M}")
        if st.button("🔄 Tarik & Download", key="btn_income", type="primary"):
            with st.spinner("Mengambil data keuangan..."):
                statements = get_statements(access_token, shop_cipher, start_utc, end_utc)
                transactions = []
                for s in statements:
                    statement_id   = s.get("id") or s.get("statement_id")
                    statement_time = s.get("statement_time") or s.get("create_time")
                    for tx in get_statement_transactions(access_token, shop_cipher, statement_id):
                        tx["_statement_settled_time"] = statement_time
                        transactions.append(tx)
            if transactions:
                df = format_income_excel(transactions)
                zero_cols = [c for c in df.columns if (df[c].fillna(0).astype(str).isin(["0", "0.0", ""])).all()]
                if zero_cols:
                    st.caption("Kolom masih 0/kosong semua: " + ", ".join(zero_cols))
                st.success(f"✅ {len(transactions)} transaksi ditemukan dari {len(statements)} statement")
                st.dataframe(df.head(10), use_container_width=True)
                st.download_button(
                    "📥 Download Excel Income",
                    to_excel_download(df),
                    f"Income_{shop_cipher}_{date_suffix}.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            else:
                st.info("Tidak ada data income untuk periode ini.")

    # ── TAB 2: ORDERS ──────────────────────
    with tab2:
        st.subheader("Daftar Pesanan Lengkap")
        st.caption(f"WIB: {start_date:%d %b %Y %H:%M} — {end_date:%d %b %Y %H:%M}")
        if st.button("🔄 Tarik & Download", key="btn_orders", type="primary"):
            with st.spinner("Mengambil data pesanan..."):
                orders = get_all_orders(access_token, shop_cipher, start_utc, end_utc)
            if orders:
                st.info(f"📋 {len(orders)} pesanan ditemukan, mengambil detail...")
                order_ids = [o.get("id") for o in orders]
                progress  = st.progress(0)
                details   = get_order_details_batch(access_token, shop_cipher, order_ids, progress_bar=progress)
                with st.spinner("Mengambil data retur & info produk..."):
                    returns = get_returns_by_orders(access_token, shop_cipher, start_utc, order_ids)
                    pcache = {}
                    for pid in {li.get("product_id") for d in details for li in d.get("line_items", [])}:
                        get_product_info(access_token, shop_cipher, pid, pcache)
                df = format_orders_excel(orders, details, returns, pcache)
                st.success(f"✅ {len(df)} baris data diproses")
                st.dataframe(df.head(10), use_container_width=True)
                st.download_button(
                    "📥 Download Excel Pesanan",
                    to_excel_download(df),
                    f"Semua_Pesanan_{shop_cipher}_{date_suffix}.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            else:
                st.info("Tidak ada pesanan untuk periode ini.")

    # ── TAB 3: CREATOR ORDERS ──────────────
    with tab3:
        st.subheader("Afiliasi & Creator Orders")
        st.caption(f"WIB: {start_date:%d %b %Y %H:%M} — {end_date:%d %b %Y %H:%M}")
        if st.button("🔄 Tarik & Download", key="btn_creator", type="primary"):
            with st.spinner("Mengambil data affiliate..."):
                aff_orders = get_affiliate_orders(access_token, shop_cipher, start_utc, end_utc)
            if aff_orders:
                df = format_creator_orders_excel(aff_orders)
                cache = {}
                df["Produk"] = df["ID Produk"].map(lambda pid: get_product_title(access_token, shop_cipher, pid, cache))
                st.success(f"✅ {len(aff_orders)} order affiliate")
                st.dataframe(df.head(10), use_container_width=True)
                st.download_button(
                    "📥 Download Excel Creator Orders",
                    to_excel_download(df),
                    f"Creator_Orders_{shop_cipher}_{date_suffix}.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            else:
                st.warning("Tidak ada data affiliate atau scope belum diaktifkan.")

    # ── TAB 4: PRODUCTS ────────────────────
    with tab4:
        st.subheader("Data Produk (Iklan GMV Max)")
        st.caption(f"WIB: {start_date:%d %b %Y %H:%M} — {end_date:%d %b %Y %H:%M}")
        ads_cfg = (st.secrets.get("ads_accounts") or {}).get(selected_shop["shop_id"])

        if not ads_cfg:
            st.warning("Kredensial Ads belum diisi untuk toko ini. Tambahkan di secrets, nama blok:")
            st.code(f'[ads_accounts."{selected_shop["shop_id"]}"]')

        if ads_cfg:
            with st.expander("🔎 Cek daftar store (untuk mencari store_id)"):
                if st.button("Cek store", key="btn_stores"):
                    st.json(get_gmv_max_stores(ads_cfg))
                  
        only_cost = st.checkbox("Hanya produk yang ada biayanya", value=False)
        if st.button("🔄 Tarik & Download", key="btn_products", type="primary"):
            if ads_cfg:
                with st.spinner("Mengambil laporan GMV Max..."):
                    rows = get_gmv_max_product_report(ads_cfg, start_date, end_date)
                    df = format_gmv_max_excel(rows, access_token, shop_cipher, only_cost) if rows else pd.DataFrame()
            else:
                st.info("Memakai data finance (kolom Biaya biasanya 0).")
                progress = st.progress(0)
                per_product = get_product_ads_performance(access_token, shop_cipher, start_utc, end_utc, progress_bar=progress)
                df = format_product_ads_excel(per_product) if per_product else pd.DataFrame()

            if not df.empty:
                st.success(f"✅ {len(df)} produk · Total biaya: {df['Biaya'].sum():,.0f} {df['Mata Uang'].iloc[0]}")
                st.dataframe(df, use_container_width=True)
                st.download_button("📥 Download Excel Produk", to_excel_download(df),
                                   f"Product_Data_{shop_cipher}_{date_suffix}.xlsx",
                                   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

            else:
                st.info("Tidak ada produk dengan biaya iklan di periode ini.")

    # ── TAB 5: RESI ────────────────────────
    with tab5:
        st.subheader("Cetak Resi Penjualan (PDF A6)")
        st.caption(f"WIB: {start_date:%d %b %Y %H:%M} — {end_date:%d %b %Y %H:%M}")
        statuses = st.multiselect(
            "Status pesanan yang dicetak",
            ["AWAITING_SHIPMENT", "AWAITING_COLLECTION", "PARTIALLY_SHIPPING",
             "IN_TRANSIT", "DELIVERED", "COMPLETED"],
            default=["AWAITING_SHIPMENT", "AWAITING_COLLECTION"],
        )
        if st.button("🖨️ Buat PDF Resi", key="btn_label", type="primary"):
            with st.spinner("Mengambil pesanan..."):
                orders = [o for o in get_all_orders(access_token, shop_cipher, start_utc, end_utc)
                          if o.get("status") in statuses]
            if not orders:
                st.info("Tidak ada pesanan dengan status tersebut di periode ini.")
            else:
                st.info(f"📋 {len(orders)} pesanan, mengambil resi...")
                progress = st.progress(0)
                pdf, ok, failed = build_label_pdf(access_token, shop_cipher, orders,
                                                  size="A6", progress_bar=progress)
                if ok:
                    st.success(f"✅ {ok} resi digabung dalam 1 PDF")
                    st.download_button("📥 Download PDF Resi", pdf,
                                       f"Resi_A6_{date_suffix}.pdf", "application/pdf")
                picked = [f for f in failed if "21042102" in str(f[2])]
                other  = [f for f in failed if "21042102" not in str(f[2])]
                if picked:
                    st.info(f"ℹ️ {len(picked)} paket sudah diambil kurir, resi tidak bisa dicetak lagi (aturan TikTok).")
                if other:
                    st.warning(f"⚠️ {len(other)} resi gagal diambil")
                    st.dataframe(pd.DataFrame(other, columns=["Order ID", "Package ID", "Error"]),
                                 use_container_width=True)
else:
    st.info("👈 Silakan hubungkan toko terlebih dahulu melalui sidebar.")
    with st.expander("📋 Panduan Setup"):
        st.markdown("""
        ### Langkah-langkah:
        1. Klik **Hubungkan Toko Baru** di sidebar
        2. Login ke akun TikTok Shop Anda
        3. Authorize aplikasi Tiktokbro
        4. Anda akan di-redirect kembali — token tersimpan otomatis

        ### Scope API yang Diperlukan:
        - ✅ **Order Information** — data pesanan
        - ✅ **Finance Information** — data income/settlement
        - ✅ **Product Basic** — data produk
        - ✅ **Affiliate/Commission** — data creator (opsional)
        """)
