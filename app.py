import streamlit as st
import requests
import time
import hmac
import hashlib
import pandas as pd
from datetime import datetime, timedelta, timezone
from supabase import create_client, Client
import json
from io import BytesIO
import urllib.parse

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
APP_KEY    = st.secrets["TIKTOK_APP_KEY"]
APP_SECRET = st.secrets["TIKTOK_APP_SECRET"]
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
def get_auth_url() -> str:
    params = {
        "app_key":      APP_KEY,
        "state":        "TiktokbroAuth",
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
        st.write("🔍 Debug token response:", result)   # bisa dihapus setelah production
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
    params["sign"]         = generate_signature(endpoint, params, APP_SECRET, None)
    params["access_token"] = access_token

    url = f"{BASE_URL}{endpoint}"
    try:
        resp = requests.get(url, params=params, timeout=30)
        result = resp.json()
        st.write("🔍 Debug authorized shops response:", result)
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


def epoch_to_wib(epoch_ms) -> str:
    if not epoch_ms:
        return ""
    try:
        utc_time = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
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
            f"/finance/202309/statements/{statement_id}/statement_transactions",
            access_token, shop_cipher,
            method="GET",
            **query,
        )

        if result.get("code") == 0:
            data = result.get("data", {})
            tx = data.get("transactions") or data.get("statement_transactions") or data.get("list") or []
            if not all_tx and tx:
                # tampil sekali saja per sesi biar bisa cek nama field asli di response,
                # hapus baris ini setelah dikonfirmasi cocok
                st.write("🔍 Debug struktur 1 statement_transaction:", tx[0])
            all_tx.extend(tx)
            page_token = data.get("next_page_token")
            if not page_token or not tx:
                break
        else:
            st.warning(f"Error statement_transactions ({statement_id}): {result.get('message')}")
            break
    return all_tx


def get_products(access_token, shop_cipher):
    all_products, page_token = [], None
    for _ in range(100):
        body = {"status": 1}
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


def get_affiliate_orders(access_token, shop_cipher, start_time, end_time):
    """
    FIX: kategori & versi endpoint affiliate berubah. Minimal version 202405,
    dan kategorinya 'affiliate_seller' (bukan 'affiliate').
    """
    all_orders, page_token = [], None
    for _ in range(100):
        body = {
            "create_time_ge": int(start_time.timestamp()),
            "create_time_lt": int(end_time.timestamp()),
        }
        query = {"page_size": 50, "version": "202410"}
        if page_token:
            query["page_token"] = page_token

        result = make_tiktok_request(
            "/affiliate_seller/202405/orders/search",
            access_token, shop_cipher,
            method="POST",
            body=body,
            **query,
        )

        if result.get("code") == 0:
            data   = result.get("data", {})
            orders = data.get("orders") or data.get("order_list") or []
            all_orders.extend(orders)
            page_token = data.get("next_page_token")
            if not page_token or not orders:
                break
        else:
            st.warning(f"Affiliate API: {result.get('message')}")
            st.json(result)
            break
    return all_orders


# ─────────────────────────────────────────────
# FORMATTING → DATAFRAME
# ─────────────────────────────────────────────
def format_orders_excel(orders_data, order_details):
    rows         = []
    details_dict = {d.get("order_id"): d for d in order_details if d}

    for order in orders_data:
        order_id  = order.get("order_id")
        detail    = details_dict.get(order_id, {})

        created_time   = epoch_to_wib(order.get("create_time"))
        paid_time      = epoch_to_wib(order.get("paid_time"))
        rts_time       = epoch_to_wib(order.get("rts_time"))
        shipped_time   = epoch_to_wib(order.get("shipped_time"))
        delivered_time = epoch_to_wib(order.get("delivered_time"))
        cancelled_time = epoch_to_wib(order.get("cancelled_time"))

        buyer_info     = detail.get("buyer_info", {})
        recipient_info = detail.get("recipient_info", {})
        payment_info   = detail.get("payment_info", {})
        shipping_info  = detail.get("shipping_info", {})
        items          = detail.get("item_list", [])

        base = {
            "Order ID":              order_id,
            "Order Status":          order.get("order_status", ""),
            "Order Substatus":       order.get("order_sub_status", ""),
            "Shipping Fee After Discount":   order.get("shipping_fee", 0),
            "Original Shipping Fee":         order.get("original_shipping_fee", 0),
            "Order Refund Amount":           order.get("refund_amount", 0),
            "Order Amount":                  order.get("total_amount", 0),
            "Created Time":          created_time,
            "Paid Time":             paid_time,
            "RTS Time":              rts_time,
            "Shipped Time":          shipped_time,
            "Delivered Time":        delivered_time,
            "Cancelled Time":        cancelled_time,
            "Cancel By":             order.get("cancel_user", ""),
            "Cancel Reason":         order.get("cancel_reason", ""),
            "Fulfillment Type":      shipping_info.get("fulfillment_type", ""),
            "Warehouse Name":        shipping_info.get("warehouse_name", ""),
            "Tracking ID":           shipping_info.get("tracking_number", ""),
            "Delivery Option":       shipping_info.get("delivery_option", ""),
            "Shipping Provider Name": shipping_info.get("shipping_provider_name", ""),
            "Buyer Message":         buyer_info.get("buyer_message", ""),
            "Buyer Username":        buyer_info.get("buyer_nickname", ""),
            "Recipient":             recipient_info.get("name", ""),
            "Phone #":               recipient_info.get("phone", ""),
            "Zipcode":               recipient_info.get("zipcode", ""),
            "Country":               recipient_info.get("country", ""),
            "Province":              recipient_info.get("state", ""),
            "Regency and City":      recipient_info.get("city", ""),
            "Districts":             recipient_info.get("district", ""),
            "Villages":              recipient_info.get("village", ""),
            "Detail Address":        recipient_info.get("full_address", ""),
            "Additional address information": recipient_info.get("address_detail", ""),
            "Payment Method":        payment_info.get("payment_method", ""),
            "Purchase Channel":      order.get("purchase_channel", ""),
            "Seller Note":           order.get("seller_note", ""),
            "Tokopedia Invoice Number": order.get("tokopedia_invoice", ""),
        }

        if not items:
            rows.append({
                **base,
                "Cancelation/Return Type":  "",
                "Normal or Pre-order":      "Normal",
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
            for item in items:
                rows.append({
                    **base,
                    "Cancelation/Return Type": item.get("return_type", ""),
                    "Normal or Pre-order": "Pre-order" if item.get("is_pre_order") else "Normal",
                    "SKU ID":       item.get("sku_id", ""),
                    "Seller SKU":   item.get("seller_sku", ""),
                    "Product Name": item.get("product_name", ""),
                    "Variation":    item.get("variation_name", ""),
                    "Quantity":     item.get("quantity", 0),
                    "Sku Quantity of return": item.get("return_quantity", 0),
                    "SKU Unit Original Price":        item.get("original_price", 0),
                    "SKU Subtotal Before Discount":   item.get("subtotal_before_discount", 0),
                    "SKU Platform Discount":          item.get("platform_discount", 0),
                    "SKU Seller Discount":            item.get("seller_discount", 0),
                    "SKU Subtotal After Discount":    item.get("subtotal_after_discount", 0),
                    "Shipping Fee Seller Discount":   item.get("shipping_fee_seller_discount", 0),
                    "Shipping Fee Platform Discount": item.get("shipping_fee_platform_discount", 0),
                    "Distance Shipping Fee":          item.get("distance_shipping_fee", 0),
                    "Distance Fee":                   item.get("distance_fee", 0),
                    "Payment platform discount":      item.get("payment_platform_discount", 0),
                    "Buyer Service Fee":              item.get("buyer_service_fee", 0),
                    "Handling Fee":                   item.get("handling_fee", 0),
                    "Shipping Insurance":             item.get("shipping_insurance", 0),
                    "Item Insurance":                 item.get("item_insurance", 0),
                    "Weight(kg)":        item.get("weight", 0) / 1000 if item.get("weight") else 0,
                    "Product Category":  item.get("category_name", ""),
                    "Package ID":        item.get("package_id", ""),
                    "Checked Status":    item.get("checked_status", ""),
                    "Checked Marked by": item.get("checked_by", ""),
                })
    return pd.DataFrame(rows)


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


def format_income_excel(transactions):
    """
    Sumber data: GET /finance/202309/statements/{id}/statement_transactions
    (dulu POST /api/v2/finance/settlements/search, sudah tidak ada).

    Semua nama kolom di bawah PERSIS seperti versi lama. Field yang saya
    tandai "~" adalah padanan terbaik yang bisa saya konfirmasi (bukan 100%
    nama identik dari TikTok). Field yang ditandai "—" tidak punya padanan
    di data TikTok Shop (sepertinya ini kolom dari template Tokopedia) jadi
    akan selalu 0/kosong.
    """
    rows = []
    for t in transactions:
        skus = t.get("sku_transactions", [])

        rows.append({
            "Order/adjustment ID":                     t.get("order_id", ""),
            "Type":                                     "Order",
            "Order created time":                       epoch_to_wib(t.get("order_create_time")),
            "Order settled time":                        epoch_to_wib(t.get("_statement_settled_time")),
            "Currency":                                  t.get("currency", "IDR"),
            "Total settlement amount":                   t.get("settlement_amount", 0),
            "Total Revenue":                             t.get("revenue_amount", 0),
            "Subtotal after seller discounts":           _sum_path(skus, "revenue_breakdown", "subtotal_before_discount_amount")
                                                          + _sum_path(skus, "revenue_breakdown", "seller_discount_amount"),
            "Subtotal before discounts":                 _sum_path(skus, "revenue_breakdown", "subtotal_before_discount_amount"),
            "Seller discounts":                          _sum_path(skus, "revenue_breakdown", "seller_discount_amount"),
            "Distance item fee from Horizon+ Program":   _sum_path(skus, "revenue_breakdown", "distant_item_fee_amount"),
            "Refund subtotal after seller discounts":    _sum_path(skus, "revenue_breakdown", "refund_subtotal_before_discount_amount")
                                                          + _sum_path(skus, "revenue_breakdown", "seller_discount_refund_amount"),
            "Refund subtotal before seller discounts":   _sum_path(skus, "revenue_breakdown", "refund_subtotal_before_discount_amount"),
            "Refund of seller discounts":                _sum_path(skus, "revenue_breakdown", "seller_discount_refund_amount"),
            "Total Fees":                                t.get("fee_and_tax_amount", 0),
            "Platform commission fee":                   _sum_path(skus, "fee_tax_breakdown", "fee", "platform_commission_amount"),
            "Pre-order service fee":                     _sum_path(skus, "fee_tax_breakdown", "fee", "pre_order_service_fee_amount"),
            "Mall service fee":                          _sum_path(skus, "fee_tax_breakdown", "fee", "mall_service_fee_amount"),
            "Payment Fee":                                _sum_path(skus, "fee_tax_breakdown", "fee", "credit_card_handling_fee_amount"),  # ~
            "Shipping cost":                             t.get("shipping_cost_amount", 0),
            "Shipping costs passed on to logistics":     _sum_path(skus, "shipping_cost_breakdown", "actual_shipping_fee_amount"),  # ~
            "Replacement shipping fee":                  _sum_path(skus, "shipping_cost_breakdown", "replacement_shipping_fee_amount"),
            "Exchange shipping fee":                     _sum_path(skus, "shipping_cost_breakdown", "exchange_shipping_fee_amount"),
            "Shipping cost borne by platform":           _sum_path(skus, "shipping_cost_breakdown", "supplementary_component", "platform_shipping_fee_discount_amount"),
            "Shipping cost paid by customer":            _sum_path(skus, "shipping_cost_breakdown", "customer_paid_shipping_fee_amount"),
            "Refunded shipping cost by customer":        _sum_path(skus, "shipping_cost_breakdown", "supplementary_component", "refunded_customer_shipping_fee_amount"),
            "Return shipping costs":                     _sum_path(skus, "shipping_cost_breakdown", "return_shipping_fee_amount"),
            "Shipping cost subsidy":                     _sum_path(skus, "shipping_cost_breakdown", "supplementary_component", "shipping_fee_subsidy_amount"),
            "Distance shipping fee Horizon+":             _sum_path(skus, "shipping_cost_breakdown", "distant_shipping_fee_amount"),
            "Affiliate Commission":                      _sum_path(skus, "fee_tax_breakdown", "fee", "affiliate_commission_amount"),
            "Affiliate partner commission":              _sum_path(skus, "fee_tax_breakdown", "fee", "affiliate_partner_commission_amount"),
            "Affiliate Shop Ads commission":             _sum_path(skus, "fee_tax_breakdown", "fee", "affiliate_ads_commission_amount"),
            "Affiliate Partner shop ads commission":     0,  # —
            "Shipping Fee Program service fee":          _sum_path(skus, "fee_tax_breakdown", "fee", "shipping_fee_guarantee_service_fee"),
            "Dynamic commission":                        _sum_path(skus, "fee_tax_breakdown", "fee", "dynamic_commission_amount"),
            "Bonus cashback service fee":                _sum_path(skus, "fee_tax_breakdown", "fee", "bonus_cashback_service_fee_amount"),
            "LIVE Specials service fee":                 _sum_path(skus, "fee_tax_breakdown", "fee", "live_specials_fee_amount"),
            "Voucher Xtra service fee":                  _sum_path(skus, "fee_tax_breakdown", "fee", "voucher_xtra_service_fee_amount"),
            "Order processing fee":                      _sum_path(skus, "fee_tax_breakdown", "fee", "fee_per_item_sold_amount"),  # ~
            "EAMS Program service fee":                  _sum_path(skus, "fee_tax_breakdown", "fee", "epr_pob_service_fee_amount"),  # ~
            "Flash Sale service fee":                    _sum_path(skus, "fee_tax_breakdown", "fee", "flash_sales_service_fee_amount"),
            "Dilayani Tokopedia fee":                    0,  # — (kolom Tokopedia, tidak ada di TikTok Shop)
            "Dilayani Tokopedia handling fee":           0,  # —
            "PayLater program fee":                      _sum_path(skus, "fee_tax_breakdown", "fee", "seller_paylater_handling_fee_amount"),
            "Campaign resource fee":                     0,  # —
            "Installation service fee":                  _sum_path(skus, "fee_tax_breakdown", "fee", "installation_service_fee"),
            "Article 22 Income Tax withheld":            _sum_path(skus, "fee_tax_breakdown", "tax", "pit_amount"),  # ~
            "Platform special service fee":              _sum_path(skus, "fee_tax_breakdown", "fee", "platform_special_service_fee_amount"),
            "GMV Max ad fee":                            _sum_path(skus, "fee_tax_breakdown", "fee", "gmv_max_ad_fee_amount"),
            "Adjustment amount":                         0,  # —
            "Related order ID":                          "",  # —
            "Customer payment":                          0,  # —
            "Customer refund":                           0,  # —
            "Seller co-funded voucher discount":         _sum_path(skus, "fee_tax_breakdown", "fee", "cofunded_promotion_service_fee_amount"),  # ~
            "Refund of seller co-funded voucher":        0,  # —
            "Platform discounts":                        0,  # —
            "Refund of platform discounts":              0,  # —
            "Platform co-funded voucher discounts":      _sum_path(skus, "fee_tax_breakdown", "fee", "cofunded_creator_bonus_amount"),  # ~
            "Refund of platform co-funded voucher":      0,  # —
            "Seller shipping cost discount":             _sum_path(skus, "shipping_cost_breakdown", "supplementary_component", "seller_shipping_fee_discount_amount"),
            "Estimated package weight (g)":              0,  # —
            "Actual package weight (g)":                 0,  # —
            "Shopping center items":                     "",  # —
            "Order Source":                              "",  # —
        })
    return pd.DataFrame(rows)


def format_product_excel(products_data):
    rows = []
    for p in products_data:
        sales = p.get("sales_data", {})
        ads   = p.get("ad_data", {})
        gross = sales.get("gross_revenue", 0)
        cost  = ads.get("cost", 0)
        orders = sales.get("orders", 0)
        rows.append({
            "ID produk":       p.get("product_id", ""),
            "Nama produk":     p.get("product_name", ""),
            "Pesanan SKU":     p.get("sku_count", 0),
            "Pendapatan kotor": gross,
            "Biaya":           cost,
            "Biaya per pesanan": cost / orders if orders else 0,
            "ROI":             round((gross - cost) / cost, 2) if cost else 0,
            "Mata uang":       p.get("currency", "IDR"),
        })
    return pd.DataFrame(rows)


def format_creator_orders_excel(affiliate_orders):
    rows = []
    for o in affiliate_orders:
        rows.append({
            "ID Pesanan":        o.get("order_id", ""),
            "ID Produk":         o.get("product_id", ""),
            "Produk":            o.get("product_name", ""),
            "SKU":               o.get("sku_name", ""),
            "ID Sku":            o.get("sku_id", ""),
            "Penjual Sku":       o.get("seller_sku", ""),
            "Harga":             o.get("price", 0),
            "Payment Amount":    o.get("payment_amount", 0),
            "Mata Uang":         o.get("currency", "IDR"),
            "Kuantitas":         o.get("quantity", 0),
            "Metode Pembayaran": o.get("payment_method", ""),
            "Status Pesanan":    o.get("order_status", ""),
            "Nama pengguna kreator": o.get("creator_nickname", ""),
            "Jenis Konten":      o.get("content_type", ""),
            "ID Konten":         o.get("content_id", ""),
            "commission model":  o.get("commission_model", ""),
            "Persentase komisi standar":             o.get("standard_commission_rate", 0),
            "Est. Acuan Komisi":                     o.get("est_commission_base", 0),
            "Perkiraan pembayaran komisi standar":   o.get("est_standard_commission", 0),
            "Acuan Komisi Aktual":                   o.get("actual_commission_base", 0),
            "Pembayaran Komisi Aktual":              o.get("actual_standard_commission", 0),
            "Persentase komisi Iklan Toko":          o.get("shop_ads_commission_rate", 0),
            "Perkiraan pembayaran komisi Iklan Toko": o.get("est_shop_ads_commission", 0),
            "Pembayaran komisi Iklan Toko aktual":   o.get("actual_shop_ads_commission", 0),
            "Perkiraan bonus kreator":               o.get("est_creator_bonus", 0),
            "Bonus aktual kreator":                  o.get("actual_creator_bonus", 0),
            "Pengembalian barang":                   o.get("is_returned", False),
            "Pengembalian dana":                     o.get("refund_amount", 0),
            "Waktu Dibuat":                          epoch_to_wib(o.get("create_time")),
            "Waktu Pembayaran":                      epoch_to_wib(o.get("paid_time")),
            "Waktu Pesanan Siap Dikirim":            epoch_to_wib(o.get("rts_time")),
            "Order Delivery Time":                   epoch_to_wib(o.get("delivery_time")),
            "Waktu Pesanan Selesai":                 epoch_to_wib(o.get("completed_time")),
            "Waktu Komisi Dibayar":                  epoch_to_wib(o.get("commission_paid_time")),
            "Platform":                              o.get("platform", "TikTok"),
            "agreement_type":                        o.get("agreement_type", ""),
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
def save_token_to_db(token_data: dict, shop_info: dict, seller_name: str = "Unknown"):
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
    try:
        updated_at = datetime.fromisoformat(shop["updated_at"].replace("Z", "+00:00"))
        expires_in = shop.get("access_token_expire_in", 86400)
        expiry     = updated_at + timedelta(seconds=expires_in)
        now        = datetime.now(timezone.utc)

        if now >= expiry - timedelta(minutes=10):
            result = refresh_access_token(shop["refresh_token"])
            if result.get("code") == 0:
                new_data  = result.get("data", {})
                shop_info = {
                    "shop_id":     shop["shop_id"],
                    "shop_cipher": shop["shop_cipher"],
                    "shop_name":   shop["shop_name"],
                }
                save_token_to_db(new_data, shop_info, shop["shop_name"])
                shop["access_token"] = new_data.get("access_token", shop["access_token"])
                st.success("🔄 Token berhasil diperbarui otomatis.")
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

if auth_code:
    auth_code = str(auth_code)

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
            result = save_token_to_db(token_data, fallback_shop_info, seller_name)
        else:
            # Simpan semua toko yang diotorisasi (biasanya hanya 1)
            results = []
            for shop_info in authorized_shops:
                r = save_token_to_db(token_data, shop_info, seller_name)
                results.append(r)
            result = any(r is not None for r in results)

        if result:
            total = len(authorized_shops) if authorized_shops else 1
            st.success(f"✅ **{seller_name}** berhasil dihubungkan! ({total} toko tersimpan)")
            st.balloons()
            st.query_params.clear()
        else:
            st.error("❌ Gagal menyimpan ke database. Cek debug di atas.")

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

    now = datetime.now(timezone.utc)  # UTC aktual

    # Untuk "Kemarin" dalam WIB:
    if time_preset == "Kemarin":
        now_wib = now + timedelta(hours=7)  # konversi ke WIB dulu
        start_wib = now_wib.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
        end_wib   = start_wib + timedelta(days=1)
        start_date = start_wib  # tampil ke user dalam WIB
        end_date   = end_wib
    elif time_preset == "7 Hari":
        now_wib = now + timedelta(hours=7)
        start_date = now_wib - timedelta(days=7)
        end_date   = now_wib
    elif time_preset == "30 Hari":
        now_wib = now + timedelta(hours=7)
        start_date = now_wib - timedelta(days=30)
        end_date   = now_wib

    else:
        col1, col2 = st.columns(2)
        with col1:
            sd = st.date_input("Dari", now.date() - timedelta(days=7))
            st_time = st.time_input("Jam Mulai", datetime.strptime("00:00", "%H:%M").time())
        with col2:
            ed = st.date_input("Sampai", now.date())
            et_time = st.time_input("Jam Selesai", datetime.strptime("23:59", "%H:%M").time())
        start_date = datetime.combine(sd, st_time)
        end_date   = datetime.combine(ed, et_time)

    # Konversi WIB → UTC untuk API (WIB = UTC+7)
    start_utc = start_date - timedelta(hours=7)
    end_utc   = end_date   - timedelta(hours=7)
    st.info(f"🌍 UTC: {start_utc:%Y-%m-%d %H:%M} — {end_utc:%Y-%m-%d %H:%M}")
    st.markdown("---")

    if st.button("🔗 Hubungkan Toko Baru", use_container_width=True):
        auth_url = get_auth_url()
        st.markdown(f"[**Klik untuk Otorisasi TikTok Shop**]({auth_url})")

# ── Main Tabs ──────────────────────────────
if selected_shop:
    access_token = selected_shop["access_token"]
    shop_cipher  = selected_shop.get("shop_cipher") or selected_shop["shop_id"]
    date_suffix  = f"{start_date:%Y%m%d}_{end_date:%Y%m%d}"

    tab1, tab2, tab3, tab4 = st.tabs([
        "💰 Income/Settlement",
        "📦 Semua Pesanan",
        "👥 Creator Orders",
        "🛍️ Product Data (Iklan)",
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
                order_ids = [o.get("order_id") for o in orders]
                progress  = st.progress(0)
                details   = get_order_details_batch(access_token, shop_cipher, order_ids, progress_bar=progress)
                df = format_orders_excel(orders, details)
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
        st.subheader("Data Produk (Iklan)")
        if st.button("🔄 Tarik & Download", key="btn_products", type="primary"):
            with st.spinner("Mengambil data produk..."):
                products = get_products(access_token, shop_cipher)
            if products:
                df = format_product_excel(products)
                st.success(f"✅ {len(products)} produk")
                st.dataframe(df, use_container_width=True)
                st.download_button(
                    "📥 Download Excel Produk",
                    to_excel_download(df),
                    f"Product_Data_{shop_cipher}_{now:%Y%m%d}.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            else:
                st.info("Tidak ada produk aktif atau scope belum diaktifkan.")

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
