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
def generate_signature(params: dict, app_secret: str) -> str:
    """
    TikTok Shop API v2 signature:
    HMAC-SHA256( app_secret + sorted(key+value ...) + app_secret )
    """
    exclude = {"sign", "access_token"}
    sign_params = {k: v for k, v in params.items()
                   if k not in exclude and v is not None}

    sorted_keys = sorted(sign_params.keys())

    sign_string = app_secret
    for key in sorted_keys:
        sign_string += f"{key}{sign_params[key]}"
    sign_string += app_secret

    # FIX: hmac.new tidak ada — yang benar adalah hmac.new() versi Python
    # Python's hmac module: hmac.new(key_bytes, msg_bytes, digestmod)
    signature = hmac.new(
        app_secret.encode("utf-8"),
        sign_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()

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
    FIX #1: Gunakan POST bukan GET
    FIX #2: grant_type = "authorized_code"
    FIX #3: Kirim sebagai query params (bukan body) sesuai docs TikTok
    """
    url = f"{AUTH_URL}/api/v2/token/get"
    params = {
        "app_key":    APP_KEY,
        "app_secret": APP_SECRET,
        "auth_code":  auth_code,
        "grant_type": "authorized_code",
    }
    try:
        # TikTok token endpoint menerima GET dengan query params
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
    timestamp = str(int(time.time()))

    params = {
        "app_key":   APP_KEY,
        "timestamp": timestamp,
    }
    if shop_cipher:
        params["shop_cipher"] = shop_cipher

    # Tambah extra params (filter, pagination, dll) — skip None
    for k, v in extra_params.items():
        if v is not None:
            params[k] = v

    params["sign"]         = generate_signature(params, APP_SECRET)
    params["access_token"] = access_token   # access_token di query, bukan header

    url     = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}

    try:
        if method.upper() == "POST":
            resp = requests.post(url, params=params, json=body, headers=headers, timeout=30)
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
    all_orders, cursor = [], None
    for _ in range(100):
        extra = {
            "create_time_ge": int(start_time.timestamp()),
            "create_time_lt": int(end_time.timestamp()),
            "page_size":      50,
            "sort_type":      1,
            "sort_field":     "create_time",
        }
        if cursor:
            extra["cursor"] = cursor

        result = make_tiktok_request("/api/orders/search", access_token, shop_cipher, **extra)

        if result.get("code") == 0:
            data   = result.get("data", {})
            orders = data.get("order_list", [])
            all_orders.extend(orders)
            cursor = data.get("next_page_token")
            if not cursor or not orders:
                break
        else:
            st.error(f"Error pesanan: {result.get('message')}")
            st.json(result)
            break
    return all_orders


def get_order_detail(access_token, shop_cipher, order_id):
    result = make_tiktok_request(
        "/api/orders/detail/query",
        access_token,
        shop_cipher,
        order_id=order_id,
    )
    return result.get("data", {}) if result.get("code") == 0 else {}


def get_settlements(access_token, shop_cipher, start_time, end_time):
    all_settlements, cursor = [], None
    for _ in range(100):
        extra = {
            "settlement_time_ge": int(start_time.timestamp()),
            "settlement_time_lt": int(end_time.timestamp()),
            "page_size":          50,
        }
        if cursor:
            extra["cursor"] = cursor

        result = make_tiktok_request(
            "/api/finance/order/settlements", access_token, shop_cipher, **extra
        )
        if result.get("code") == 0:
            data        = result.get("data", {})
            settlements = data.get("settlement_list", [])
            all_settlements.extend(settlements)
            cursor = data.get("next_page_token")
            if not cursor or not settlements:
                break
        else:
            st.error(f"Error settlement: {result.get('message')}")
            st.json(result)
            break
    return all_settlements


def get_products(access_token, shop_cipher):
    all_products, cursor = [], None
    for _ in range(100):
        extra = {"page_size": 50, "status": 1}
        if cursor:
            extra["cursor"] = cursor

        result = make_tiktok_request(
            "/api/products/search", access_token, shop_cipher, **extra
        )
        if result.get("code") == 0:
            data     = result.get("data", {})
            products = data.get("product_list", [])
            all_products.extend(products)
            cursor = data.get("next_page_token")
            if not cursor or not products:
                break
        else:
            st.error(f"Error produk: {result.get('message')}")
            st.json(result)
            break
    return all_products


def get_affiliate_orders(access_token, shop_cipher, start_time, end_time):
    all_orders, cursor = [], None
    for _ in range(100):
        extra = {
            "create_time_ge": int(start_time.timestamp()),
            "create_time_lt": int(end_time.timestamp()),
            "page_size":      50,
        }
        if cursor:
            extra["cursor"] = cursor

        result = make_tiktok_request(
            "/api/affiliate/orders/search", access_token, shop_cipher, **extra
        )
        if result.get("code") == 0:
            data   = result.get("data", {})
            orders = data.get("order_list", [])
            all_orders.extend(orders)
            cursor = data.get("next_page_token")
            if not cursor or not orders:
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


def format_income_excel(settlements_data):
    rows = []
    for s in settlements_data:
        rows.append({
            "Order/adjustment ID":                     s.get("order_id", ""),
            "Type":                                    s.get("settlement_type", "Order"),
            "Order created time":                      epoch_to_wib(s.get("order_create_time")),
            "Order settled time":                      epoch_to_wib(s.get("settlement_time")),
            "Currency":                                s.get("currency", "IDR"),
            "Total settlement amount":                 s.get("settlement_amount", 0),
            "Total Revenue":                           s.get("total_revenue", 0),
            "Subtotal after seller discounts":         s.get("subtotal_after_discount", 0),
            "Subtotal before discounts":               s.get("subtotal_before_discount", 0),
            "Seller discounts":                        s.get("seller_discount", 0),
            "Distance item fee from Horizon+ Program": s.get("distance_item_fee", 0),
            "Refund subtotal after seller discounts":  s.get("refund_subtotal_after_discount", 0),
            "Refund subtotal before seller discounts": s.get("refund_subtotal_before_discount", 0),
            "Refund of seller discounts":              s.get("refund_seller_discount", 0),
            "Total Fees":                              s.get("total_fee", 0),
            "Platform commission fee":                 s.get("platform_commission", 0),
            "Pre-order service fee":                   s.get("pre_order_service_fee", 0),
            "Mall service fee":                        s.get("mall_service_fee", 0),
            "Payment Fee":                             s.get("payment_fee", 0),
            "Shipping cost":                           s.get("shipping_cost", 0),
            "Shipping costs passed on to logistics":   s.get("shipping_cost_logistics", 0),
            "Replacement shipping fee":                s.get("replacement_shipping_fee", 0),
            "Exchange shipping fee":                   s.get("exchange_shipping_fee", 0),
            "Shipping cost borne by platform":         s.get("shipping_cost_platform", 0),
            "Shipping cost paid by customer":          s.get("shipping_cost_customer", 0),
            "Refunded shipping cost by customer":      s.get("refunded_shipping_cost", 0),
            "Return shipping costs":                   s.get("return_shipping_cost", 0),
            "Shipping cost subsidy":                   s.get("shipping_subsidy", 0),
            "Distance shipping fee Horizon+":          s.get("distance_shipping_fee", 0),
            "Affiliate Commission":                    s.get("affiliate_commission", 0),
            "Affiliate partner commission":            s.get("affiliate_partner_commission", 0),
            "Affiliate Shop Ads commission":           s.get("affiliate_shop_ads_commission", 0),
            "Affiliate Partner shop ads commission":   s.get("affiliate_partner_shop_ads", 0),
            "Shipping Fee Program service fee":        s.get("shipping_fee_program_service", 0),
            "Dynamic commission":                      s.get("dynamic_commission", 0),
            "Bonus cashback service fee":              s.get("bonus_cashback_fee", 0),
            "LIVE Specials service fee":               s.get("live_specials_fee", 0),
            "Voucher Xtra service fee":                s.get("voucher_xtra_fee", 0),
            "Order processing fee":                    s.get("order_processing_fee", 0),
            "EAMS Program service fee":                s.get("eams_fee", 0),
            "Flash Sale service fee":                  s.get("flash_sale_fee", 0),
            "Dilayani Tokopedia fee":                  s.get("dilayani_tokopedia_fee", 0),
            "Dilayani Tokopedia handling fee":         s.get("dilayani_handling_fee", 0),
            "PayLater program fee":                    s.get("paylater_fee", 0),
            "Campaign resource fee":                   s.get("campaign_resource_fee", 0),
            "Installation service fee":                s.get("installation_fee", 0),
            "Article 22 Income Tax withheld":          s.get("pph22", 0),
            "Platform special service fee":            s.get("platform_special_fee", 0),
            "GMV Max ad fee":                          s.get("gmv_max_ad_fee", 0),
            "Adjustment amount":                       s.get("adjustment_amount", 0),
            "Related order ID":                        s.get("related_order_id", ""),
            "Customer payment":                        s.get("customer_payment", 0),
            "Customer refund":                         s.get("customer_refund", 0),
            "Seller co-funded voucher discount":       s.get("seller_voucher_discount", 0),
            "Refund of seller co-funded voucher":      s.get("refund_seller_voucher", 0),
            "Platform discounts":                      s.get("platform_discount", 0),
            "Refund of platform discounts":            s.get("refund_platform_discount", 0),
            "Platform co-funded voucher discounts":    s.get("platform_co_funded_voucher", 0),
            "Refund of platform co-funded voucher":    s.get("refund_platform_co_funded", 0),
            "Seller shipping cost discount":           s.get("seller_shipping_discount", 0),
            "Estimated package weight (g)":            s.get("estimated_weight", 0),
            "Actual package weight (g)":               s.get("actual_weight", 0),
            "Shopping center items":                   s.get("shopping_center_items", ""),
            "Order Source":                            s.get("order_source", ""),
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
def save_token_to_db(token_data: dict, seller_name: str = "Unknown"):
    """
    FIX: Petakan field dari response TikTok token ke kolom Supabase dengan benar.
    Response TikTok v2 token berisi:
      - access_token, refresh_token, access_token_expire_in, refresh_token_expire_in
      - seller_id (bisa berisi shop_id), seller_name, shop_cipher (list shops)
    """
    try:
        # shop_id — coba beberapa field yang mungkin ada di response
        shop_id = (
            token_data.get("seller_id")
            or token_data.get("shop_id")
            or token_data.get("user_id")
            or "unknown"
        )

        # shop_cipher — TikTok v2 kadang kirim sebagai list of authorized_shops
        shop_cipher = None
        authorized_shops = token_data.get("authorized_shops", [])
        if authorized_shops and isinstance(authorized_shops, list):
            # Ambil cipher toko pertama
            shop_cipher = authorized_shops[0].get("shop_cipher") or authorized_shops[0].get("shop_id")
        if not shop_cipher:
            shop_cipher = token_data.get("shop_cipher") or shop_id

        # seller_name dari response jika ada
        resolved_name = token_data.get("seller_name") or seller_name

        data = {
            "shop_id":                   str(shop_id),
            "shop_cipher":               str(shop_cipher),
            "shop_name":                 resolved_name,
            "access_token":              token_data.get("access_token", ""),
            "refresh_token":             token_data.get("refresh_token", ""),
            "access_token_expire_in":    token_data.get("access_token_expire_in", 86400),
            "refresh_token_expire_in":   token_data.get("refresh_token_expire_in", 2592000),
            "updated_at":                datetime.now(timezone.utc).isoformat(),
        }

        # Debug: tampilkan data yang akan disimpan
        st.write("🔍 Debug data yang akan disimpan ke DB:", data)

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
        updated_at  = datetime.fromisoformat(shop["updated_at"].replace("Z", "+00:00"))
        expires_in  = shop.get("access_token_expire_in", 86400)
        expiry      = updated_at + timedelta(seconds=expires_in)
        now         = datetime.now(timezone.utc)

        # Refresh kalau sisa < 10 menit
        if now >= expiry - timedelta(minutes=10):
            result = refresh_access_token(shop["refresh_token"])
            if result.get("code") == 0:
                new_data = result.get("data", {})
                save_token_to_db(new_data, shop["shop_name"])
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
    with st.spinner("Menukar kode otorisasi dengan access token..."):
        token_response = exchange_auth_code(auth_code)

    if token_response.get("code") != 0:
        st.error(f"❌ Gagal tukar auth code: {token_response.get('message', 'Unknown error')}")
        st.json(token_response)
    else:
        data        = token_response.get("data", {})
        seller_name = data.get("seller_name", "Toko Baru")
        result      = save_token_to_db(data, seller_name)
        if result:
            st.success(f"✅ Toko **{seller_name}** berhasil dihubungkan!")
            st.balloons()
            # Hapus query param agar tidak re-trigger saat refresh
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

    now = datetime.now()
    if time_preset == "Kemarin":
        start_date = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end_date   = start_date + timedelta(days=1)
    elif time_preset == "7 Hari":
        start_date = now - timedelta(days=7)
        end_date   = now
    elif time_preset == "30 Hari":
        start_date = now - timedelta(days=30)
        end_date   = now
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
                settlements = get_settlements(access_token, shop_cipher, start_utc, end_utc)
            if settlements:
                df = format_income_excel(settlements)
                st.success(f"✅ {len(settlements)} transaksi ditemukan")
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
                progress = st.progress(0)
                details  = []
                for i, o in enumerate(orders):
                    details.append(get_order_detail(access_token, shop_cipher, o.get("order_id")))
                    progress.progress((i + 1) / len(orders))
                    time.sleep(0.05)
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
