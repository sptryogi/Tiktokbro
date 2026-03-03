import streamlit as st
import requests
import time
import hmac
import hashlib
import pandas as pd
from datetime import datetime, timedelta
from supabase import create_client, Client
import json
from io import BytesIO

# --- KONFIGURASI API & DB ---
APP_KEY = st.secrets["TIKTOK_APP_KEY"]
APP_SECRET = st.secrets["TIKTOK_APP_SECRET"]
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
REDIRECT_URI = "https://tiktokbro.streamlit.app/"  # WAJIB sama dengan Partner Center

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# TikTok Shop API Endpoints
BASE_URL = "https://open-api.tiktokglobalshop.com"
AUTH_URL = "https://auth.tiktok-shops.com"
AUTH_URL_SELLER = "https://auth.tiktok-shops.com/oauth/authorize" # Untuk Browser
TOKEN_URL_SERVER = "https://auth.tiktok-shops.com/api/v2/token/get" # Untuk Server-to-Server

# --- HELPER FUNCTIONS ---

def generate_signature(path, params, app_secret, body=None):
    # 1. Urutkan parameter secara alfabetis (kecuali sign dan access_token)
    keys = sorted([k for k in params.keys() if k not in ["sign", "access_token"]])
    
    # 2. Gabungkan key dan value
    param_string = "".join([f"{k}{params[k]}" for k in keys])
    
    # 3. Tambahkan body jika ada (untuk POST request)
    body_string = ""
    if body:
        # TikTok minta body dalam bentuk raw string JSON tanpa spasi yang tidak perlu
        body_string = json.dumps(body, separators=(',', ':'))
    
    # 4. Pola: secret + path + params + body + secret
    base_string = f"{app_secret}{path}{param_string}{body_string}{app_secret}"
    
    # 5. HMAC-SHA256
    signature = hmac.new(
        app_secret.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    
    return signature
def get_auth_url():
    """Generate URL otorisasi TikTok Shop - HANYA app_key dan state yang diperlukan"""
    # PERBAIKAN: Tidak include app_secret di URL authorize
    return f"{AUTH_URL_SELLER}/api/v2/token/get?app_key={APP_KEY}&state=TiktokbroAuth"

def exchange_auth_code(auth_code):
    """Tukar auth code dengan access token"""
    endpoint = "/api/v2/token/get"
    # url = f"{AUTH_URL}{endpoint}"
    url = TOKEN_URL_SERVER
    
    params = {
        "app_key": APP_KEY,
        "app_secret": APP_SECRET,  # app_secret di sini untuk autentikasi server
        "auth_code": auth_code,
        "grant_type": "authorized_app"
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"code": -1, "message": str(e)}

def refresh_access_token(refresh_token):
    """Refresh token yang sudah expired"""
    endpoint = "/api/v2/token/refresh"
    # url = f"{AUTH_URL}{endpoint}"
    url = "https://auth.tiktok-shops.com/api/v2/token/refresh"
    
    params = {
        "app_key": APP_KEY,
        "app_secret": APP_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        return response.json()
    except Exception as e:
        return {"code": -1, "message": str(e)}

def make_tiktok_request(endpoint, access_token, shop_id=None, method="POST", body=None):
    """Generic function untuk call TikTok Shop API dengan signature"""
    timestamp = int(time.time())
    
    params = {
        "app_key": APP_KEY,
        "timestamp": timestamp,
        "access_token": access_token,
        "timestamp": timestamp,
    }
    
    if shop_id:
        params["shop_id"] = shop_id
    
    if additional_params:
        # Filter None values
        additional_params = {k: v for k, v in additional_params.items() if v is not None}
        params.update(additional_params)
    
    sign = generate_signature(endpoint, params, APP_SECRET, body)
    params["sign"] = sign
    
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    
    try:
        if method.upper() == "POST":
            # Kirim body sebagai JSON string
            response = requests.post(url, params=query_params, json=body, headers=headers)
        else:
            response = requests.get(url, params=query_params, headers=headers)
            
        return response.json()
    except Exception as e:
        return {"code": -1, "message": str(e)}

# --- KONVERSI WAKTU UTC-7 (WIB) ---

def to_wib(utc_timestamp):
    """Konversi timestamp UTC ke WIB (UTC+7)"""
    if not utc_timestamp:
        return ""
    try:
        if isinstance(utc_timestamp, str):
            # Coba parse string timestamp
            utc_time = datetime.fromisoformat(utc_timestamp.replace('Z', '+00:00'))
        else:
            # Assume epoch timestamp
            utc_time = datetime.fromtimestamp(utc_timestamp, tz=timezone.utc)
        
        wib_time = utc_time + timedelta(hours=7)
        return wib_time.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(utc_timestamp)

def epoch_to_wib(epoch_ms):
    """Konversi epoch milliseconds ke WIB"""
    if not epoch_ms:
        return ""
    try:
        utc_time = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
        wib_time = utc_time + timedelta(hours=7)
        return wib_time.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ""

# --- API FUNCTIONS ---

def get_all_orders(access_token, shop_id, start_time, end_time):
    """Ambil semua pesanan dengan pagination"""
    all_orders = []
    page_token = None
    max_pages = 100  # Safety limit
    
    for page in range(max_pages):
        endpoint = "/api/orders/search"
        
        params = {
            "shop_id": shop_id,
            "create_time_ge": int(start_time.timestamp()),
            "create_time_lt": int(end_time.timestamp()),
            "page_size": 50,
            "sort_type": 1,
            "sort_field": "create_time"
        }
        
        if page_token:
            params["cursor"] = page_token
        
        result = make_tiktok_request(endpoint, access_token, shop_id, params)
        
        if result.get("code") == 0:
            data = result.get("data", {})
            orders = data.get("order_list", [])
            all_orders.extend(orders)
            
            page_token = data.get("next_page_token")
            if not page_token or not orders:
                break
        else:
            st.error(f"Error fetching orders: {result.get('message')}")
            break
    
    return all_orders

def get_order_detail_batch(access_token, shop_id, order_ids):
    """Ambil detail pesanan secara batch"""
    all_details = []
    
    # TikTok API mungkin support batch atau perlu individual calls
    # Asumsi individual calls untuk safety
    for order_id in order_ids:
        endpoint = "/api/orders/detail/query"
        params = {"shop_id": shop_id, "order_id": order_id}
        
        result = make_tiktok_request(endpoint, access_token, shop_id, params)
        if result.get("code") == 0:
            all_details.append(result.get("data", {}))
        
        # Rate limiting protection
        time.sleep(0.1)
    
    return all_details

def get_settlements(access_token, shop_id, start_time, end_time):
    """Ambil data settlement/income"""
    all_settlements = []
    page_token = None
    max_pages = 100
    
    for page in range(max_pages):
        endpoint = "/api/finance/settlement/search"
        
        params = {
            "shop_id": shop_id,
            "start_settlement_time": int(start_time.timestamp()),
            "end_settlement_time": int(end_time.timestamp()),
            "page_size": 50
        }
        
        if page_token:
            params["cursor"] = page_token
        
        result = make_tiktok_request(endpoint, access_token, shop_id, params)
        
        if result.get("code") == 0:
            data = result.get("data", {})
            settlements = data.get("settlement_list", [])
            all_settlements.extend(settlements)
            
            page_token = data.get("next_page_token")
            if not page_token or not settlements:
                break
        else:
            st.error(f"Error fetching settlements: {result.get('message')}")
            break
    
    return all_settlements

def get_products(access_token, shop_id):
    """Ambil semua produk"""
    all_products = []
    page_token = None
    max_pages = 100
    
    for page in range(max_pages):
        endpoint = "/api/products/search"
        
        params = {
            "shop_id": shop_id,
            "page_size": 50,
            "status": 1  # Active
        }
        
        if page_token:
            params["cursor"] = page_token
        
        result = make_tiktok_request(endpoint, access_token, shop_id, params)
        
        if result.get("code") == 0:
            data = result.get("data", {})
            products = data.get("product_list", [])
            all_products.extend(products)
            
            page_token = data.get("next_page_token")
            if not page_token or not products:
                break
        else:
            st.error(f"Error fetching products: {result.get('message')}")
            break
    
    return all_products

def get_affiliate_orders(access_token, shop_id, start_time, end_time):
    """Ambil data creator/affiliate orders"""
    all_orders = []
    page_token = None
    max_pages = 100
    
    for page in range(max_pages):
        # Endpoint affiliate mungkin berbeda, sesuaikan dengan docs terbaru
        endpoint = "/api/affiliate/orders"
        
        params = {
            "shop_id": shop_id,
            "start_time": int(start_time.timestamp()),
            "end_time": int(end_time.timestamp()),
            "page_size": 50
        }
        
        if page_token:
            params["cursor"] = page_token
        
        result = make_tiktok_request(endpoint, access_token, shop_id, params)
        
        if result.get("code") == 0:
            data = result.get("data", {})
            orders = data.get("order_list", [])
            all_orders.extend(orders)
            
            page_token = data.get("next_page_token")
            if not page_token or not orders:
                break
        else:
            # Affiliate API mungkin memerlukan scope berbeda
            st.warning(f"Affiliate API: {result.get('message')}")
            break
    
    return all_orders

# --- FORMATTING FUNCTIONS ---

def format_orders_excel(orders_data, order_details):
    """Format data pesanan sesuai kolom yang diminta"""
    rows = []
    
    for order in orders_data:
        order_id = order.get("order_id")
        detail = next((d for d in order_details if d.get("order_id") == order_id), {})
        
        # Extract info dasar
        order_status = order.get("order_status", "")
        order_substatus = order.get("order_sub_status", "")
        
        # Info waktu - KONVERSI KE WIB
        created_time = epoch_to_wib(order.get("create_time"))
        paid_time = epoch_to_wib(order.get("paid_time"))
        rts_time = epoch_to_wib(order.get("rts_time"))
        shipped_time = epoch_to_wib(order.get("shipped_time"))
        delivered_time = epoch_to_wib(order.get("delivered_time"))
        cancelled_time = epoch_to_wib(order.get("cancelled_time"))
        
        # Info pembatalan
        cancel_by = order.get("cancel_user", "")
        cancel_reason = order.get("cancel_reason", "")
        
        # Info pembeli & pengiriman
        buyer_info = detail.get("buyer_info", {})
        recipient_info = detail.get("recipient_info", {})
        payment_info = detail.get("payment_info", {})
        shipping_info = detail.get("shipping_info", {})
        
        # Loop untuk setiap item/SKU dalam pesanan
        items = detail.get("item_list", [])
        
        if not items:
            # Jika tidak ada detail item, buat 1 row dengan info order saja
            rows.append({
                "Order ID": order_id,
                "Order Status": order_status,
                "Order Substatus": order_substatus,
                "Cancelation/Return Type": "",
                "Normal or Pre-order": "Normal",
                "SKU ID": "",
                "Seller SKU": "",
                "Product Name": "",
                "Variation": "",
                "Quantity": 0,
                "Sku Quantity of return": 0,
                "SKU Unit Original Price": 0,
                "SKU Subtotal Before Discount": 0,
                "SKU Platform Discount": 0,
                "SKU Seller Discount": 0,
                "SKU Subtotal After Discount": 0,
                "Shipping Fee After Discount": order.get("shipping_fee", 0),
                "Original Shipping Fee": order.get("original_shipping_fee", 0),
                "Shipping Fee Seller Discount": 0,
                "Shipping Fee Platform Discount": 0,
                "Distance Shipping Fee": 0,
                "Distance Fee": 0,
                "Order Refund Amount": order.get("refund_amount", 0),
                "Payment platform discount": 0,
                "Buyer Service Fee": 0,
                "Handling Fee": 0,
                "Shipping Insurance": 0,
                "Item Insurance": 0,
                "Order Amount": order.get("total_amount", 0),
                "Created Time": created_time,
                "Paid Time": paid_time,
                "RTS Time": rts_time,
                "Shipped Time": shipped_time,
                "Delivered Time": delivered_time,
                "Cancelled Time": cancelled_time,
                "Cancel By": cancel_by,
                "Cancel Reason": cancel_reason,
                "Fulfillment Type": shipping_info.get("fulfillment_type", ""),
                "Warehouse Name": shipping_info.get("warehouse_name", ""),
                "Tracking ID": shipping_info.get("tracking_number", ""),
                "Delivery Option": shipping_info.get("delivery_option", ""),
                "Shipping Provider Name": shipping_info.get("shipping_provider_name", ""),
                "Buyer Message": buyer_info.get("buyer_message", ""),
                "Buyer Username": buyer_info.get("buyer_nickname", ""),
                "Recipient": recipient_info.get("name", ""),
                "Phone #": recipient_info.get("phone", ""),
                "Zipcode": recipient_info.get("zipcode", ""),
                "Country": recipient_info.get("country", ""),
                "Province": recipient_info.get("state", ""),
                "Regency and City": recipient_info.get("city", ""),
                "Districts": recipient_info.get("district", ""),
                "Villages": recipient_info.get("village", ""),
                "Detail Address": recipient_info.get("full_address", ""),
                "Additional address information": recipient_info.get("address_detail", ""),
                "Payment Method": payment_info.get("payment_method", ""),
                "Weight(kg)": 0,
                "Product Category": "",
                "Package ID": "",
                "Purchase Channel": order.get("purchase_channel", ""),
                "Seller Note": order.get("seller_note", ""),
                "Checked Status": "",
                "Checked Marked by": "",
                "Tokopedia Invoice Number": order.get("tokopedia_invoice", "")
            })
        else:
            for item in items:
                rows.append({
                    "Order ID": order_id,
                    "Order Status": order_status,
                    "Order Substatus": order_substatus,
                    "Cancelation/Return Type": item.get("return_type", ""),
                    "Normal or Pre-order": "Pre-order" if item.get("is_pre_order") else "Normal",
                    "SKU ID": item.get("sku_id", ""),
                    "Seller SKU": item.get("seller_sku", ""),
                    "Product Name": item.get("product_name", ""),
                    "Variation": item.get("variation_name", ""),
                    "Quantity": item.get("quantity", 0),
                    "Sku Quantity of return": item.get("return_quantity", 0),
                    "SKU Unit Original Price": item.get("original_price", 0),
                    "SKU Subtotal Before Discount": item.get("subtotal_before_discount", 0),
                    "SKU Platform Discount": item.get("platform_discount", 0),
                    "SKU Seller Discount": item.get("seller_discount", 0),
                    "SKU Subtotal After Discount": item.get("subtotal_after_discount", 0),
                    "Shipping Fee After Discount": order.get("shipping_fee", 0),
                    "Original Shipping Fee": order.get("original_shipping_fee", 0),
                    "Shipping Fee Seller Discount": item.get("shipping_fee_seller_discount", 0),
                    "Shipping Fee Platform Discount": item.get("shipping_fee_platform_discount", 0),
                    "Distance Shipping Fee": item.get("distance_shipping_fee", 0),
                    "Distance Fee": item.get("distance_fee", 0),
                    "Order Refund Amount": item.get("refund_amount", 0),
                    "Payment platform discount": item.get("payment_platform_discount", 0),
                    "Buyer Service Fee": item.get("buyer_service_fee", 0),
                    "Handling Fee": item.get("handling_fee", 0),
                    "Shipping Insurance": item.get("shipping_insurance", 0),
                    "Item Insurance": item.get("item_insurance", 0),
                    "Order Amount": order.get("total_amount", 0),
                    "Created Time": created_time,
                    "Paid Time": paid_time,
                    "RTS Time": rts_time,
                    "Shipped Time": shipped_time,
                    "Delivered Time": delivered_time,
                    "Cancelled Time": cancelled_time,
                    "Cancel By": cancel_by,
                    "Cancel Reason": cancel_reason,
                    "Fulfillment Type": shipping_info.get("fulfillment_type", ""),
                    "Warehouse Name": shipping_info.get("warehouse_name", ""),
                    "Tracking ID": shipping_info.get("tracking_number", ""),
                    "Delivery Option": shipping_info.get("delivery_option", ""),
                    "Shipping Provider Name": shipping_info.get("shipping_provider_name", ""),
                    "Buyer Message": buyer_info.get("buyer_message", ""),
                    "Buyer Username": buyer_info.get("buyer_nickname", ""),
                    "Recipient": recipient_info.get("name", ""),
                    "Phone #": recipient_info.get("phone", ""),
                    "Zipcode": recipient_info.get("zipcode", ""),
                    "Country": recipient_info.get("country", ""),
                    "Province": recipient_info.get("state", ""),
                    "Regency and City": recipient_info.get("city", ""),
                    "Districts": recipient_info.get("district", ""),
                    "Villages": recipient_info.get("village", ""),
                    "Detail Address": recipient_info.get("full_address", ""),
                    "Additional address information": recipient_info.get("address_detail", ""),
                    "Payment Method": payment_info.get("payment_method", ""),
                    "Weight(kg)": item.get("weight", 0) / 1000 if item.get("weight") else 0,
                    "Product Category": item.get("category_name", ""),
                    "Package ID": item.get("package_id", ""),
                    "Purchase Channel": order.get("purchase_channel", ""),
                    "Seller Note": order.get("seller_note", ""),
                    "Checked Status": item.get("checked_status", ""),
                    "Checked Marked by": item.get("checked_by", ""),
                    "Tokopedia Invoice Number": order.get("tokopedia_invoice", "")
                })
    
    return pd.DataFrame(rows)

def format_income_excel(settlements_data):
    """Format data income/settlement sesuai kolom yang diminta"""
    rows = []
    
    for settlement in settlements_data:
        # Konversi waktu ke WIB
        order_created_time = epoch_to_wib(settlement.get("order_create_time"))
        order_settled_time = epoch_to_wib(settlement.get("settlement_time"))
        
        rows.append({
            "Order/adjustment ID": settlement.get("order_id", ""),
            "Type": settlement.get("settlement_type", "Order"),
            "Order created time": order_created_time,
            "Order settled time": order_settled_time,
            "Currency": settlement.get("currency", "IDR"),
            "Total settlement amount": settlement.get("settlement_amount", 0),
            "Total Revenue": settlement.get("total_revenue", 0),
            "Subtotal after seller discounts": settlement.get("subtotal_after_discount", 0),
            "Subtotal before discounts": settlement.get("subtotal_before_discount", 0),
            "Seller discounts": settlement.get("seller_discount", 0),
            "Distance item fee from Horizon+ Program": settlement.get("distance_item_fee", 0),
            "Refund subtotal after seller discounts": settlement.get("refund_subtotal_after_discount", 0),
            "Refund subtotal before seller discounts": settlement.get("refund_subtotal_before_discount", 0),
            "Refund of seller discounts": settlement.get("refund_seller_discount", 0),
            "Total Fees": settlement.get("total_fee", 0),
            "Platform commission fee": settlement.get("platform_commission", 0),
            "Pre-order service fee": settlement.get("pre_order_service_fee", 0),
            "Mall service fee": settlement.get("mall_service_fee", 0),
            "Payment Fee": settlement.get("payment_fee", 0),
            "Shipping cost": settlement.get("shipping_cost", 0),
            "Shipping costs passed on to the logistics provider": settlement.get("shipping_cost_logistics", 0),
            "Replacement shipping fee (passed on to the customer)": settlement.get("replacement_shipping_fee", 0),
            "Exchange shipping fee (passed on to the customer)": settlement.get("exchange_shipping_fee", 0),
            "Shipping cost borne by the platform": settlement.get("shipping_cost_platform", 0),
            "Shipping cost paid by the customer": settlement.get("shipping_cost_customer", 0),
            "Refunded shipping cost paid by the customer": settlement.get("refunded_shipping_cost", 0),
            "Return shipping costs (passed on to the customer)": settlement.get("return_shipping_cost", 0),
            "Shipping cost subsidy": settlement.get("shipping_subsidy", 0),
            "Distance shipping fee from Horizon+ Program": settlement.get("distance_shipping_fee", 0),
            "Affiliate Commission": settlement.get("affiliate_commission", 0),
            "Affiliate partner commission": settlement.get("affiliate_partner_commission", 0),
            "Affiliate Shop Ads commission": settlement.get("affiliate_shop_ads_commission", 0),
            "Affiliate Partner shop ads commission": settlement.get("affiliate_partner_shop_ads", 0),
            "Shipping Fee Program service fee": settlement.get("shipping_fee_program_service", 0),
            "Dynamic commission": settlement.get("dynamic_commission", 0),
            "Bonus cashback service fee": settlement.get("bonus_cashback_fee", 0),
            "LIVE Specials service fee": settlement.get("live_specials_fee", 0),
            "Voucher Xtra service fee": settlement.get("voucher_xtra_fee", 0),
            "Order processing fee": settlement.get("order_processing_fee", 0),
            "EAMS Program service fee": settlement.get("eams_fee", 0),
            "Brands Crazy Deals/Flash Sale service fee": settlement.get("flash_sale_fee", 0),
            "Dilayani Tokopedia fee": settlement.get("dilayani_tokopedia_fee", 0),
            "Dilayani Tokopedia handling fee": settlement.get("dilayani_handling_fee", 0),
            "PayLater program fee": settlement.get("paylater_fee", 0),
            "Campaign resource fee": settlement.get("campaign_resource_fee", 0),
            "Installation service fee": settlement.get("installation_fee", 0),
            "Article 22 Income Tax withheld": settlement.get("pph22", 0),
            "Platform special service fee": settlement.get("platform_special_fee", 0),
            "GMV Max ad fee": settlement.get("gmv_max_ad_fee", 0),
            "Ajustment amount": settlement.get("adjustment_amount", 0),
            "Related order ID": settlement.get("related_order_id", ""),
            "Customer payment": settlement.get("customer_payment", 0),
            "Customer refund": settlement.get("customer_refund", 0),
            "Seller co-funded voucher discount": settlement.get("seller_voucher_discount", 0),
            "Refund of seller co-funded voucher discount": settlement.get("refund_seller_voucher", 0),
            "Platform discounts": settlement.get("platform_discount", 0),
            "Refund of platform discounts": settlement.get("refund_platform_discount", 0),
            "Platform co-funded voucher discounts": settlement.get("platform_co_funded_voucher", 0),
            "Refund of platform co-funded voucher discounts": settlement.get("refund_platform_co_funded", 0),
            "Seller shipping cost discount": settlement.get("seller_shipping_discount", 0),
            "Estimated package weight (g)": settlement.get("estimated_weight", 0),
            "Actual package weight (g)": settlement.get("actual_weight", 0),
            "Shopping center items": settlement.get("shopping_center_items", ""),
            "Order Source": settlement.get("order_source", "")
        })
    
    return pd.DataFrame(rows)

def format_product_excel(products_data):
    """Format data produk untuk iklan"""
    rows = []
    
    for product in products_data:
        # Hitung metrik iklan jika tersedia
        sales_data = product.get("sales_data", {})
        ad_data = product.get("ad_data", {})
        
        gross_revenue = sales_data.get("gross_revenue", 0)
        ad_cost = ad_data.get("cost", 0)
        orders = sales_data.get("orders", 0)
        
        roi = (gross_revenue - ad_cost) / ad_cost if ad_cost > 0 else 0
        cost_per_order = ad_cost / orders if orders > 0 else 0
        
        rows.append({
            "ID produk": product.get("product_id", ""),
            "Nama produk": product.get("product_name", ""),
            "Pesanan SKU": product.get("sku_count", 0),
            "Pendapatan kotor": gross_revenue,
            "Biaya": ad_cost,
            "Biaya per pesanan": cost_per_order,
            "ROI": round(roi, 2),
            "Mata uang": product.get("currency", "IDR")
        })
    
    return pd.DataFrame(rows)

def format_creator_orders_excel(affiliate_orders):
    """Format data creator/affiliate orders"""
    rows = []
    
    for order in affiliate_orders:
        # Konversi waktu ke WIB
        created_time = epoch_to_wib(order.get("create_time"))
        paid_time = epoch_to_wib(order.get("paid_time"))
        rts_time = epoch_to_wib(order.get("rts_time"))
        delivery_time = epoch_to_wib(order.get("delivery_time"))
        completed_time = epoch_to_wib(order.get("completed_time"))
        commission_paid_time = epoch_to_wib(order.get("commission_paid_time"))
        
        rows.append({
            "ID Pesanan": order.get("order_id", ""),
            "ID Produk": order.get("product_id", ""),
            "Produk": order.get("product_name", ""),
            "SKU": order.get("sku_name", ""),
            "ID Sku": order.get("sku_id", ""),
            "Penjual Sku": order.get("seller_sku", ""),
            "Harga": order.get("price", 0),
            "Payment Amount": order.get("payment_amount", 0),
            "Mata Uang": order.get("currency", "IDR"),
            "Kuantitas": order.get("quantity", 0),
            "Metode Pembayaran": order.get("payment_method", ""),
            "Status Pesanan": order.get("order_status", ""),
            "Nama pengguna kreator": order.get("creator_nickname", ""),
            "Jenis Konten": order.get("content_type", ""),
            "ID Konten": order.get("content_id", ""),
            "commission model": order.get("commission_model", ""),
            "Persentase komisi standar": order.get("standard_commission_rate", 0),
            "Est. Acuan Komisi": order.get("est_commission_base", 0),
            "Perkiraan pembayaran komisi standar": order.get("est_standard_commission", 0),
            "Acuan Komisi Aktual": order.get("actual_commission_base", 0),
            "Pembayaran Komisi Aktual": order.get("actual_standard_commission", 0),
            "Persentase komisi Iklan Toko": order.get("shop_ads_commission_rate", 0),
            "Perkiraan pembayaran komisi Iklan Toko": order.get("est_shop_ads_commission", 0),
            "Pembayaran komisi Iklan Toko aktual": order.get("actual_shop_ads_commission", 0),
            "Perkiraan bonus yang ditanggung bersama untuk kreator": order.get("est_creator_bonus", 0),
            "Bonus sebenarnya yang ditanggung bersama untuk kreator": order.get("actual_creator_bonus", 0),
            "Pengembalian barang": order.get("is_returned", False),
            "Pengembalian dana": order.get("refund_amount", 0),
            "Waktu Dibuat": created_time,
            "Waktu Pembayaran": paid_time,
            "Waktu Pesanan Siap Dikirim": rts_time,
            "Order Delivery Time": delivery_time,
            "Waktu Pesanan Selesai": completed_time,
            "Waktu Komisi Dibayar": commission_paid_time,
            "Platform": order.get("platform", "TikTok"),
            "agreement_type": order.get("agreement_type", "")
        })
    
    return pd.DataFrame(rows)

def to_excel_download(df, filename):
    """Convert DataFrame ke Excel download"""
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Data')
    output.seek(0)
    return output

# --- DATABASE FUNCTIONS ---

def save_token_to_db(token_data, seller_name="Unknown"):
    """Simpan token ke Supabase"""
    try:
        data = {
            "shop_id": token_data.get("seller_id") or token_data.get("shop_id"),
            "shop_name": seller_name,
            "access_token": token_data["access_token"],
            "refresh_token": token_data.get("refresh_token"),
            "access_token_expire_in": token_data.get("access_token_expire_in", 86400),
            "refresh_token_expire_in": token_data.get("refresh_token_expire_in", 2592000),
            "updated_at": datetime.now().isoformat()
        }
        
        result = supabase.table("tiktok_shops").upsert(data).execute()
        return result
    except Exception as e:
        st.error(f"Database error: {str(e)}")
        return None

def get_shop_tokens():
    """Ambil semua toko yang tersimpan"""
    try:
        result = supabase.table("tiktok_shops").select("*").execute()
        return result.data
    except Exception as e:
        st.error(f"Error fetching shops: {str(e)}")
        return []

# --- STREAMLIT UI ---

st.set_page_config(page_title="Tiktokbro - TikTok Shop Automation", layout="wide")
st.title("🚀 Tiktokbro Data Extractor")
st.markdown("### Integrasi TikTok Shop Seller API - WIB Timezone (UTC+7)")

# Handle OAuth Callback
query_params = st.query_params
if "code" in query_params:
    auth_code = query_params["code"]
    
    with st.spinner("Menghubungkan ke TikTok Shop..."):
        token_response = exchange_auth_code(auth_code)
        
        if token_response.get("code") == 0:
            data = token_response["data"]
            seller_name = data.get("seller_name", "Toko Baru")
            save_token_to_db(data, seller_name)
            st.success(f"✅ Toko **{seller_name}** berhasil dihubungkan!")
            st.balloons()
        else:
            st.error(f"❌ Gagal: {token_response.get('message', 'Unknown error')}")
            st.json(token_response)  # Debug
    
    st.query_params.clear()
    st.rerun()

# Sidebar
with st.sidebar:
    st.header("⚙️ Konfigurasi Toko")
    
    shops = get_shop_tokens()
    
    if not shops:
        st.warning("Belum ada toko terhubung")
        selected_shop = None
    else:
        shop_options = {s['shop_name']: s for s in shops}
        selected_name = st.selectbox("Pilih Toko", list(shop_options.keys()))
        selected_shop = shop_options[selected_name]
        
        st.info(f"Shop ID: ...{selected_shop['shop_id'][-6:]}")
        
        # Cek token expiry
        try:
            updated_at = datetime.fromisoformat(selected_shop['updated_at'].replace('Z', '+00:00'))
            expires_in = selected_shop.get('access_token_expire_in', 86400)
            expiry = updated_at + timedelta(seconds=expires_in)
            
            if datetime.now() > expiry:
                st.error("⚠️ Token expired! Re-authorize diperlukan.")
        except:
            pass
    
    st.markdown("---")
    
    # Filter Waktu
    st.subheader("📅 Filter Waktu (WIB)")
    time_preset = st.radio(
        "Rentang",
        ["Kemarin", "7 Hari", "30 Hari", "Custom"],
        horizontal=True
    )
    
    end_date = datetime.now()
    start_date = end_date
    
    if time_preset == "Kemarin":
        start_date = end_date - timedelta(days=1)
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date + timedelta(days=1)
    elif time_preset == "7 Hari":
        start_date = end_date - timedelta(days=7)
    elif time_preset == "30 Hari":
        start_date = end_date - timedelta(days=30)
    else:
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Dari", end_date - timedelta(days=7))
            start_time = st.time_input("Jam Mulai", value=datetime.strptime("00:00", "%H:%M").time())
        with col2:
            end_date = st.date_input("Sampai", end_date)
            end_time = st.time_input("Jam Selesai", value=datetime.strptime("23:59", "%H:%M").time())
        
        start_date = datetime.combine(start_date, start_time)
        end_date = datetime.combine(end_date, end_time)
    
    # Konversi ke UTC untuk API call (WIB = UTC+7, jadi kurangi 7 jam)
    start_date_utc = start_date - timedelta(hours=7)
    end_date_utc = end_date - timedelta(hours=7)
    
    st.info(f"🌍 UTC: {start_date_utc.strftime('%Y-%m-%d %H:%M')} - {end_date_utc.strftime('%Y-%m-%d %H:%M')}")
    
    st.markdown("---")
    
    if st.button("🔗 Hubungkan Toko Baru", use_container_width=True):
        auth_url = get_auth_url()
        st.markdown(f"[**Klik untuk Otorisasi**]({auth_url})")

# Main Content
if selected_shop:
    access_token = selected_shop['access_token']
    shop_id = selected_shop['shop_id']
    
    tab1, tab2, tab3, tab4 = st.tabs([
        "💰 Income/Settlement", 
        "📦 Semua Pesanan", 
        "👥 Creator Orders", 
        "🛍️ Product Data (Iklan)"
    ])
    
    # TAB 1: INCOME
    with tab1:
        st.subheader("Laporan Income & Settlement")
        st.caption(f"Periode WIB: {start_date.strftime('%d %b %Y %H:%M')} - {end_date.strftime('%d %b %Y %H:%M')}")
        
        if st.button("🔄 Tarik & Download Excel", key="btn_income", type="primary"):
            with st.spinner("Mengambil data keuangan..."):
                settlements = get_settlements(access_token, shop_id, start_date_utc, end_date_utc)
                
                if settlements:
                    df = format_income_excel(settlements)
                    st.success(f"✅ Ditemukan {len(settlements)} transaksi")
                    st.dataframe(df.head(10), use_container_width=True)
                    
                    # Download Excel
                    excel_file = to_excel_download(df, "income")
                    st.download_button(
                        label="📥 Download Excel Income",
                        data=excel_file,
                        file_name=f"Income_{shop_id}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                else:
                    st.info("Tidak ada data income untuk periode ini")
    
    # TAB 2: ORDERS
    with tab2:
        st.subheader("Daftar Pesanan Lengkap")
        st.caption(f"Periode WIB: {start_date.strftime('%d %b %Y %H:%M')} - {end_date.strftime('%d %b %Y %H:%M')}")
        
        if st.button("🔄 Tarik & Download Excel", key="btn_orders", type="primary"):
            with st.spinner("Mengambil data pesanan (ini mungkin memakan waktu)..."):
                # Step 1: Get order list
                orders = get_all_orders(access_token, shop_id, start_date_utc, end_date_utc)
                
                if orders:
                    st.info(f"📋 Ditemukan {len(orders)} pesanan, mengambil detail...")
                    
                    # Step 2: Get details for each order
                    order_ids = [o.get("order_id") for o in orders]
                    progress_bar = st.progress(0)
                    
                    order_details = []
                    for i, order_id in enumerate(order_ids):
                        detail = get_order_detail_batch(access_token, shop_id, [order_id])
                        order_details.extend(detail)
                        progress_bar.progress((i + 1) / len(order_ids))
                        time.sleep(0.05)  # Rate limiting
                    
                    # Step 3: Format to Excel
                    df = format_orders_excel(orders, order_details)
                    st.success(f"✅ Berhasil memproses {len(df)} baris data")
                    st.dataframe(df.head(10), use_container_width=True)
                    
                    # Download Excel
                    excel_file = to_excel_download(df, "orders")
                    st.download_button(
                        label="📥 Download Excel Pesanan",
                        data=excel_file,
                        file_name=f"Semua_Pesanan_{shop_id}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                else:
                    st.info("Tidak ada pesanan untuk periode ini")
    
    # TAB 3: CREATOR ORDERS
    with tab3:
        st.subheader("Afiliasi & Creator Orders")
        st.caption(f"Periode WIB: {start_date.strftime('%d %b %Y %H:%M')} - {end_date.strftime('%d %b %Y %H:%M')}")
        
        if st.button("🔄 Tarik & Download Excel", key="btn_creator", type="primary"):
            with st.spinner("Mengambil data affiliate..."):
                affiliate_orders = get_affiliate_orders(access_token, shop_id, start_date_utc, end_date_utc)
                
                if affiliate_orders:
                    df = format_creator_orders_excel(affiliate_orders)
                    st.success(f"✅ Ditemukan {len(affiliate_orders)} order affiliate")
                    st.dataframe(df.head(10), use_container_width=True)
                    
                    excel_file = to_excel_download(df, "creator_orders")
                    st.download_button(
                        label="📥 Download Excel Creator Orders",
                        data=excel_file,
                        file_name=f"Creator_Order_All_{shop_id}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                else:
                    st.warning("Tidak ada data affiliate atau scope belum diaktifkan")
    
    # TAB 4: PRODUCTS
    with tab4:
        st.subheader("Data Produk (Iklan)")
        
        if st.button("🔄 Tarik & Download Excel", key="btn_products", type="primary"):
            with st.spinner("Mengambil data produk..."):
                products = get_products(access_token, shop_id)
                
                if products:
                    df = format_product_excel(products)
                    st.success(f"✅ Ditemukan {len(products)} produk")
                    st.dataframe(df, use_container_width=True)
                    
                    excel_file = to_excel_download(df, "products")
                    st.download_button(
                        label="📥 Download Excel Produk",
                        data=excel_file,
                        file_name=f"Product_Data_Iklan_{shop_id}_{datetime.now().strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                else:
                    st.info("Tidak ada produk aktif atau scope belum diaktifkan")

else:
    st.info("👈 Silakan hubungkan toko terlebih dahulu melalui sidebar")
    
    with st.expander("📋 Panduan Setup"):
        st.markdown("""
        ### Langkah-langkah:
        1. Klik "Hubungkan Toko Baru" di sidebar
        2. Login ke TikTok Shop Anda
        3. Authorize aplikasi Tiktokbro
        4. Kembali ke aplikasi ini, token akan tersimpan otomatis
        
        ### Scope API yang Diperlukan:
        - ✅ **Order Information** - untuk data pesanan
        - ✅ **Finance Information** - untuk data income
        - ✅ **Product Basic** - untuk data produk
        - ✅ **Affiliate/Commission** - untuk data creator (jika ada)
        """)
