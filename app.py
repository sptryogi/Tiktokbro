import streamlit as st
import requests
import time
import hmac
import hashlib
import pandas as pd
from datetime import datetime, timedelta
from supabase import create_client, Client
import json

# --- KONFIGURASI API & DB ---
APP_KEY = st.secrets["TIKTOK_APP_KEY"]
APP_SECRET = st.secrets["TIKTOK_APP_SECRET"]
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
REDIRECT_URI = "https://tiktokbro.streamlit.app/"  # WAJIB sama dengan yang didaftarkan

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# TikTok Shop API Endpoints (Region Indonesia)
BASE_URL = "https://open-api.tiktokglobalshop.com"
AUTH_URL = "https://auth.tiktok-shops.com"

# --- HELPER FUNCTIONS ---

def generate_signature(path, params, app_secret):
    """
    Generate HMAC-SHA256 signature untuk TikTok Shop API
    Format: app_secret + path + param_string + app_secret
    """
    # 1. Filter dan sort parameter (exclude sign, access_token)
    filtered_params = {k: v for k, v in params.items() 
                      if k not in ["sign", "access_token"] and v is not None}
    sorted_keys = sorted(filtered_params.keys())
    
    # 2. Build param string: key1value1key2value2
    param_string = ""
    for key in sorted_keys:
        param_string += f"{key}{filtered_params[key]}"
    
    # 3. Build signature base string
    signature_base = f"{app_secret}{path}{param_string}{app_secret}"
    
    # 4. HMAC-SHA256
    signature = hmac.new(
        app_secret.encode('utf-8'),
        signature_base.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return signature

def get_auth_url():
    """Generate URL otorisasi untuk Seller"""
    # Untuk TikTok Shop Seller, gunakan endpoint authorize yang benar
    return f"{AUTH_URL}/api/v2/token/get?app_key={APP_KEY}&state=TiktokbroAuth"

def exchange_auth_code(auth_code):
    """Tukar auth code dengan access token"""
    endpoint = "/api/v2/token/get"
    url = f"{AUTH_URL}{endpoint}"
    
    params = {
        "app_key": APP_KEY,
        "app_secret": APP_SECRET,
        "auth_code": auth_code,
        "grant_type": "authorized_app"
    }
    
    response = requests.get(url, params=params)
    return response.json()

def refresh_access_token(refresh_token):
    """Refresh token yang sudah expired"""
    endpoint = "/api/v2/token/refresh"
    url = f"{AUTH_URL}{endpoint}"
    
    params = {
        "app_key": APP_KEY,
        "app_secret": APP_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    
    response = requests.get(url, params=params)
    return response.json()

def make_tiktok_request(endpoint, access_token, shop_id=None, additional_params=None):
    """
    Generic function untuk call TikTok Shop API dengan signature
    """
    timestamp = int(time.time())
    
    params = {
        "app_key": APP_KEY,
        "timestamp": timestamp,
        "access_token": access_token
    }
    
    if shop_id:
        params["shop_id"] = shop_id
    
    if additional_params:
        params.update(additional_params)
    
    # Generate signature
    sign = generate_signature(endpoint, params, APP_SECRET)
    params["sign"] = sign
    
    url = f"{BASE_URL}{endpoint}"
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"API Error: {str(e)}")
        return {"error": str(e)}

# --- API SPECIFIC FUNCTIONS ---

def get_order_list(access_token, shop_id, start_time, end_time, page_size=50):
    """Ambil daftar pesanan"""
    endpoint = "/api/orders/search"
    
    params = {
        "shop_id": shop_id,
        "create_time_ge": int(start_time.timestamp()),
        "create_time_lt": int(end_time.timestamp()),
        "page_size": page_size,
        "sort_type": 1,  # DESC
        "sort_field": "create_time"
    }
    
    return make_tiktok_request(endpoint, access_token, shop_id, params)

def get_order_detail(access_token, shop_id, order_id):
    """Ambil detail pesanan spesifik"""
    endpoint = "/api/orders/detail/query"
    
    params = {
        "shop_id": shop_id,
        "order_id": order_id
    }
    
    return make_tiktok_request(endpoint, access_token, shop_id, params)

def get_settlement_list(access_token, shop_id, start_time, end_time):
    """Ambil data income/settlement (MEMERLUKAN scope seller.finance.info)"""
    endpoint = "/api/finance/settlement/search"
    
    params = {
        "shop_id": shop_id,
        "start_settlement_time": int(start_time.timestamp()),
        "end_settlement_time": int(end_time.timestamp()),
        "page_size": 50
    }
    
    return make_tiktok_request(endpoint, access_token, shop_id, params)

def get_product_list(access_token, shop_id, page_size=50):
    """Ambil daftar produk (MEMERLUKAN scope seller.product.basic)"""
    endpoint = "/api/products/search"
    
    params = {
        "shop_id": shop_id,
        "page_size": page_size,
        "status": 1  # Active products
    }
    
    return make_tiktok_request(endpoint, access_token, shop_id, params)

def get_affiliate_orders(access_token, shop_id, start_time, end_time):
    """Ambil creator/affiliate orders (MEMERLUKAN scope khusus affiliate)"""
    # Endpoint ini mungkin berbeda, perlu cek dokumentasi terbaru
    endpoint = "/api/affiliate/orders"
    
    params = {
        "shop_id": shop_id,
        "start_time": int(start_time.timestamp()),
        "end_time": int(end_time.timestamp())
    }
    
    return make_tiktok_request(endpoint, access_token, shop_id, params)

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
st.markdown("### Integrasi TikTok Shop Seller API")

# Handle OAuth Callback
query_params = st.query_params
if "code" in query_params:
    auth_code = query_params["code"]
    
    with st.spinner("Menghubungkan ke TikTok Shop..."):
        token_response = exchange_auth_code(auth_code)
        
        if token_response.get("code") == 0:
            data = token_response["data"]
            save_token_to_db(data, data.get("seller_name", "Toko Baru"))
            st.success("✅ Toko berhasil dihubungkan!")
            st.balloons()
        else:
            st.error(f"❌ Gagal: {token_response.get('message', 'Unknown error')}")
    
    # Clear query params
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
        
        st.info(f"Shop ID: {selected_shop['shop_id'][:10]}...")
        
        # Cek token expiry
        updated_at = datetime.fromisoformat(selected_shop['updated_at'].replace('Z', '+00:00'))
        expires_in = selected_shop.get('access_token_expire_in', 86400)
        expiry = updated_at + timedelta(seconds=expires_in)
        
        if datetime.now() > expiry:
            st.error("⚠️ Token expired! Re-authorize diperlukan.")
    
    st.markdown("---")
    
    # Filter Waktu
    st.subheader("📅 Filter Waktu")
    time_preset = st.radio(
        "Rentang",
        ["Kemarin", "7 Hari", "30 Hari", "Custom"],
        horizontal=True
    )
    
    end_date = datetime.now()
    
    if time_preset == "Kemarin":
        start_date = end_date - timedelta(days=1)
        start_date = start_date.replace(hour=0, minute=0, second=0)
        end_date = end_date.replace(hour=0, minute=0, second=0)
    elif time_preset == "7 Hari":
        start_date = end_date - timedelta(days=7)
    elif time_preset == "30 Hari":
        start_date = end_date - timedelta(days=30)
    else:
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Dari", end_date - timedelta(days=7))
        with col2:
            end_date = st.date_input("Sampai", end_date)
        start_date = datetime.combine(start_date, datetime.min.time())
        end_date = datetime.combine(end_date, datetime.max.time())
    
    st.markdown("---")
    
    # Tombol Authorize
    if st.button("🔗 Hubungkan Toko Baru", use_container_width=True):
        auth_url = get_auth_url()
        st.markdown(f"[**Klik untuk Otorisasi**]({auth_url})")
        st.info("Anda akan diarahkan ke TikTok untuk login")

# Main Content
if selected_shop:
    access_token = selected_shop['access_token']
    shop_id = selected_shop['shop_id']
    
    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "💰 Income/Settlement", 
        "📦 Semua Pesanan", 
        "👥 Creator Orders", 
        "🛍️ Product Data"
    ])
    
    # TAB 1: INCOME
    with tab1:
        st.subheader("Laporan Income & Settlement")
        st.caption(f"Periode: {start_date.strftime('%d %b %Y')} - {end_date.strftime('%d %b %Y')}")
        
        if st.button("🔄 Tarik Data Income", key="btn_income"):
            with st.spinner("Mengambil data keuangan..."):
                result = get_settlement_list(access_token, shop_id, start_date, end_date)
                
                if result.get("code") == 0:
                    settlements = result.get("data", {}).get("settlement_list", [])
                    if settlements:
                        df = pd.DataFrame(settlements)
                        st.success(f"Ditemukan {len(settlements)} transaksi")
                        st.dataframe(df, use_container_width=True)
                        
                        # Download button
                        csv = df.to_csv(index=False)
                        st.download_button(
                            "📥 Download CSV",
                            csv,
                            f"income_{shop_id}_{start_date.strftime('%Y%m%d')}.csv",
                            "text/csv"
                        )
                    else:
                        st.info("Tidak ada data settlement untuk periode ini")
                else:
                    error_msg = result.get("message", "Unknown error")
                    if "permission" in error_msg.lower() or "scope" in error_msg.lower():
                        st.error("❌ Scope 'Finance Information' belum diaktifkan. Silakan apply di Partner Center.")
                    else:
                        st.error(f"API Error: {error_msg}")
    
    # TAB 2: ORDERS
    with tab2:
        st.subheader("Daftar Pesanan")
        st.caption(f"Periode: {start_date.strftime('%d %b %Y')} - {end_date.strftime('%d %b %Y')}")
        
        col1, col2 = st.columns([1, 3])
        with col1:
            if st.button("🔄 Tarik Semua Pesanan", key="btn_orders"):
                with st.spinner("Mengambil data pesanan..."):
                    result = get_order_list(access_token, shop_id, start_date, end_date)
                    
                    if result.get("code") == 0:
                        orders = result.get("data", {}).get("order_list", [])
                        if orders:
                            df = pd.DataFrame(orders)
                            st.session_state['orders_data'] = df
                            st.success(f"Ditemukan {len(orders)} pesanan")
                        else:
                            st.info("Tidak ada pesanan untuk periode ini")
                    else:
                        error_msg = result.get("message", "")
                        if "permission" in error_msg.lower():
                            st.error("❌ Scope 'Order Information' belum diaktifkan.")
                        else:
                            st.error(f"Error: {error_msg}")
        
        with col2:
            if 'orders_data' in st.session_state:
                df = st.session_state['orders_data']
                st.dataframe(df, use_container_width=True)
                
                # Detail viewer
                if st.checkbox("Lihat Detail Pesanan"):
                    order_ids = df['order_id'].tolist() if 'order_id' in df.columns else []
                    if order_ids:
                        selected_order = st.selectbox("Pilih Order ID", order_ids)
                        if st.button("Lihat Detail"):
                            detail = get_order_detail(access_token, shop_id, selected_order)
                            st.json(detail)
    
    # TAB 3: CREATOR ORDERS
    with tab3:
        st.subheader("Afiliasi & Creator Orders")
        st.warning("⚠️ Fitur ini memerlukan scope tambahan untuk Affiliate API")
        
        if st.button("🔄 Tarik Creator Orders", key="btn_creator"):
            with st.spinner("Mengambil data affiliate..."):
                result = get_affiliate_orders(access_token, shop_id, start_date, end_date)
                st.json(result)  # Debug mode
    
    # TAB 4: PRODUCTS
    with tab4:
        st.subheader("Katalog Produk")
        
        if st.button("🔄 Tarik Data Produk", key="btn_products"):
            with st.spinner("Mengambil data produk..."):
                result = get_product_list(access_token, shop_id)
                
                if result.get("code") == 0:
                    products = result.get("data", {}).get("product_list", [])
                    if products:
                        df = pd.DataFrame(products)
                        st.success(f"Ditemukan {len(products)} produk")
                        st.dataframe(df, use_container_width=True)
                    else:
                        st.info("Tidak ada produk aktif")
                else:
                    error_msg = result.get("message", "")
                    if "permission" in error_msg.lower():
                        st.error("❌ Scope 'Product Basic' belum diaktifkan.")
                    else:
                        st.error(f"Error: {error_msg}")

else:
    st.info("👈 Silakan hubungkan toko terlebih dahulu melalui sidebar")
