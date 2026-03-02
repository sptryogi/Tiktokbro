import streamlit as st
import requests
import time
import hmac
import hashlib
import pandas as pd
from datetime import datetime, timedelta
from supabase import create_client, Client

# --- KONFIGURASI API & DB ---
APP_KEY = st.secrets["TIKTOK_APP_KEY"]
APP_SECRET = st.secrets["TIKTOK_APP_SECRET"]
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
REDIRECT_URI = "https://tiktokbro.streamlit.app/" # Sesuaikan dengan URL deploy Anda

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
BASE_URL = "https://open-api.tiktokglobalshop.com"

# --- HELPER FUNCTIONS ---

def generate_signature(path, params):
    """Fungsi wajib untuk TikTok API: Menghasilkan signature HMAC-SHA256"""
    # 1. Sortir parameter kecuali 'sign' dan 'access_token'
    keys = sorted([k for k in params.keys() if k not in ["sign", "access_token"]])
    
    # 2. Gabungkan Path + Params
    input_str = path
    for k in keys:
        input_str += k + str(params[k])
    
    # 3. Bungkus dengan App Secret
    base_str = APP_SECRET + input_str + APP_SECRET
    
    # 4. HMAC-SHA256
    hash_res = hmac.new(APP_SECRET.encode('utf-8'), base_str.encode('utf-8'), hashlib.sha256)
    return hash_res.hexdigest()

def get_auth_url():
    """Membuat URL untuk tombol Otorisasi"""
    return f"https://services.tiktokshop.com/open/authorize?app_key={APP_KEY}&state=TiktokbroAuth"

def save_token_to_db(data):
    """Menyimpan atau mengupdate token di Supabase"""
    res = supabase.table("tiktok_shops").upsert({
        "shop_id": data["shop_id"],
        "shop_name": data.get("seller_name", "Toko Baru"),
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "access_token_expire_in": data["access_token_expire_in"],
        "refresh_token_expire_in": data["refresh_token_expire_in"],
        "updated_at": "now()"
    }).execute()
    return res

def fetch_tiktok_data(path, shop_token, additional_params={}):
    """Fungsi umum untuk tarik data dari TikTok"""
    ts = int(time.time())
    params = {
        "app_key": APP_KEY,
        "timestamp": ts,
        "shop_id": st.session_state.selected_shop_id, # Asumsi shop_id tersimpan
        **additional_params
    }
    
    sign = generate_signature(path, params)
    params["sign"] = sign
    params["access_token"] = shop_token
    
    full_url = f"{BASE_URL}{path}"
    response = requests.get(full_url, params=params)
    return response.json()

# --- UI STREAMLIT ---

st.set_page_config(page_title="Tiktokbro - Automation", layout="wide")
st.title("🚀 Tiktokbro Data Extractor")

# 1. LOGIKA HANDLE REDIRECT (Setelah user klik Authorize)
query_params = st.query_params
if "code" in query_params:
    code = query_params["code"]
    st.info("Sedang menukar kode dengan token...")
    # Logic tukar token (API call ke /api/v2/token/get)
    # Jika berhasil: save_token_to_db(res_data)
    st.success("Toko berhasil dihubungkan!")
    st.query_params.clear()

# 2. SIDEBAR: PILIH TOKO & RENTANG WAKTU
with st.sidebar:
    st.header("Konfigurasi")
    
    # Ambil daftar toko dari Supabase
    shops_data = supabase.table("tiktok_shops").select("*").execute()
    shop_options = {s['shop_name']: s for s in shops_data.data}
    
    if shop_options:
        selected_shop_name = st.selectbox("Pilih Toko", list(shop_options.keys()))
        selected_shop = shop_options[selected_shop_name]
        st.session_state.selected_shop_id = selected_shop['shop_id']
        st.session_state.access_token = selected_shop['access_token']
    else:
        st.warning("Belum ada toko terhubung.")
    
    st.markdown("---")
    st.subheader("Filter Waktu")
    time_filter = st.radio("Rentang Waktu", ["Kemarin", "7 Hari Terakhir", "30 Hari Terakhir", "Custom"])
    
    start_date = datetime.now()
    end_date = datetime.now()

    if time_filter == "Kemarin":
        start_date = datetime.now() - timedelta(days=1)
    elif time_filter == "7 Hari Terakhir":
        start_date = datetime.now() - timedelta(days=7)
    elif time_filter == "30 Hari Terakhir":
        start_date = datetime.now() - timedelta(days=30)
    elif time_filter == "Custom":
        start_date = st.date_input("Mulai dari", datetime.now() - timedelta(days=1))
        end_date = st.date_input("Sampai", datetime.now())

    st.markdown("---")
    if st.button("🔗 Hubungkan Toko Baru"):
        st.markdown(f"[Klik di sini untuk Otorisasi]({get_auth_url()})")

# 3. MAIN DASHBOARD DENGAN TAB
tab1, tab2, tab3, tab4 = st.tabs(["💰 Income", "📦 Semua Pesanan", "👥 Creator Orders", "🛍️ Product Data"])

with tab1:
    st.subheader("Laporan Income / Keuangan")
    if st.button("Tarik Data Income"):
        with st.spinner("Mengunduh data keuangan..."):
            # Contoh pemanggilan endpoint finance
            # data = fetch_tiktok_data("/api/finance/settlements", st.session_state.access_token)
            st.write("Data Settlement ditemukan untuk rentang waktu terpilih.")
            # st.table(pd.DataFrame(data)) # Visualisasi hasil

with tab2:
    st.subheader("Manajemen Pesanan")
    if st.button("Tarik Semua Pesanan"):
        # Logika fetch order list
        st.info(f"Menarik data dari {start_date.strftime('%Y-%m-%d')} ke {end_date.strftime('%Y-%m-%d')}")
        # Tampilkan DataFrame hasil

with tab3:
    st.subheader("Afiliasi / Creator Orders")
    st.write("Melihat performa pesanan melalui kreator.")

with tab4:
    st.subheader("Katalog Produk")
    if st.button("Cek Stok & Harga"):
        # Logika fetch products
        st.write("Menampilkan 50 produk terbaru...")
