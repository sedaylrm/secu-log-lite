import streamlit as st
import pandas as pd
import re
import sqlite3
import os

st.set_page_config(page_title="SecuLog Lite - Enterprise SOC", page_icon="🛡️", layout="wide")

# --- 1. VERİTABANI BAŞLANGICI (SQLite) ---
def init_db():
    conn = sqlite3.connect("security_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyzed_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            request TEXT,
            status_code INTEGER,
            size INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

st.title("🛡️ SecuLog Lite - Kurumsal Güvenlik ve Log İzleme Paneli")
st.write("Bu araç; sunucu loglarını analiz eden, tehdit avcılığı yapan ve verileri yerel veritabanında saklayan tam kapsamlı bir SOC simülatörüdür.")

# --- 2. DOSYA YÜKLEME ALANI (Kullanıcı kendi logunu yükleyebilir) ---
st.sidebar.header("📁 Log Kaynağı Yönetimi")
uploaded_file = st.sidebar.file_uploader("Bir log dosyası (.log veya .txt) yükleyin", type=["log", "txt"])

# Hangi log dosyasını okuyacağız?
target_file = None
if uploaded_file is not None:
    # Kullanıcının yüklediği dosyayı geçici olarak kaydedelim
    with open("temp_access.log", "wb") as f:
        f.write(uploaded_file.getbuffer())
    target_file = "temp_access.log"
    st.sidebar.success("Özel log dosyası başarıyla yüklendi!")
elif os.path.exists("access.log"):
    target_file = "access.log"
    st.sidebar.info("Varsayılan `access.log` dosyası kullanılıyor.")

# Log okuma fonksiyonu
def parse_and_save_logs(filepath):
    log_data = []
    pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)'
    
    conn = sqlite3.connect("security_logs.db")
    cursor = conn.cursor()
    # Her yeni yüklemede tabloyu temizleyip güncel veriyi basalım
    cursor.execute("DELETE FROM analyzed_logs")
    
    try:
        with open(filepath, "r") as f:
            for line in f:
                match = re.match(pattern, line)
                if match:
                    ip, timestamp, request, status, size = match.groups()
                    cursor.execute("""
                        INSERT INTO analyzed_logs (ip, timestamp, request, status_code, size)
                        VALUES (?, ?, ?, ?, ?)
                    """, (ip, timestamp, request, int(status), int(size)))
        conn.commit()
    except Exception as e:
        st.error(f"Log işlenirken hata oluştu: {e}")
    finally:
        conn.close()

if target_file:
    parse_and_save_logs(target_file)

# Veritabanından verileri çekme
def load_from_db():
    conn = sqlite3.connect("security_logs.db")
    df = pd.read_sql("SELECT ip as IP, timestamp as Zaman, request as İstek, status_code as 'Durum Kodu', size as Boyut FROM analyzed_logs", conn)
    conn.close()
    return df

df = load_from_db()

if not df.empty:
    # Üst kısımda genel metrikler
    col1, col2, col3 = st.columns(3)
    col1.metric("Toplam İstek Sayısı", len(df))
    col2.metric("Benzersiz IP Sayısı", df["IP"].nunique())
    col3.metric("Şüpheli/Hatalı Kodlar (4xx)", len(df[df["Durum Kodu"] >= 400]))
    
    # --- TEHDİT ANALİZİ VE AKILLI FİLTRELEME ---
    st.markdown("---")
    st.subheader("🚨 Tehdit Avcılığı ve Şüpheli Aktiviteler")
    
    failed_logins = df[(df["Durum Kodu"].isin([401, 403]))]
    ip_counts = failed_logins["IP"].value_counts()
    suspicious_ips = ip_counts[ip_counts >= 2].index.tolist()
    
    path_attacks = df[df["İstek"].str.contains(r"\.|etc/passwd|admin|config", na=False)]
    
    col_t1, col_t2 = st.columns(2)
    
    with col_t1:
        st.markdown("### ⚠️ Olası Brute-Force (Kaba Kuvvet) Girişimleri")
        if len(suspicious_ips) > 0:
            st.error(f"Dikkat! Şüpheli IP'ler tespit edildi: {', '.join(suspicious_ips)}")
            brute_df = df[df["IP"].isin(suspicious_ips)]
            st.dataframe(brute_df, use_container_width=True)
        else:
            st.info("Kaba kuvvet imzasına rastlanmadı.")
            
    with col_t2:
        st.markdown("### 🎯 Zararlı Dizin / Dosya Tarama")
        if not path_attacks.empty:
            st.warning("Sistemde yetkisiz dosya veya dizin tarama girişimi saptandı!")
            st.dataframe(path_attacks, use_container_width=True)
        else:
            st.info("Zararlı dizin taraması tespit edilmedi.")
            
    st.markdown("---")
    st.subheader("📋 Veritabanına Kayıtlı Ham Log Verileri")
    st.dataframe(df, use_container_width=True)
else:
    st.warning("Veritabanında görüntülenecek log verisi bulunamadı!")