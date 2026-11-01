# 🛡️ SecuLog Lite - Enterprise SOC & Log Analysis Dashboard

> Python, Pandas, SQLite ve Streamlit kullanılarak geliştirilmiş web tabanlı bir Güvenlik Operasyon Merkezi (SOC) ve Log Analiz Simülatörüdür.

## 📌 Proje Hakkında
Bu proje; kurumsal web sunucu loglarını (`access.log`) otomatik olarak parse eden, **Brute-Force (Kaba Kuvvet)** ve **Path Traversal (Zararlı Dizin Tarama)** gibi siber saldırı imzalarını tespit eden ve verileri yerel bir **SQLite** veritabanında saklayan hafif, ölçeklenebilir bir güvenlik aracıdır.

## 🚀 Temel Özellikler
* **Dinamik Log Kaynağı Yönetimi:** İstendiğinde varsayılan log dosyası kullanılabilir, istendiğinde arayüz üzerindeki dosya yükleme (`file uploader`) bileşeni ile farklı log dosyaları sisteme dahil edilerek anlık analiz yapılabilir.
* **Tehdit Avcılığı (Threat Hunting) Motoru:** 
  * `401 / 403` hata kodlarına ve istek sıklığına bakarak şüpheli IP adreslerini ve olası Brute-Force girişimlerini izole eder.
  * `etc/passwd`, `admin`, `config` veya üst dizin tarama (`..`) kalıplarını regex ile tarayarak yetkisiz erişim denemelerini raporlar.
* **Veritabanı Katmanı (SQLite):** Tüm ham ve işlenen log verileri kalıcı olarak SQLite veritabanında saklanır.
* **Modern Web Arayüzü:** Streamlit tabanlı, kurumsal koyu tema (dark mode) tasarımına sahip interaktif yönetim paneli.

## 🛠️ Kullanılan Teknolojiler
* **Python 3.13** (Backend mantığı ve regex parse işlemleri)
* **Streamlit** (Arayüz ve web sunumu)
* **Pandas** (Veri manipülasyonu ve filtreleme)
* **SQLite3** (İlişkisel veritabanı yönetimi)

## ⚙️ Kurulum ve Çalıştırma

Projeyi yerel ortamınızda çalıştırmak için aşağıdaki adımları takip edebilirsiniz:

1. Repoyu klonlayın:
   ```bash
   git clone [https://github.com/sedaylrm/secu-log-lite.git](https://github.com/sedaylrm/secu-log-lite.git)
   cd secu-log-lite