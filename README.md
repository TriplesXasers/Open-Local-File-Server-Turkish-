#  Kurulum ve Çalıştırma Rehberi (Linux + Windows + macOS)

Bu rehber; Python’un güncel sürümünü kurmak, sanal ortam (venv) oluşturmak, gerekli paketleri yüklemek ve **main.py** dosyasını başlatmak için tüm adımları içerir.


#  Gerekli Python Paketleri

Aşağıdaki import’lar için ihtiyaç duyulan paketler:

- pyqt5  
- flask  
- werkzeug  
- rarfile  
- py7zr  
- psutil  

#  Linux (Ubuntu / Debian)

##  Python Kurulumu

sudo apt update
sudo apt install -y python3 python3-venv python3-pip

## venv Oluşturma

python3 -m venv venv

## venv Açma

source venv/bin/activate

## Paketleri Kurma

pip install pyqt5 flask werkzeug rarfile py7zr psutil

## Programı Başlatma

python main.py

# Windows (PowerShell)

winget install Python.Python.3

## venv Oluşturma

python -m venv venv

## venv Açma

.\venv\Scripts\activate

## Paketleri Kurma

pip install pyqt5 flask werkzeug rarfile py7zr psutil

## Programı Başlatma

python main.py

# macOS
## Python Kurulumu

brew install python

## venv Oluşturma

python3 -m venv venv

## venv Açma

source venv/bin/activate

## Paketleri Kurma

pip install pyqt5 flask werkzeug rarfile py7zr psutil

## Başlatma Sırası (Tüm Platformlar İçin)

source venv/bin/activate
python main.py
.\venv\Scripts\activate
python main.py
