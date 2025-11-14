import sys
import os
import socket
import webbrowser
import json
import hashlib
import zipfile
import rarfile
import py7zr
import shutil
import psutil
import subprocess
from threading import Thread
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QMessageBox, QSpinBox, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer, QCoreApplication
from PyQt5.QtGui import QFont
from flask import Flask, render_template, send_from_directory, request, redirect, url_for, flash, jsonify, session, Response
from werkzeug.utils import secure_filename
from functools import wraps
import mimetypes

# Flask uygulamaları - Ana sunucu ve Admin paneli
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Admin paneli kaldırıldı

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_FOLDER = os.path.join(BASE_DIR, 'Shared')
DATA_FOLDER = os.path.join(BASE_DIR, 'Veriler')
BACKUP_FOLDER = os.path.join(BASE_DIR, 'Yedekler')
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')

if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

# Konfigürasyon yönetimi
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {'last_port': 5000, 'autostart': False}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

# Kullanıcı ayarları yönetimi
def get_user_settings_file(username):
    return os.path.join(DATA_FOLDER, f'{username}_settings.json')

def load_user_settings(username):
    settings_file = get_user_settings_file(username)
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as f:
            settings = json.load(f)
            # Widget ayarları yoksa ekle
            if 'widgets' not in settings:
                settings['widgets'] = get_default_widgets()
            return settings
    return {'theme': 'light', 'widgets': get_default_widgets()}

def save_user_settings(username, settings):
    settings_file = get_user_settings_file(username)
    with open(settings_file, 'w') as f:
        json.dump(settings, f, indent=2)

def get_default_widgets():
    """Varsayılan widget ayarları"""
    return {
        'clock': {'enabled': False, 'x': 20, 'y': 20}
    }

def get_user_backup_folder(username):
    """Kullanıcının yedek klasörünü al"""
    backup_folder = os.path.join(BACKUP_FOLDER, username)
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)
    return backup_folder

def move_to_backup(username, file_path, relative_path):
    """Dosyayı yedek klasörüne taşı"""
    try:
        backup_folder = get_user_backup_folder(username)
        backup_path = os.path.join(backup_folder, os.path.basename(file_path))
        
        # Aynı isimde dosya varsa numara ekle
        counter = 1
        original_backup_path = backup_path
        while os.path.exists(backup_path):
            name, ext = os.path.splitext(original_backup_path)
            backup_path = f"{name}_{counter}{ext}"
            counter += 1
        
        if os.path.isfile(file_path):
            shutil.move(file_path, backup_path)
        elif os.path.isdir(file_path):
            shutil.move(file_path, backup_path)
        
        return True
    except Exception as e:
        print(f'Yedekleme hatası: {e}')
        return False

def get_backup_items(username):
    """Kullanıcının yedeklenmiş öğelerini listele"""
    backup_folder = get_user_backup_folder(username)
    items = []
    
    try:
        for item in os.listdir(backup_folder):
            item_path = os.path.join(backup_folder, item)
            is_dir = os.path.isdir(item_path)
            
            items.append({
                'name': item,
                'is_dir': is_dir,
                'size': get_file_size(os.path.getsize(item_path)) if not is_dir else '-',
                'path': item
            })
    except Exception as e:
        print(f'Yedek listeleme hatası: {e}')
    
    return items

# Admin kullanıcısını oluştur
def init_admin():
    users = load_users()
    if 'admin' not in users:
        users['admin'] = hash_password('admin1303')
        save_users(users)
    
    # Admin klasörünü Shared'den temizle
    cleanup_admin_folder()

# Kullanıcı yönetimi
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_folder(username):
    # Admin için Shared klasöründe klasör oluşturma
    if username == 'admin':
        return None
    
    user_folder = os.path.join(SHARED_FOLDER, username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    return user_folder

def cleanup_admin_folder():
    """Shared içindeki admin klasörünü sil"""
    admin_folder = os.path.join(SHARED_FOLDER, 'admin')
    if os.path.exists(admin_folder):
        try:
            shutil.rmtree(admin_folder)
            print('Admin klasörü Shared\'den silindi')
        except Exception as e:
            print(f'Admin klasörü silinirken hata: {e}')

# Global log callback
_server_log_callback = None

def set_log_callbacks(server_callback, _unused=None):
    global _server_log_callback
    _server_log_callback = server_callback

def log_to_gui(message, log_type='server'):
    """GUI'ye log gönder"""
    if _server_log_callback:
        _server_log_callback(message)

def get_user_stats():
    """Tüm kullanıcıların istatistiklerini al"""
    users = load_users()
    user_stats = []
    total_users = 0
    
    for username in users.keys():
        if username != 'admin':
            total_users += 1
            user_folder = get_user_folder(username)
            if user_folder and os.path.exists(user_folder):
                total_size = get_folder_size(user_folder)
                user_stats.append({
                    'username': username,
                    'size': total_size,
                    'size_str': get_file_size(total_size)
                })
    
    # Shared klasörü toplam boyutu
    shared_size = get_folder_size(SHARED_FOLDER)
    
    return {
        'total_users': total_users,
        'users': user_stats,
        'shared_size': shared_size,
        'shared_size_str': get_file_size(shared_size)
    }

def get_file_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

def get_folder_size(folder_path):
    """Klasörün toplam boyutunu hesapla"""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
    except Exception as e:
        print(f"Klasör boyutu hesaplama hatası: {e}")
    return total_size

def get_system_stats():
    """Sistem istatistiklerini al"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    shared_size = get_folder_size(SHARED_FOLDER)
    
    return {
        'cpu': cpu_percent,
        'ram': memory.percent,
        'ram_used': get_file_size(memory.used),
        'ram_total': get_file_size(memory.total),
        'shared_size': get_file_size(shared_size)
    }

def get_file_type(filename):
    """Dosya tipini belirle"""
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    image_exts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico']
    video_exts = ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v']
    audio_exts = ['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', 'wma']
    archive_exts = ['zip', 'rar', '7z']
    text_exts = ['txt', 'md', 'log', 'json', 'xml', 'csv', 'html', 'css', 'js', 'py']
    
    if ext in image_exts:
        return 'image'
    elif ext in video_exts:
        return 'video'
    elif ext in audio_exts:
        return 'audio'
    elif ext in archive_exts:
        return 'archive'
    elif ext in text_exts:
        return 'text'
    return 'other'

def get_files_and_folders(path, base_path):
    items = []
    try:
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            is_dir = os.path.isdir(item_path)
            
            item_info = {
                'name': item,
                'is_dir': is_dir,
                'size': get_file_size(os.path.getsize(item_path)) if not is_dir else '-',
                'path': os.path.relpath(item_path, base_path),
                'file_type': get_file_type(item) if not is_dir else 'folder'
            }
            items.append(item_info)
    except Exception as e:
        print(f"Hata: {e}")
    
    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
    return items

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        users = load_users()
        
        if username in users and users[username] == hash_password(password):
            session['username'] = username
            if username == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Kullanıcı adı veya şifre hatalı!')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password:
            return render_template('register.html', error='Kullanıcı adı ve şifre gerekli!')
        
        if password != confirm_password:
            return render_template('register.html', error='Şifreler eşleşmiyor!')
        
        users = load_users()
        
        if username in users:
            return render_template('register.html', error='Bu kullanıcı adı zaten kullanılıyor!')
        
        # Kullanıcı oluştur
        users[username] = hash_password(password)
        save_users(users)
        
        # Kullanıcı klasörü oluştur
        get_user_folder(username)
        
        session['username'] = username
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@app.route('/<path:subpath>')
@login_required
def index(subpath=''):
    username = session['username']
    
    # Admin normal dosya sistemine erişemez
    if username == 'admin':
        return redirect(url_for('admin_panel'))
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return 'Erişim reddedildi', 403
    
    current_path = os.path.join(user_folder, subpath)
    
    if not os.path.exists(current_path):
        flash('Klasör bulunamadı!', 'error')
        return redirect(url_for('index'))
    
    if os.path.isfile(current_path):
        return send_from_directory(os.path.dirname(current_path), os.path.basename(current_path), as_attachment=True)
    
    items = get_files_and_folders(current_path, user_folder)
    
    path_parts = []
    if subpath:
        parts = subpath.split('/')
        for i, part in enumerate(parts):
            path_parts.append({
                'name': part,
                'path': '/'.join(parts[:i+1])
            })
    
    settings = load_user_settings(username)
    
    return render_template('index.html', 
                         items=items, 
                         current_path=subpath,
                         path_parts=path_parts,
                         username=username,
                         settings=settings)

@app.route('/upload', methods=['POST'])
@app.route('/upload/<path:subpath>', methods=['POST'])
@login_required
def upload(subpath=''):
    username = session['username']
    client_ip = request.remote_addr
    
    # Admin dosya yükleyemez
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Admin dosya yükleyemez'}), 403
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Dosya seçilmedi'}), 400
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return jsonify({'success': False, 'message': 'Erişim reddedildi'}), 403
    
    files = request.files.getlist('file')
    current_path = os.path.join(user_folder, subpath)
    
    uploaded_count = 0
    for file in files:
        if file.filename == '':
            continue
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_path, filename)
        file.save(file_path)
        
        # Dosya bilgilerini logla
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(filename)[1]
        log_to_gui(f'📤 {client_ip} | {filename} | {file_ext} | {get_file_size(file_size)}', 'server')
        
        uploaded_count += 1
    
    return jsonify({'success': True, 'message': f'{uploaded_count} dosya yüklendi'})

@app.route('/delete/<path:filepath>', methods=['POST'])
@login_required
def delete(filepath):
    username = session['username']
    
    # Admin dosya silemez
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Admin dosya silemez'}), 403
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return jsonify({'success': False, 'message': 'Erişim reddedildi'}), 403
    
    file_path = os.path.join(user_folder, filepath)
    
    try:
        # Dosyayı yedekle
        if move_to_backup(username, file_path, filepath):
            return jsonify({'success': True, 'message': 'Öğe çöp kutusuna taşındı'})
        else:
            return jsonify({'success': False, 'message': 'Yedekleme başarısız'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/trash')
@login_required
def trash():
    username = session['username']
    
    if username == 'admin':
        return 'Erişim reddedildi', 403
    
    items = get_backup_items(username)
    settings = load_user_settings(username)
    
    return render_template('trash.html', items=items, username=username, settings=settings)

@app.route('/restore/<path:filename>', methods=['POST'])
@login_required
def restore(filename):
    username = session['username']
    
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Admin geri yükleyemez'}), 403
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return jsonify({'success': False, 'message': 'Erişim reddedildi'}), 403
    
    backup_folder = get_user_backup_folder(username)
    backup_path = os.path.join(backup_folder, filename)
    restore_path = os.path.join(user_folder, filename)
    
    try:
        if not os.path.exists(backup_path):
            return jsonify({'success': False, 'message': 'Yedek bulunamadı'}), 404
        
        # Aynı isimde dosya varsa numara ekle
        counter = 1
        original_restore_path = restore_path
        while os.path.exists(restore_path):
            name, ext = os.path.splitext(original_restore_path)
            restore_path = f"{name}_geri_{counter}{ext}"
            counter += 1
        
        shutil.move(backup_path, restore_path)
        
        return jsonify({'success': True, 'message': 'Öğe geri yüklendi'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/delete-permanent/<path:filename>', methods=['POST'])
@login_required
def delete_permanent(filename):
    username = session['username']
    
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Erişim reddedildi'}), 403
    
    backup_folder = get_user_backup_folder(username)
    backup_path = os.path.join(backup_folder, filename)
    
    try:
        if os.path.isfile(backup_path):
            os.remove(backup_path)
        elif os.path.isdir(backup_path):
            shutil.rmtree(backup_path)
        
        return jsonify({'success': True, 'message': 'Öğe kalıcı olarak silindi'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/create-folder', methods=['POST'])
@app.route('/create-folder/<path:subpath>', methods=['POST'])
@login_required
def create_folder(subpath=''):
    username = session['username']
    
    # Admin klasör oluşturamaz
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Admin klasör oluşturamaz'}), 403
    
    folder_name = request.form.get('folder_name')
    if not folder_name:
        return jsonify({'success': False, 'message': 'Klasör adı gerekli'}), 400
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return jsonify({'success': False, 'message': 'Erişim reddedildi'}), 403
    
    folder_name = secure_filename(folder_name)
    current_path = os.path.join(user_folder, subpath)
    new_folder = os.path.join(current_path, folder_name)
    
    try:
        os.makedirs(new_folder)
        return jsonify({'success': True, 'message': 'Klasör oluşturuldu'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/preview/<path:filepath>')
@login_required
def preview(filepath):
    username = session['username']
    
    # Admin dosya önizleyemez
    if username == 'admin':
        return 'Erişim reddedildi', 403
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return 'Erişim reddedildi', 403
    
    file_path = os.path.join(user_folder, filepath)
    
    if not os.path.exists(file_path):
        return 'Dosya bulunamadı', 404
    
    file_type = get_file_type(filepath)
    
    if file_type == 'text':
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return render_template('preview.html', content=content, filename=os.path.basename(filepath), file_type='text')
        except:
            return 'Dosya okunamadı', 400
    
    elif file_type in ['image', 'video', 'audio']:
        return render_template('preview.html', filepath=filepath, filename=os.path.basename(filepath), file_type=file_type)
    
    elif file_type == 'archive':
        return redirect(url_for('view_archive', filepath=filepath))
    
    return 'Önizleme desteklenmiyor', 400

@app.route('/view-archive/<path:filepath>')
@login_required
def view_archive(filepath):
    username = session['username']
    
    # Admin arşiv görüntüleyemez
    if username == 'admin':
        return 'Erişim reddedildi', 403
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return 'Erişim reddedildi', 403
    
    file_path = os.path.join(user_folder, filepath)
    
    if not os.path.exists(file_path):
        return 'Dosya bulunamadı', 404
    
    ext = filepath.lower().split('.')[-1]
    files = []
    
    try:
        if ext == 'zip':
            with zipfile.ZipFile(file_path, 'r') as zf:
                files = [{'name': f, 'size': get_file_size(zf.getinfo(f).file_size)} for f in zf.namelist()]
        elif ext == 'rar':
            with rarfile.RarFile(file_path, 'r') as rf:
                files = [{'name': f, 'size': get_file_size(rf.getinfo(f).file_size)} for f in rf.namelist()]
        elif ext == '7z':
            with py7zr.SevenZipFile(file_path, 'r') as szf:
                files = [{'name': f, 'size': '-'} for f in szf.getnames()]
    except Exception as e:
        return f'Arşiv okunamadı: {str(e)}', 400
    
    return render_template('archive.html', files=files, filename=os.path.basename(filepath), filepath=filepath)

@app.route('/extract-archive/<path:filepath>', methods=['POST'])
@login_required
def extract_archive(filepath):
    username = session['username']
    
    # Admin arşiv çıkaramaz
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Admin arşiv çıkaramaz'}), 403
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return jsonify({'success': False, 'message': 'Erişim reddedildi'}), 403
    
    file_path = os.path.join(user_folder, filepath)
    
    if not os.path.exists(file_path):
        return jsonify({'success': False, 'message': 'Dosya bulunamadı'}), 404
    
    ext = filepath.lower().split('.')[-1]
    folder_name = os.path.splitext(os.path.basename(filepath))[0]
    extract_path = os.path.join(os.path.dirname(file_path), folder_name)
    
    try:
        if ext == 'zip':
            with zipfile.ZipFile(file_path, 'r') as zf:
                zf.extractall(extract_path)
        elif ext == 'rar':
            with rarfile.RarFile(file_path, 'r') as rf:
                rf.extractall(extract_path)
        elif ext == '7z':
            with py7zr.SevenZipFile(file_path, 'r') as szf:
                szf.extractall(extract_path)
        
        return jsonify({'success': True, 'message': 'Arşiv çıkarıldı'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@app.route('/serve-file/<path:filepath>')
@login_required
def serve_file(filepath):
    username = session['username']
    
    # Admin dosya indiremez
    if username == 'admin':
        return 'Erişim reddedildi', 403
    
    user_folder = get_user_folder(username)
    if not user_folder:
        return 'Erişim reddedildi', 403
    
    file_path = os.path.join(user_folder, filepath)
    
    if not os.path.exists(file_path):
        return 'Dosya bulunamadı', 404
    
    return send_from_directory(os.path.dirname(file_path), os.path.basename(file_path))

# Admin paneli kaldırıldı

@app.route('/settings')
@login_required
def settings():
    username = session['username']
    user_settings = load_user_settings(username)
    is_admin = (username == 'admin')
    return render_template('settings.html', settings=user_settings, username=username, is_admin=is_admin)

@app.route('/update-settings', methods=['POST'])
@login_required
def update_settings():
    username = session['username']
    user_settings = load_user_settings(username)
    
    # JSON veya form data kontrolü
    data = request.get_json() if request.is_json else request.form
    
    # Tema değiştirme
    if 'theme' in data:
        user_settings['theme'] = data.get('theme')
    
    # Widget ayarları
    if 'widgets' in data:
        user_settings['widgets'] = data['widgets']
    
    save_user_settings(username, user_settings)
    return jsonify({'success': True, 'message': 'Ayarlar kaydedildi'})

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    username = session['username']
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    users = load_users()
    
    # Mevcut şifreyi kontrol et
    if users[username] != hash_password(current_password):
        return jsonify({'success': False, 'message': 'Mevcut şifre hatalı'}), 400
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'Yeni şifreler eşleşmiyor'}), 400
    
    if len(new_password) < 4:
        return jsonify({'success': False, 'message': 'Şifre en az 4 karakter olmalı'}), 400
    
    # Şifreyi güncelle
    users[username] = hash_password(new_password)
    save_users(users)
    
    return jsonify({'success': True, 'message': 'Şifre değiştirildi'})

@app.route('/change-username', methods=['POST'])
@login_required
def change_username():
    old_username = session['username']
    
    # Admin kullanıcı adını değiştiremez
    if old_username == 'admin':
        return jsonify({'success': False, 'message': 'Admin kullanıcı adı değiştirilemez'}), 400
    
    new_username = request.form.get('new_username', '').strip()
    
    if not new_username:
        return jsonify({'success': False, 'message': 'Kullanıcı adı boş olamaz'}), 400
    
    users = load_users()
    
    if new_username in users:
        return jsonify({'success': False, 'message': 'Bu kullanıcı adı zaten kullanılıyor'}), 400
    
    # Kullanıcı adını değiştir
    users[new_username] = users[old_username]
    del users[old_username]
    save_users(users)
    
    # Klasör adını değiştir
    old_folder = get_user_folder(old_username)
    new_folder = os.path.join(SHARED_FOLDER, new_username)
    if os.path.exists(old_folder):
        os.rename(old_folder, new_folder)
    
    # Ayarlar dosyasını değiştir
    old_settings = get_user_settings_file(old_username)
    new_settings = get_user_settings_file(new_username)
    if os.path.exists(old_settings):
        os.rename(old_settings, new_settings)
    
    # Session'ı güncelle
    session['username'] = new_username
    
    return jsonify({'success': True, 'message': 'Kullanıcı adı değiştirildi'})

@app.route('/admin-panel')
@login_required
def admin_panel():
    """Admin kontrol paneli"""
    if session['username'] != 'admin':
        return redirect(url_for('index'))
    
    system_stats = get_system_stats()
    user_stats = get_user_stats()
    config = load_config()
    
    return render_template('server_panel.html', 
                         system_stats=system_stats,
                         user_stats=user_stats,
                         config=config)

@app.route('/favicon.ico')
def favicon():
    """Favicon isteğini sessizce yoksay"""
    return '', 204


# GUI Sınıfı
class ServerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.server_thread = None
        self.is_running = False
        self.config = load_config()
        self.init_ui()
        
        # Sistem istatistikleri için timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(2000)  # Her 2 saniyede bir güncelle
        
        # Kullanıcı istatistikleri timer
        self.user_stats_timer = QTimer()
        self.user_stats_timer.timeout.connect(self.update_user_stats)
        self.user_stats_timer.start(10000)  # Her 10 saniyede bir güncelle
        
        # Admin klasörü temizleme timer
        self.cleanup_timer = QTimer()
        self.cleanup_timer.timeout.connect(cleanup_admin_folder)
        self.cleanup_timer.start(5000)  # Her 5 saniyede bir kontrol et
    
    def init_ui(self):
        self.setWindowTitle('📁 Dosya Paylaşım Sunucusu')
        self.setGeometry(100, 100, 700, 500)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Başlık
        title = QLabel('🌐 Web Dosya Paylaşım Sunucusu')
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet('color: #667eea; padding: 10px;')
        main_layout.addWidget(title)
        
        # Port ayarı
        port_layout = QHBoxLayout()
        port_label = QLabel('Port:')
        port_label.setStyleSheet('font-size: 14px; font-weight: bold;')
        self.port_input = QSpinBox()
        self.port_input.setRange(1024, 65535)
        self.port_input.setValue(self.config.get('last_port', 5000))
        self.port_input.valueChanged.connect(self.check_port_validity)
        self.port_input.setStyleSheet('''
            QSpinBox {
                padding: 8px;
                font-size: 14px;
                border: 2px solid #e9ecef;
                border-radius: 5px;
            }
            QSpinBox:focus {
                border-color: #667eea;
            }
        ''')
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        port_layout.addStretch()
        main_layout.addLayout(port_layout)
        
        # Otomatik başlatma
        self.autostart_checkbox = QCheckBox('Sistem ile Beraber Açıl')
        self.autostart_checkbox.setChecked(self.config.get('autostart', False))
        self.autostart_checkbox.setStyleSheet('font-size: 14px; padding: 5px;')
        self.autostart_checkbox.stateChanged.connect(self.toggle_autostart)
        main_layout.addWidget(self.autostart_checkbox)
        
        # Admin şifre değiştirme
        admin_password_layout = QVBoxLayout()
        admin_password_label = QLabel('🔐 Admin Şifresi:')
        admin_password_label.setStyleSheet('font-size: 14px; font-weight: bold; margin-top: 10px;')
        admin_password_layout.addWidget(admin_password_label)
        
        password_input_layout = QHBoxLayout()
        self.admin_password_input = QLineEdit()
        self.admin_password_input.setPlaceholderText('Yeni admin şifresi')
        self.admin_password_input.setEchoMode(QLineEdit.Password)
        self.admin_password_input.setStyleSheet('''
            QLineEdit {
                padding: 8px;
                font-size: 14px;
                border: 2px solid #e9ecef;
                border-radius: 5px;
            }
            QLineEdit:focus {
                border-color: #667eea;
            }
        ''')
        password_input_layout.addWidget(self.admin_password_input)
        
        self.change_admin_password_btn = QPushButton('Değiştir')
        self.change_admin_password_btn.setStyleSheet('''
            QPushButton {
                background: #667eea;
                color: white;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background: #5568d3;
            }
        ''')
        self.change_admin_password_btn.clicked.connect(self.change_admin_password)
        password_input_layout.addWidget(self.change_admin_password_btn)
        
        admin_password_layout.addLayout(password_input_layout)
        main_layout.addLayout(admin_password_layout)
        
        # Paylaşılan klasör bilgisi
        folder_info = QLabel(f'📁 Paylaşılan Klasör: {SHARED_FOLDER}')
        folder_info.setStyleSheet('''
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            color: #6c757d;
        ''')
        folder_info.setWordWrap(True)
        main_layout.addWidget(folder_info)
        
        # Sistem istatistikleri
        stats_layout = QHBoxLayout()
        
        self.cpu_label = QLabel('CPU: 0%')
        self.cpu_label.setStyleSheet('''
            background: #e8f4f8;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: bold;
        ''')
        stats_layout.addWidget(self.cpu_label)
        
        self.ram_label = QLabel('RAM: 0%')
        self.ram_label.setStyleSheet('''
            background: #e8f4f8;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: bold;
        ''')
        stats_layout.addWidget(self.ram_label)
        
        self.shared_label = QLabel('Shared: 0 B')
        self.shared_label.setStyleSheet('''
            background: #e8f4f8;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: bold;
        ''')
        stats_layout.addWidget(self.shared_label)
        
        main_layout.addLayout(stats_layout)
        
        # Butonlar
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton('🚀 Sunucuyu Başlat')
        self.start_btn.setStyleSheet('''
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
                color: white;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #5568d3, stop:1 #6a3f8f);
            }
            QPushButton:disabled {
                background: #cccccc;
            }
        ''')
        self.start_btn.clicked.connect(self.start_server)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton('⏹️ Sunucuyu Durdur')
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet('''
            QPushButton {
                background: #dc3545;
                color: white;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #c82333;
            }
            QPushButton:disabled {
                background: #cccccc;
            }
        ''')
        self.stop_btn.clicked.connect(self.stop_server)
        button_layout.addWidget(self.stop_btn)
        
        self.open_browser_btn = QPushButton('🌐 Tarayıcıda Aç')
        self.open_browser_btn.setEnabled(False)
        self.open_browser_btn.setStyleSheet('''
            QPushButton {
                background: #28a745;
                color: white;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #218838;
            }
            QPushButton:disabled {
                background: #cccccc;
            }
        ''')
        self.open_browser_btn.clicked.connect(self.open_browser)
        button_layout.addWidget(self.open_browser_btn)
        
        main_layout.addLayout(button_layout)
        
        # Sistem butonları
        system_button_layout = QHBoxLayout()
        
        self.shutdown_btn = QPushButton('🔴 Sistemi Kapat')
        self.shutdown_btn.setStyleSheet('''
            QPushButton {
                background: #6c757d;
                color: white;
                padding: 10px 20px;
                font-size: 13px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #5a6268;
            }
        ''')
        self.shutdown_btn.clicked.connect(self.shutdown_system)
        system_button_layout.addWidget(self.shutdown_btn)
        
        main_layout.addLayout(system_button_layout)
        
        # Kullanıcı İstatistikleri
        stats_label = QLabel('👥 Kullanıcı İstatistikleri:')
        stats_label.setStyleSheet('font-size: 14px; font-weight: bold; margin-top: 10px;')
        main_layout.addWidget(stats_label)
        
        self.user_stats_text = QTextEdit()
        self.user_stats_text.setReadOnly(True)
        self.user_stats_text.setStyleSheet('''
            QTextEdit {
                background: #e8f5e9;
                border: 2px solid #4caf50;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                max-height: 150px;
            }
        ''')
        main_layout.addWidget(self.user_stats_text)
        
        # Durum bilgisi - Sunucu Logu
        server_log_label = QLabel('📊 Sunucu Logu:')
        server_log_label.setStyleSheet('font-size: 14px; font-weight: bold; margin-top: 10px;')
        main_layout.addWidget(server_log_label)
        
        self.server_status_text = QTextEdit()
        self.server_status_text.setReadOnly(True)
        self.server_status_text.setStyleSheet('''
            QTextEdit {
                background: #f8f9fa;
                border: 2px solid #e9ecef;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
                max-height: 200px;
            }
        ''')
        main_layout.addWidget(self.server_status_text)
        
        self.server_log('Sunucu hazır. Başlatmak için butona tıklayın.')
    
    def server_log(self, message):
        """Sunucu loguna mesaj ekle"""
        try:
            if hasattr(self, 'server_status_text') and self.server_status_text:
                self.server_status_text.append(f'• {message}')
        except Exception as e:
            print(f'Server log hatası: {e}')
    
    def update_user_stats(self):
        """Kullanıcı istatistiklerini güncelle"""
        try:
            if not hasattr(self, 'user_stats_text') or not self.user_stats_text:
                return
            
            stats = get_user_stats()
            
            self.user_stats_text.clear()
            self.user_stats_text.append(f'📊 Toplam Kullanıcı: {stats["total_users"]}')
            self.user_stats_text.append(f'📁 Shared Klasör Boyutu: {stats["shared_size_str"]}')
            self.user_stats_text.append('─' * 40)
            
            if stats['users']:
                for user in stats['users']:
                    self.user_stats_text.append(f'👤 {user["username"]}: {user["size_str"]}')
            else:
                self.user_stats_text.append('Henüz kullanıcı yok')
                
        except Exception as e:
            print(f'Kullanıcı istatistikleri hatası: {e}')
    
    def update_stats(self):
        """Sistem istatistiklerini güncelle"""
        try:
            if not self.isVisible():
                return
            
            stats = get_system_stats()
            
            if hasattr(self, 'cpu_label') and self.cpu_label:
                self.cpu_label.setText(f'CPU: {stats["cpu"]:.1f}%')
            
            if hasattr(self, 'ram_label') and self.ram_label:
                self.ram_label.setText(f'RAM: {stats["ram"]:.1f}% ({stats["ram_used"]} / {stats["ram_total"]})')
            
            if hasattr(self, 'shared_label') and self.shared_label:
                self.shared_label.setText(f'Shared: {stats["shared_size"]}')
        except Exception as e:
            print(f'İstatistik güncelleme hatası: {e}')
    
    def toggle_autostart(self, state):
        """Otomatik başlatmayı aç/kapat"""
        enabled = state == Qt.Checked
        self.config['autostart'] = enabled
        save_config(self.config)
        
        autostart_path = os.path.expanduser('~/.config/autostart/file-server.desktop')
        autostart_dir = os.path.dirname(autostart_path)
        
        if enabled:
            # Autostart dosyası oluştur
            if not os.path.exists(autostart_dir):
                os.makedirs(autostart_dir)
            
            desktop_content = f"""[Desktop Entry]
Type=Application
Name=File Server
Exec=python3 {os.path.abspath(__file__)}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
            with open(autostart_path, 'w') as f:
                f.write(desktop_content)
            
            self.server_log('✅ Otomatik başlatma etkinleştirildi')
        else:
            # Autostart dosyasını sil
            if os.path.exists(autostart_path):
                os.remove(autostart_path)
            self.server_log('❌ Otomatik başlatma devre dışı bırakıldı')
    
    def shutdown_system(self):
        """Bilgisayarı kapat"""
        reply = QMessageBox.question(self, 'Sistemi Kapat', 
            'Bilgisayarı kapatmak istediğinizden emin misiniz?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.server_log('🔴 Sistem kapatılıyor...')
            try:
                if sys.platform == 'linux':
                    subprocess.run(['shutdown', '-h', 'now'])
                elif sys.platform == 'win32':
                    subprocess.run(['shutdown', '/s', '/t', '0'])
                elif sys.platform == 'darwin':
                    subprocess.run(['sudo', 'shutdown', '-h', 'now'])
            except Exception as e:
                QMessageBox.critical(self, 'Hata', f'Sistem kapatılamadı: {str(e)}')
    
    def change_admin_password(self):
        """Admin şifresini değiştir"""
        new_password = self.admin_password_input.text().strip()
        
        if not new_password:
            QMessageBox.warning(self, 'Uyarı', 'Lütfen yeni şifre girin!')
            return
        
        if len(new_password) < 4:
            QMessageBox.warning(self, 'Uyarı', 'Şifre en az 4 karakter olmalı!')
            return
        
        reply = QMessageBox.question(self, 'Şifre Değiştir', 
            f'Admin şifresini değiştirmek istediğinizden emin misiniz?\n\nYeni şifre: {new_password}',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                users = load_users()
                users['admin'] = hash_password(new_password)
                save_users(users)
                
                self.admin_password_input.clear()
                self.server_log(f'✅ Admin şifresi değiştirildi: {new_password}')
                QMessageBox.information(self, 'Başarılı', 
                    f'Admin şifresi başarıyla değiştirildi!\n\nYeni şifre: {new_password}')
            except Exception as e:
                self.server_log(f'❌ Şifre değiştirme hatası: {str(e)}')
                QMessageBox.critical(self, 'Hata', f'Şifre değiştirilemedi: {str(e)}')
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def check_port_validity(self, port):
        """Port kontrolü - artık gerek yok"""
        pass
    
    def start_server(self):
        port = self.port_input.value()
        
        # Port'u kaydet
        self.config['last_port'] = port
        save_config(self.config)
        
        self.server_log(f'Sunucu başlatılıyor... Port: {port}')
        
        def run_server():
            try:
                app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
            except Exception as e:
                self.server_log(f'❌ Hata: {str(e)}')
        

        
        # Log callback'lerini ayarla
        set_log_callbacks(self.server_log, self.server_log)
        
        self.server_thread = Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        self.is_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.open_browser_btn.setEnabled(True)
        self.port_input.setEnabled(False)
        
        local_ip = self.get_local_ip()
        
        self.server_log(f'✅ Sunucu başlatıldı!')
        self.server_log(f'🌐 Yerel erişim: http://localhost:{port}')
        self.server_log(f'🌐 Ağ erişimi: http://{local_ip}:{port}')
        self.server_log(f'📁 Paylaşılan klasör: {SHARED_FOLDER}')
        self.server_log('─' * 50)
        
        # Kullanıcı istatistiklerini göster
        self.update_user_stats()
    
    def stop_server(self):
        self.server_log('⏹️ Sunucu durduruluyor...')
        self.server_log('Not: Flask sunucusu durduruldu. Yeniden başlatmak için uygulamayı kapatıp açın.')
        
        self.is_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.open_browser_btn.setEnabled(False)
        self.port_input.setEnabled(True)
        
        QMessageBox.information(self, 'Bilgi', 
            'Sunucular durduruldu.\nYeniden başlatmak için uygulamayı kapatıp açın.')
    
    def open_browser(self):
        port = self.port_input.value()
        url = f'http://localhost:{port}'
        webbrowser.open(url)
        self.server_log(f'🌐 Tarayıcı açıldı: {url}')
    
    def closeEvent(self, event):
        try:
            # Timer'ları durdur
            if hasattr(self, 'stats_timer') and self.stats_timer:
                self.stats_timer.stop()
            
            if hasattr(self, 'cleanup_timer') and self.cleanup_timer:
                self.cleanup_timer.stop()
            
            if hasattr(self, 'user_stats_timer') and self.user_stats_timer:
                self.user_stats_timer.stop()
            
            if self.is_running:
                reply = QMessageBox.question(self, 'Çıkış', 
                    'Sunucu çalışıyor. Çıkmak istediğinizden emin misiniz?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                
                if reply == QMessageBox.Yes:
                    event.accept()
                else:
                    event.ignore()
            else:
                event.accept()
        except Exception as e:
            print(f'Kapatma hatası: {e}')
            event.accept()


if __name__ == '__main__':
    try:
        init_admin()  # Admin kullanıcısını oluştur
        
        # QApplication ayarları - QApplication oluşturmadan önce
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        
        app_qt = QApplication(sys.argv)
        
        window = ServerGUI()
        window.show()
        sys.exit(app_qt.exec_())
    except Exception as e:
        print(f'Kritik hata: {e}')
        import traceback
        traceback.print_exc()
