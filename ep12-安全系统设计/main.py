import sys
import sqlite3
import base64
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QLabel, QDialog, QMessageBox)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import pyotp
from datetime import datetime

# 初始化数据库
def init_db():
    conn = sqlite3.connect("secure_mis.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        totp_secret TEXT
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS sensitive_data (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        encrypted_data TEXT,
        session_key TEXT,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()

# 密码哈希和验证
def hash_password(password):
    salt = os.urandom(16)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt + password.encode())
    password_hash = digest.finalize()
    return base64.b64encode(salt + password_hash).decode()

def verify_password(stored_hash, password):
    stored_hash = base64.b64decode(stored_hash)
    salt = stored_hash[:16]
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt + password.encode())
    return stored_hash[16:] == digest.finalize()

# 数据加密/解密
def encrypt_data(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    data_bytes = plaintext.encode('utf-8')
    padding_length = 16 - (len(data_bytes) % 16)
    padded_data = data_bytes + (padding_length * chr(padding_length)).encode('utf-8')
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_data(ciphertext, key):
    try:
        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        padding_length = padded_data[-1]
        return padded_data[:-padding_length].decode('utf-8')
    except Exception as e:
        print(f"解密失败: {e}")
        return ""

# 生成RSA密钥对
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, public_key, public_pem

# TOTP相关函数
def get_totp_code(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

# 会话密钥
def generate_session_key():
    return os.urandom(32)

# 登录对话框
class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("登录/注册")
        self.resize(400, 300)
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
                border-radius: 10px;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton {
                padding: 10px;
                border: none;
                border-radius: 5px;
                background-color: #4CAF50;
                color: white;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QLabel {
                font-size: 12px;
                color: #333;
            }
        """)
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # 标题
        title = QLabel("安全信息系统", self)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("用户名")
        self.username_input.textChanged.connect(self.check_user_exists)
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("密码")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.totp_input = QLineEdit(self)
        self.totp_input.setPlaceholderText("TOTP验证码")
        layout.addWidget(self.totp_input)

        self.totp_secret = "T5R5J5LYKRHHWYXGXLXDOMVJ7FM25AU7"
        self.totp_label = QLabel(f"TOTP密钥: {self.totp_secret}")
        layout.addWidget(self.totp_label)

        self.totp_code_label = QLabel("当前TOTP验证码: 计算中...")
        layout.addWidget(self.totp_code_label)

        self.status_label = QLabel("请输入用户名以检查状态")
        layout.addWidget(self.status_label)

        button_layout = QHBoxLayout()
        self.login_button = QPushButton("登录", self)
        self.login_button.clicked.connect(self.login)
        button_layout.addWidget(self.login_button)

        self.register_button = QPushButton("注册", self)
        self.register_button.clicked.connect(self.register)
        button_layout.addWidget(self.register_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        self.user_id = None
        self.private_key = None
        self.public_key = None

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_totp_code)
        self.timer.start(1000)

    def update_totp_code(self):
        current_code = get_totp_code(self.totp_secret)
        self.totp_code_label.setText(f"当前TOTP验证码 (30秒内有效): {current_code}")

    def check_user_exists(self):
        username = self.username_input.text()
        with sqlite3.connect("secure_mis.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            self.status_label.setText(f"用户 {username} 已存在，请登录" if result else f"用户 {username} 未注册，请注册")

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        totp_code = self.totp_input.text()

        if not all([username, password, totp_code]):
            QMessageBox.warning(self, "错误", "请填写所有字段！")
            return

        with sqlite3.connect("secure_mis.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                QMessageBox.warning(self, "错误", "用户名已存在！")
                return

            password_hash = hash_password(password)
            private_key, public_key, public_pem = generate_key_pair()
            totp_secret = self.totp_secret

            if not pyotp.TOTP(totp_secret).verify(totp_code):
                QMessageBox.warning(self, "错误", "TOTP验证码错误！")
                return

            cursor.execute("INSERT INTO users (username, password_hash, public_key, totp_secret) VALUES (?, ?, ?, ?)",
                           (username, password_hash, public_pem, totp_secret))
            conn.commit()
            self.user_id = cursor.lastrowid
            self.private_key = private_key
            self.public_key = public_key
            QMessageBox.information(self, "成功", f"用户 {username} 注册成功！")
            self.accept()

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        totp_code = self.totp_input.text()

        if not all([username, password, totp_code]):
            QMessageBox.warning(self, "错误", "请填写所有字段！")
            return

        with sqlite3.connect("secure_mis.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, totp_secret, public_key FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if not result:
                QMessageBox.warning(self, "错误", "用户不存在，请先注册！")
                return

            self.user_id, stored_hash, totp_secret, public_pem = result
            if verify_password(stored_hash, password) and pyotp.TOTP(totp_secret).verify(totp_code):
                self.public_key = serialization.load_pem_public_key(public_pem.encode())
                self.private_key, _, _ = generate_key_pair()
                QMessageBox.information(self, "成功", "登录成功！")
                self.accept()
            else:
                QMessageBox.warning(self, "错误", "密码或TOTP验证码错误！")

# 主窗口
class MainWindow(QMainWindow):
    def __init__(self, user_id, private_key, public_key):
        super().__init__()
        self.setWindowTitle("安全信息管理系统")
        self.resize(700, 500)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ffffff;
            }
            QLineEdit {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 14px;
                background-color: #f9f9f9;
            }
            QPushButton {
                padding: 10px;
                border: none;
                border-radius: 5px;
                background-color: #2196F3;
                color: white;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QTableWidget {
                border: 1px solid #ddd;
                border-radius: 5px;
                background-color: #fff;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:hover {
                background-color: #e0f7fa;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                padding: 5px;
                border: 1px solid #ddd;
                font-size: 14px;
            }
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #333;
            }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)

        # 标题
        title = QLabel("数据管理", self)
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # 输入和按钮区域
        input_layout = QHBoxLayout()
        self.data_input = QLineEdit(self)
        self.data_input.setPlaceholderText("输入数据")
        input_layout.addWidget(self.data_input)

        self.add_button = QPushButton("添加", self)
        self.add_button.clicked.connect(self.add_data)
        input_layout.addWidget(self.add_button)

        self.update_button = QPushButton("修改", self)
        self.update_button.clicked.connect(self.update_data)
        input_layout.addWidget(self.update_button)

        self.delete_button = QPushButton("删除", self)
        self.delete_button.clicked.connect(self.delete_data)
        input_layout.addWidget(self.delete_button)

        self.logout_button = QPushButton("退出登录", self)
        self.logout_button.clicked.connect(self.logout)
        input_layout.addWidget(self.logout_button)

        layout.addLayout(input_layout)

        # 数据表格
        self.table = QTableWidget(self)
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["添加时间", "数据"])
        self.table.cellClicked.connect(self.select_row)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        self.user_id = user_id
        self.private_key = private_key
        self.public_key = public_key
        self.load_data()

    def load_data(self):
        try:
            with sqlite3.connect("secure_mis.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, encrypted_data, session_key, created_at FROM sensitive_data WHERE user_id = ?", (self.user_id,))
                rows = cursor.fetchall()
                self.table.setRowCount(len(rows))
                for row_idx, (data_id, encrypted_data, session_key, created_at) in enumerate(rows):
                    decrypted_data = decrypt_data(encrypted_data, base64.b64decode(session_key))
                    self.table.setItem(row_idx, 0, QTableWidgetItem(created_at))
                    self.table.setItem(row_idx, 1, QTableWidgetItem(decrypted_data))
                    item = self.table.item(row_idx, 0)
                    if item:
                        item.setData(Qt.UserRole, data_id)
        except Exception as e:
            QMessageBox.warning(self, "错误", f"加载数据失败: {e}")

    def add_data(self):
        data = self.data_input.text()
        if not data:
            QMessageBox.warning(self, "错误", "请输入数据！")
            return

        try:
            session_key = generate_session_key()
            encrypted_data = encrypt_data(data, session_key)
            session_key_str = base64.b64encode(session_key).decode()
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with sqlite3.connect("secure_mis.db") as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO sensitive_data (user_id, encrypted_data, session_key, created_at) VALUES (?, ?, ?, ?)",
                               (self.user_id, encrypted_data, session_key_str, created_at))
                conn.commit()
            self.load_data()
            self.data_input.clear()
        except Exception as e:
            QMessageBox.warning(self, "错误", f"添加数据失败: {e}")

    def update_data(self):
        selected = self.table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "错误", "请先选择一行！")
            return

        data_id = self.table.item(selected, 0).data(Qt.UserRole)
        new_data = self.data_input.text()
        if not new_data:
            QMessageBox.warning(self, "错误", "请输入新数据！")
            return

        try:
            session_key = generate_session_key()
            encrypted_data = encrypt_data(new_data, session_key)
            session_key_str = base64.b64encode(session_key).decode()

            with sqlite3.connect("secure_mis.db") as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE sensitive_data SET encrypted_data = ?, session_key = ? WHERE id = ?",
                               (encrypted_data, session_key_str, data_id))
                conn.commit()
            self.load_data()
        except Exception as e:
            QMessageBox.warning(self, "错误", f"修改数据失败: {e}")

    def delete_data(self):
        selected = self.table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "错误", "请先选择一行！")
            return

        data_id = self.table.item(selected, 0).data(Qt.UserRole)
        try:
            with sqlite3.connect("secure_mis.db") as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM sensitive_data WHERE id = ?", (data_id,))
                conn.commit()
            self.load_data()
        except Exception as e:
            QMessageBox.warning(self, "错误", f"删除数据失败: {e}")

    def select_row(self, row, col):
        self.data_input.setText(self.table.item(row, 1).text())

    def logout(self):
        self.close()
        login_dialog = LoginDialog()
        if login_dialog.exec_() == QDialog.Accepted:
            new_main_window = MainWindow(login_dialog.user_id, login_dialog.private_key, login_dialog.public_key)
            new_main_window.show()
            self.new_window = new_main_window

# 主程序
if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    login_dialog = LoginDialog()
    if login_dialog.exec_() == QDialog.Accepted:
        main_window = MainWindow(login_dialog.user_id, login_dialog.private_key, login_dialog.public_key)
        main_window.show()
        sys.exit(app.exec_())