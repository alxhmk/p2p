import sys
import socket
import threading
import base64
from queue import Queue
from typing import Optional

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QRadioButton, QLineEdit, QPushButton, QLabel,
    QTextEdit, QStackedWidget, QMessageBox, QStatusBar
)
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot, QThread

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

DH_PARAMS_PEM = b'''
-----BEGIN DH PARAMETERS-----
MIIBiAKCAYEA7slflbrJJEa2bjMMN+ubBBKqfEtmyHx/qMv5d3NzZL+4YKXz8lOZ
kGXulkC1Fx//TatUI8MXA0K67CiS15vt6nwcIPc1whSZs1uywdrCcioMo3v2BmFE
dOhQ1Y2U1YTgp2fwCZTJ5Tp4ViN1Oagpg8AmJxCwJO7ODE9UqY1Fg5YKnWG/XSZM
l6ZifQSWAWEXT/f63RDpktjCnSHKKSh39U5MTHbh/SLCHMxgjl6+QNyjoTjSHw6N
czuDKSRk/xRWFvtHn3Vr599APGqA3xwpdOBNhCmRSe63jTdfPb5C0KzPcJw1is2y
kD5CamuO+YRPJkuAiv1AOH2tWe6e5R6bxakY4BiU/aO63F3RXxw1s6CppczD8SOc
KJLUnYedNtBqIpKh6hZPrHGzpzA4uxQo25ZXO/XL8XtVMKozQSu1UtJ2wpD97Vxz
i1xUChTj4ycL/ZgtlJqJxcYJ2gM0HMuAfNb/onatb6t9s1xRKV2eXhN8mhgQNARC
YGvDw9In76F3AgEC
-----END DH PARAMETERS-----
'''

try:
    DH_PARAMS = serialization.load_pem_parameters(DH_PARAMS_PEM)
except Exception as e:
    print(f"Ошибка загрузки параметров DH: {e}")
    sys.exit(1)

BUFFER_SIZE = 8192
DEFAULT_PORT = 5005

class ChatWorker(QObject):
    """Выполняет сетевое взаимодействие в фоновом потоке."""
    status_updated = pyqtSignal(str)
    message_received = pyqtSignal(str)
    connection_success = pyqtSignal()
    connection_closed = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.sock: Optional[socket.socket] = None
        self.cipher: Optional[Fernet] = None
        self.running = False
        self.mode: Optional[str] = None
        self.host: Optional[str] = None
        self.port: Optional[int] = None
        self.outgoing_queue = Queue()
        self.dh_params = DH_PARAMS

    @pyqtSlot(int)
    def start_host(self, port: int):
        self.mode = 'host'
        self.port = port
        self.host = None
        self.running = True

    @pyqtSlot(str, int)
    def start_client(self, host: str, port: int):
        self.mode = 'client'
        self.host = host
        self.port = port
        self.running = True

    @pyqtSlot(str)
    def send_message(self, text: str):
        self.outgoing_queue.put(text)

    @pyqtSlot()
    def stop(self):
        self.running = False

    def _generate_keypair(self):
        private_key = self.dh_params.generate_private_key()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_bytes

    def _derive_shared_secret(self, private_key, peer_public_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'p2p_chat_handshake_v1',
        ).derive(shared_secret)

    def _create_cipher(self, shared_secret: bytes) -> Fernet:
        key = base64.urlsafe_b64encode(shared_secret)
        return Fernet(key)

    def _setup_host(self) -> Optional[socket.socket]:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', self.port))
            server.listen(1)
            self.status_updated.emit(f"Ожидание подключения на порту {self.port}…")
            conn, addr = server.accept()
            self.status_updated.emit(f"Подключено: {addr[0]}:{addr[1]}")
            server.close()
            return conn
        except Exception as e:
            self.error_occurred.emit(f"Ошибка сервера: {e}")
            return None

    def _setup_client(self) -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            self.status_updated.emit(f"Подключено к {self.host}:{self.port}")
            return sock
        except Exception as e:
            self.error_occurred.emit(f"Ошибка подключения: {e}")
            return None

    def _perform_key_exchange(self, is_host: bool) -> bool:
        try:
            private_key, my_public_bytes = self._generate_keypair()

            if is_host:
                self.sock.send(my_public_bytes)
                peer_public_bytes = self.sock.recv(BUFFER_SIZE)
            else:
                peer_public_bytes = self.sock.recv(BUFFER_SIZE)
                self.sock.send(my_public_bytes)

            if not peer_public_bytes:
                self.error_occurred.emit("Обмен ключами не удался: нет данных")
                return False

            shared_secret = self._derive_shared_secret(private_key, peer_public_bytes)
            self.cipher = self._create_cipher(shared_secret)
            return True
        except Exception as e:
            self.error_occurred.emit(f"Ошибка обмена ключами: {e}")
            return False

    @pyqtSlot()
    def _run(self):
        if self.mode == 'host':
            self.sock = self._setup_host()
            is_host = True
        else:
            self.sock = self._setup_client()
            is_host = False

        if not self.sock:
            self.running = False
            return

        if not self._perform_key_exchange(is_host):
            self.sock.close()
            self.running = False
            return

        self.sock.settimeout(0.5)
        self.status_updated.emit("Защищённый канал установлен!")
        self.connection_success.emit()

        while self.running:
            try:
                data = self.sock.recv(BUFFER_SIZE)
                if data:
                    decrypted = self.cipher.decrypt(data).decode()
                    self.message_received.emit(decrypted)
                else:
                    break
            except socket.timeout:
                pass
            except Exception:
                break

            while not self.outgoing_queue.empty():
                if not self.running:
                    break
                try:
                    msg = self.outgoing_queue.get_nowait()
                    encrypted = self.cipher.encrypt(msg.encode())
                    self.sock.send(encrypted)
                except Exception:
                    self.running = False
                    break

        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.running = False
        self.connection_closed.emit()

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Защищённый P2P Чат")
        self.resize(500, 500)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.setup_page = QWidget()
        self.init_setup_page()
        self.stack.addWidget(self.setup_page)

        self.chat_page = QWidget()
        self.init_chat_page()
        self.stack.addWidget(self.chat_page)

        self.worker = ChatWorker()
        self.worker_thread = QThread()
        self.worker.moveToThread(self.worker_thread)

        self.worker.status_updated.connect(self.show_status)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.connection_success.connect(self.on_connection_success)
        self.worker.connection_closed.connect(self.on_connection_closed)
        self.worker.message_received.connect(self.display_peer_message)

        self.worker_thread.started.connect(self.worker._run)
        self.worker.destroyed.connect(self.worker_thread.quit)

        self.statusBar().showMessage("Готов")

    def init_setup_page(self):
        layout = QVBoxLayout()

        mode_group = QGroupBox("Режим подключения")
        mode_layout = QVBoxLayout()
        self.radio_host = QRadioButton("Ждать входящее подключение (хост)")
        self.radio_client = QRadioButton("Подключиться к хосту (клиент)")
        self.radio_host.setChecked(True)
        mode_layout.addWidget(self.radio_host)
        mode_layout.addWidget(self.radio_client)
        mode_group.setLayout(mode_layout)

        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP-адрес:"))
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_label = QLabel("IP-адрес:")
        ip_layout.addWidget(self.ip_input)

        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Порт:"))
        self.port_input = QLineEdit(str(DEFAULT_PORT))
        port_layout.addWidget(self.port_input)

        self.connect_btn = QPushButton("Подключиться")
        self.setup_status = QLabel("")

        layout.addWidget(mode_group)
        layout.addLayout(ip_layout)
        layout.addLayout(port_layout)
        layout.addWidget(self.connect_btn)
        layout.addWidget(self.setup_status)
        layout.addStretch()
        self.setup_page.setLayout(layout)

        self.radio_host.toggled.connect(self.on_mode_toggled)
        self.connect_btn.clicked.connect(self.on_connect)

        self.ip_input.setVisible(False)

    def init_chat_page(self):
        layout = QVBoxLayout()

        self.chat_log = QTextEdit()
        self.chat_log.setReadOnly(True)

        input_layout = QHBoxLayout()
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Введите сообщение…")
        self.send_btn = QPushButton("Отправить")
        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(self.send_btn)

        self.disconnect_btn = QPushButton("Отключиться")

        layout.addWidget(self.chat_log)
        layout.addLayout(input_layout)
        layout.addWidget(self.disconnect_btn)
        self.chat_page.setLayout(layout)

        self.send_btn.clicked.connect(self.send_message)
        self.msg_input.returnPressed.connect(self.send_message)
        self.disconnect_btn.clicked.connect(self.disconnect)

    @pyqtSlot()
    def on_mode_toggled(self):
        self.ip_input.setVisible(self.radio_client.isChecked())

    @pyqtSlot()
    def on_connect(self):
        try:
            port = int(self.port_input.text().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Введите корректный номер порта (1-65535).")
            return

        self.connect_btn.setEnabled(False)
        self.setup_status.setText("Подключение…")

        if self.radio_host.isChecked():
            self.worker.start_host(port)
        else:
            host = self.ip_input.text().strip()
            if not host:
                QMessageBox.warning(self, "Ошибка", "Введите IP-адрес хоста.")
                self.connect_btn.setEnabled(True)
                self.setup_status.setText("")
                return
            self.worker.start_client(host, port)

        # Запуск потока
        self.worker_thread.start()

    @pyqtSlot(str)
    def show_status(self, msg: str):
        self.setup_status.setText(msg)
        self.statusBar().showMessage(msg)

    @pyqtSlot(str)
    def on_error(self, msg: str):
        QMessageBox.critical(self, "Ошибка", msg)
        self.connect_btn.setEnabled(True)
        self.setup_status.setText("")
        self.worker_thread.quit()
        self.worker_thread.wait()
        self.reset_worker()

    @pyqtSlot()
    def on_connection_success(self):
        self.stack.setCurrentIndex(1)
        self.msg_input.setFocus()

    @pyqtSlot()
    def on_connection_closed(self):
        self.chat_log.append("⚠ Соединение закрыто.")
        self.stack.setCurrentIndex(0)
        self.connect_btn.setEnabled(True)
        self.setup_status.setText("Соединение разорвано")
        self.statusBar().showMessage("Отключено")
        self.worker_thread.quit()
        self.worker_thread.wait()
        self.reset_worker()

    @pyqtSlot(str)
    def display_peer_message(self, msg: str):
        self.chat_log.append(f"👤 Собеседник: {msg}")

    @pyqtSlot()
    def send_message(self):
        text = self.msg_input.text().strip()
        if not text:
            return
        self.chat_log.append(f"💬 Вы: {text}")
        self.worker.send_message(text)
        self.msg_input.clear()

    @pyqtSlot()
    def disconnect(self):
        self.worker.stop()
        self.worker_thread.quit()
        self.worker_thread.wait()
        self.chat_log.clear()
        self.stack.setCurrentIndex(0)
        self.connect_btn.setEnabled(True)
        self.setup_status.setText("Отключено")
        self.statusBar().showMessage("Отключено")
        self.reset_worker()

    def reset_worker(self):
        self.worker = ChatWorker()
        self.worker.moveToThread(self.worker_thread)
        self.worker.status_updated.connect(self.show_status)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.connection_success.connect(self.on_connection_success)
        self.worker.connection_closed.connect(self.on_connection_closed)
        self.worker.message_received.connect(self.display_peer_message)
        self.worker_thread.started.connect(self.worker._run)

    def closeEvent(self, event):
        self.worker.stop()
        self.worker_thread.quit()
        self.worker_thread.wait(2000)
        event.accept()

def main():
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()