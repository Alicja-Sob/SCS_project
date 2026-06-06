import threading
import time
import tkinter as tk
import crypto
import json
import socket
import base64
GLOBAL_CLIENT_ID = None
GLOBAL_SESSION_KEY = None

def simulate_auth():
    global GLOBAL_CLIENT_ID, GLOBAL_PRIVATE_KEY
    client_id = crypto.generate_random_id()
    GLOBAL_CLIENT_ID = client_id
    client_public_key, client_private_key = crypto.generate_RSA_key_pair()
    GLOBAL_PRIVATE_KEY = client_private_key
    GLOBAL_SESSION_KEY = None
    
    host = '127.0.0.1'
    port = 5000
    
    time.sleep(2)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            s.sendall(json.dumps({"type": "register"}).encode('utf-8'))
            data = s.recv(4096)

            if data:
                data = json.loads(data.decode('utf-8'))
                ttp_id = data["id"]
                ttp_public_key = crypto.deserialize_public_key(data["public_key"].encode('utf-8'))
          
                encrypted_client_id = crypto.encrypt_data(ttp_public_key, client_id.encode('utf-8'))
                encrypted_client_id_str = base64.b64encode(encrypted_client_id).decode('utf-8')
                client_public_key_str = crypto.serialize_public_key(client_public_key).decode('utf-8')
                
                payload = {
                    "type": "register",
                    "encrypted_server_id": encrypted_client_id_str,
                    "server_public_key": client_public_key_str,
                }
                s.sendall(json.dumps(payload).encode('utf-8'))
                
                cert_response = s.recv(4096)
                if cert_response:
                    status_label.config(text="Autoryzacja poprawna", fg="green")
                    service_btn.config(state=tk.NORMAL)
        
        except Exception as e:
            status_label.config(text=f"Błąd: {e}", fg="red")

def request_service():
    global GLOBAL_SESSION_KEY
    status_label.config(text="Usługa aktywna", fg="blue")
    server_host = '127.0.0.1'
    server_port = 7000
    ttp_port = 5000
    ttp_host = '127.0.0.1'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            payload = {
                "type": "service_request",
                "client_id": GLOBAL_CLIENT_ID
                }
            s.sendall(json.dumps(payload).encode('utf-8'))
            time.sleep(2)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ttp_s:
                ttp_s.connect((ttp_host, ttp_port))
                payload={
                    "type": "fetch_key",
                    "client_id": GLOBAL_CLIENT_ID
                }
                ttp_s.sendall(json.dumps(payload).encode('utf-8'))
                data = ttp_s.recv(4096)
                if data:
                    data = json.loads(data.decode('utf-8'))
                    if data.get("status") == "OK":
                        encrypted_session_key = base64.b64decode(data["encrypted_session_key"])
                        session_key = crypto.decrypt_data(GLOBAL_PRIVATE_KEY, encrypted_session_key)
                        GLOBAL_SESSION_KEY = session_key

                        status_label.config(text="klucz AES pobrany", fg="green")
                        msg_entry.config(state=tk.NORMAL)
                        send_btn.config(state=tk.NORMAL)
                        print (f"otrzymany klucz AES: {session_key.hex()}")
                    else:
                        status_label.config(text="Błąd pobierania klucza AES", fg="red")

    except Exception as e:
        status_label.config(text=f"Błąd: {e}", fg="red")
def send_message():
    message = msg_entry.get()
    if GLOBAL_SESSION_KEY:
            encrypted_message = crypto.encrypt_aes(GLOBAL_SESSION_KEY, message.encode('utf-8'))
            print(f"zaszyfrowana wiadomość: {encrypted_message.hex()}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', 7000))
                payload = {
                    "type": "secure_data",
                    "client_id": GLOBAL_CLIENT_ID,
                    "encrypted_data": base64.b64encode(encrypted_message).decode('utf-8')
                }
                s.sendall(json.dumps(payload).encode('utf-8'))
            status_label.config(text="Wiadomość wysłana", fg="green")
            msg_entry.delete(0, tk.END)
            
    else:
        status_label.config(text="Brak klucza AES", fg="red")


root = tk.Tk()
root.title("Klient")
root.geometry("500x350")

status_label = tk.Label(root, text="Brak uwierzytelnienia", fg="red")
status_label.pack(pady=10)

auth_btn = tk.Button(root, text="Zaloguj do TTP", command=simulate_auth)
auth_btn.pack(pady=5)

service_btn = tk.Button(root, text="Pobierz klucz AES", state=tk.DISABLED, command=request_service)
service_btn.pack()

tk.Label(root, text="Wiadomość do serwera:").pack(pady=10)
msg_entry = tk.Entry(root, width=50, state=tk.DISABLED)
msg_entry.pack(pady=5)

send_btn = tk.Button(root, text="Wyślij wiadomość", state=tk.DISABLED, command=send_message)
send_btn.pack(pady=5)

root.mainloop()