import time
import tkinter as tk
import crypto
import json
import socket
import base64
GLOBAL_CLIENT_ID = None
GLOBAL_SESSION_KEY = None
GLOBAL_CERTIFICATE = None

## @defgroup group2-user User app
## @ingroup group2_mains
## Files, methods, etc used to run the user application and facilitate its GUI

## @ingroup group2-user
## @file user/gui.py
## @brief Methods facilitating the app's GUI and running the client application

## @ingroup group2-user
## @brief Simulates client authentication with a Trusted Third Party (TTP)
## @details Generates a client ID and RSA keys and performs a registration handshake with a trusted third party (TTP) over a TCP socket
## The client ID is encrypted with a TTP public key and sent along with the clients public key.
##
## If successfull service access is enabled in the GUI
## @exception socket.error - network communication failure
## @exception json.JSONDecodeError - invalid JSON response from TTP
def simulate_auth():
    global GLOBAL_CLIENT_ID, GLOBAL_PRIVATE_KEY, GLOBAL_CERTIFICATE
    client_id = crypto.generate_random_id()
    GLOBAL_CLIENT_ID = client_id
    client_public_key, client_private_key = crypto.generate_RSA_key_pair()
    GLOBAL_PRIVATE_KEY = client_private_key
    
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
                    GLOBAL_CERTIFICATE = cert_response.decode('utf-8')
                    status_label.config(text="Authorization correct", fg="green")
                    service_btn.config(state=tk.NORMAL)
                    forge_btn.config(state=tk.NORMAL)
        
        except Exception as e:
            status_label.config(text=f"Error: {e}", fg="red")


## @ingroup group2-user
## @brief Requests a session key from the TTP and service access from server
## @details Sends a service request to the main server, then contacts the TTP to retrieve an encrypted AES session key.
## The key is decrypted using the client's private RSA key and stored globally for later encrypted communication.
## @exception socket.error - network communication failure
## @exception json.JSONDecodeError - invalid JSON response
def request_service():
    global GLOBAL_SESSION_KEY
    status_label.config(text="Service active", fg="blue")
    server_host = '127.0.0.1'
    server_port = 7000
    ttp_port = 5000
    ttp_host = '127.0.0.1'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            payload = {
                "type": "service_request",
                "client_id": GLOBAL_CLIENT_ID,
                "certificate": GLOBAL_CERTIFICATE
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

                        status_label.config(text="AES key obtained", fg="green")
                        msg_entry.config(state=tk.NORMAL)
                        send_btn.config(state=tk.NORMAL)
                        print (f"Received AES key: {session_key.hex()}")
                    else:
                        status_label.config(text="Error while obtaining the AES key", fg="red")

    except Exception as e:
        status_label.config(text=f"Error: {e}", fg="red")


## @ingroup group2-user
## @brief Sends an encrypted message to the server
## @details Encrypts a user-provided message using a AES session key and sends it securely to the server via TCP.
## @exception AttributeError - Raised if GUI elements or session key are not initialized
## @exception socket.error - Network communication failure
def send_message():
    message = msg_entry.get()
    if GLOBAL_SESSION_KEY:
            encrypted_message = crypto.encrypt_aes(GLOBAL_SESSION_KEY, message.encode('utf-8'))
            print(f"Encrypted message: {encrypted_message.hex()}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', 7000))
                payload = {
                    "type": "secure_data",
                    "client_id": GLOBAL_CLIENT_ID,
                    "encrypted_data": base64.b64encode(encrypted_message).decode('utf-8')
                }
                s.sendall(json.dumps(payload).encode('utf-8'))
            status_label.config(text="Message sent", fg="green")
            msg_entry.delete(0, tk.END)
            
    else:
        status_label.config(text="No AES key", fg="red")


## @ingroup group2-user
## @brief Sends a deliberately forged certificate to the server
## @details Creates an invalid version of the client's certificate by modifying its contents and sends it to the server.
## This function is intended for testing the server's certificate handling mechanisms
## @exception socket.error - network communication failure
def test_forged_certificate():
    if not GLOBAL_CERTIFICATE:
        return

    forged_cert = GLOBAL_CERTIFICATE.replace('a', 'b', 1)

    server_host, server_port = '127.0.0.1', 7000
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_host, server_port))
            payload = {
                "type": "service_request",
                "client_id": GLOBAL_CLIENT_ID,
                "certificate": forged_cert
            }
            s.sendall(json.dumps(payload).encode('utf-8'))

        status_label.config(text="Sent Forged Certificate", fg="orange")
    except Exception as e:
        print(e)


## @ingroup group2-user
## @brief Initializes and runs the client GUI application
## @details Creates a Tkinter-based GUI that allows the user to:
## - Authenticate with a Trusted Third Party (TTP) ("Log in with TTP")
## - Request a secure AES session key ("Download AES key")
## - Input and send encrypted messages to a server ("Send message")
## The GUI remains active via the Tk main event loop.
root = tk.Tk()
root.title("Client")
root.geometry("500x350")

status_label = tk.Label(root, text="No authorization", fg="red")
status_label.pack(pady=10)

auth_btn = tk.Button(root, text="Log in with TTP", command=simulate_auth)
auth_btn.pack(pady=5)

service_btn = tk.Button(root, text="Download AES key", state=tk.DISABLED, command=request_service)
service_btn.pack()

tk.Label(root, text="Message for the server:").pack(pady=10)
msg_entry = tk.Entry(root, width=50, state=tk.DISABLED)
msg_entry.pack(pady=5)

send_btn = tk.Button(root, text="Send message", state=tk.DISABLED, command=send_message)
send_btn.pack(pady=5)

forge_btn = tk.Button(root, text="Send Forged Certificate", state=tk.DISABLED, command=test_forged_certificate)
forge_btn.pack(pady=5)

root.mainloop()