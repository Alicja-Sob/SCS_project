import json
import logging
import socket
import crypto 
import base64
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("TTP_App") 

def main():
    logger.info("generowanie certyfikatu przez ttp")
    ttp_id = crypto.generate_random_id()
    
    logger.info(f"ttp id: {ttp_id}")

    ttp_public_key, ttp_private_key = crypto.generate_RSA_key_pair()
    ttp_cert = crypto.generate_certificate(ttp_id, ttp_public_key, ttp_id, ttp_private_key)
    
    logger.info(f"certyfikat ttp wygenerowany: {ttp_cert}")

    logger.info("ttp dziala")
    
    host = '0.0.0.0'
    port = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        logger.info(f" naslucjiwanie na :{port}")
        
        registered_servers = {}
        pending_client_keys = {}
        while True:
            conn, addr = s.accept()
           
            
            with conn:
            
                logger.info(f"polaczono : {addr}")
                
                data = conn.recv(4096)
                request = json.loads(data.decode('utf-8'))
                request_type = request.get("type")
                if request_type == "register":
                    logger.info(f"otrzymano prosbe rejestracji: {request}")
                    payload = {
                        "id": ttp_id,
                        "public_key": crypto.serialize_public_key(ttp_public_key).decode('utf-8')
                    }
                    conn.sendall(json.dumps(payload).encode('utf-8'))
                    registration_data = conn.recv(4096)

                    data = json.loads(registration_data.decode('utf-8'))
                    encrypted_server_id = base64.b64decode(data["encrypted_server_id"])
                    server_public_key = crypto.deserialize_public_key(data["server_public_key"].encode('utf-8'))
                    server_id = crypto.decrypt_data(ttp_private_key, encrypted_server_id).decode('utf-8')
                    logger.info(f"serwer/klient id: {server_id}")

                    registered_servers[server_id] = {
                        "public_key": server_public_key,
                        "callback_port": data.get("callback_port"),
                        "address": addr[0]
                    }

                    server_cert = crypto.generate_certificate(server_id, server_public_key, ttp_id, ttp_private_key)

                    serialized_cert = crypto.serialize_certificate(server_cert).decode('utf-8')
                    conn.sendall(serialized_cert.encode('utf-8'))
                    logger.info(f"wysłano certyfikat do serwera: {serialized_cert}")


                elif request_type == "session_request":
                    logger.info(f"prosba o autoryzacje: {request}")
                    client_id = request.get("client_id")
                    server_id = request.get("server_id")

                    if server_id in registered_servers and client_id in registered_servers:
                        server_info = registered_servers[server_id]
                        client_info = registered_servers[client_id]

                        session_key = crypto.generate_aes_key()
                        logger.info(f"wygenerowano 256 bitowy klucz AES")

                        encrypted_session_key_for_server = crypto.encrypt_data(server_info["public_key"], session_key)
                        encrypted_session_key_for_client = crypto.encrypt_data(client_info["public_key"], session_key)

                        response_to_server = {
                            "status": "OK",
                            "encrypted_session_key": base64.b64encode(encrypted_session_key_for_server).decode('utf-8'),
                        }
                        conn.sendall(json.dumps(response_to_server).encode('utf-8'))
                        logger.info(f"wysłano zaszyfrowany klucz sesji do serwera")

                        pending_client_keys[client_id] = base64.b64encode(encrypted_session_key_for_client).decode('utf-8')                        
                        logger.info(f"zapisano zaszyfrowany klucz sesji dla klienta {client_id} w oczekujących kluczach")       

                    else:
                        logger.warning(f"nieznany server_id lub client_id: {server_id}, {client_id}")

                elif request_type == "fetch_key":
                    client_id = request.get("client_id")
                    if client_id in pending_client_keys:
                        encrypted_session_key_for_client = pending_client_keys.pop(client_id)
                        response = {
                            "status": "OK",
                            "encrypted_session_key": encrypted_session_key_for_client
                        }
                        conn.sendall(json.dumps(response).encode('utf-8'))
                        logger.info(f"wysłano zaszyfrowany klucz sesji do klienta {client_id}")
                        
                    else:
                        response = {
                            "status": "ERROR",
                            "message": "Brak klucza sesji dla tego klienta"
                        }
                        conn.sendall(json.dumps(response).encode('utf-8'))
                        logger.warning(f"nie znaleziono klucza sesji dla klienta {client_id}")
                else:
                    logger.warning(f"nieznany typ żądania: {request_type}")
                # data = conn.recv(1024)
                # if data:
                #     logger.info(f"wiadomosc : {data.decode('utf-8')}")
                #     conn.sendall(b"ping od ttp dla serwera ")

if __name__ == "__main__":
    main()