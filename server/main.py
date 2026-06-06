import logging
import time
import socket
import crypto
import json
import base64
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Server_App") 

def main():

    logger.info("generowanie id oraz kluczy przez serwer")
    server_id = crypto.generate_random_id()
    server_public_key, server_private_key = crypto.generate_RSA_key_pair()
    logger.info(f"server id: {server_id}")
    GLOBAL_SERVER_ID = server_id

    logger.info("server działa")
    
    host = 'ttp'
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
                logger.info(f"otrzymano dane od ttp: {data}")

                encrypted_server_id = crypto.encrypt_data(ttp_public_key, server_id.encode('utf-8'))
                encrypted_server_id_str = base64.b64encode(encrypted_server_id).decode('utf-8')
                server_public_key_str = crypto.serialize_public_key(server_public_key).decode('utf-8')

                payload = {
                    "type": "register",
                    "encrypted_server_id": encrypted_server_id_str,
                    "server_public_key": server_public_key_str
                }
                s.sendall(json.dumps(payload).encode('utf-8'))
                logger.info(f"wysłano zaszyfrowany id serwera oraz klucz publiczny do ttp: {payload}")
                cert_response = s.recv(4096)
                if cert_response:
                    logger.info(f"otrzymano certyfikat od ttp: {cert_response.decode('utf-8')}")
                    
            # logger.info("server : connected")
            # payload = {
            #     "id": server_id,
            #     "public_key": crypto.serialize_public_key(server_public_key)
            # }
            # s.sendall(json.dumps(payload).encode('utf-8'))

        except Exception as e:
            logger.error(f"error: {e}")
    server_host='0.0.0.0'
    server_port = 7000
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server_host, server_port))
        s.listen()
        logger.info(f"serwer nasłuchuje na porcie {server_port}")
    
        try:
            while True:
                conn, addr = s.accept()
                with conn:
                    logger.info(f"połączono z klientem: {addr}")
                    data = conn.recv(4096)
                    if data:
                        data = json.loads(data.decode('utf-8'))
                        logger.info(f"otrzymano dane od klienta: {data}")
                        client_id = data.get("client_id")

                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ttp_s:
                            ttp_s.connect((host, port))
                            payload = {
                                "type": "session_request",
                                "server_id": GLOBAL_SERVER_ID,
                                "client_id": client_id
                            }

                            ttp_s.sendall(json.dumps(payload).encode('utf-8'))
                            logger.info(f"wysłano zapytanie o autoryzację klienta do ttp: {payload}")

                            ttp_response = ttp_s.recv(4096)
                            if ttp_response:
                                logger.info(f"otrzymano odpowiedź od ttp z kluczem sesyjnym: {ttp_response.decode('utf-8')}")
                                ttp_response_data = json.loads(ttp_response.decode('utf-8'))

        except KeyboardInterrupt:
            logger.info("shutdown")

if __name__ == "__main__":
    main()