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
        
        while True:
            conn, addr = s.accept()
            payload = {
                "id": ttp_id,
                "public_key": crypto.serialize_public_key(ttp_public_key).decode('utf-8')
            }
            
            with conn:
            
                logger.info(f"polaczono : {addr}")
                conn.sendall(json.dumps(payload).encode('utf-8'))

                data = conn.recv(4096)
                if data: 
                    data = json.loads(data.decode('utf-8'))
                    encrypted_server_id = base64.b64decode(data["encrypted_server_id"])
                    server_public_key = crypto.deserialize_public_key(data["server_public_key"].encode('utf-8'))
                    server_id = crypto.decrypt_data(ttp_private_key, encrypted_server_id).decode('utf-8')
                    logger.info(f"serwer id: {server_id}")

                    server_cert = crypto.generate_certificate(server_id, server_public_key, ttp_id, ttp_private_key)

                    serialized_cert = crypto.serialize_certificate(server_cert).decode('utf-8')
                    conn.sendall(serialized_cert.encode('utf-8'))
                    logger.info(f"wysłano certyfikat do serwera: {serialized_cert}")

                # data = conn.recv(1024)
                # if data:
                #     logger.info(f"wiadomosc : {data.decode('utf-8')}")
                #     conn.sendall(b"ping od ttp dla serwera ")

if __name__ == "__main__":
    main()