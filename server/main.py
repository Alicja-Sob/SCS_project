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


    logger.info("server działa")
    
    host = 'ttp'
    port = 5000
    
    time.sleep(2)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
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
            
    try:
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        logger.info("shutdown")

if __name__ == "__main__":
    main()