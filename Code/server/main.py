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


## @defgroup group2_mains Running the Applications
## Main methods running each of the specific applications (TTP, user and server)

## @defgroup group2-server Server app
## @ingroup group2_mains
## Files, methods, etc used to run the server application

## @ingroup group2-server
## @file server/main.py
## @brief Starts the server application.
## @details The server:
## - Generates its own RSA key pair and unique ID
## - Registers itself with the Trusted Third Party (TTP)
## - Receives and stores a certificate issued by the TTP
## - Accepts client service requests
## - Requests session keys from the TTP
## - Receives encrypted messages from authenticated clients
## - Decrypts received data using negotiated AES session keys
def main():

    logger.info("Generating IDs and keys by the server")
    server_id = crypto.generate_random_id()
    server_public_key, server_private_key = crypto.generate_RSA_key_pair()
    logger.info(f"server id: {server_id}")
    GLOBAL_SERVER_ID = server_id
    active_sessions = {}
    logger.info("server running")
    
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
                logger.info(f"Recieved data from TTP: {data}")

                encrypted_server_id = crypto.encrypt_data(ttp_public_key, server_id.encode('utf-8'))
                encrypted_server_id_str = base64.b64encode(encrypted_server_id).decode('utf-8')
                server_public_key_str = crypto.serialize_public_key(server_public_key).decode('utf-8')

                payload = {
                    "type": "register",
                    "encrypted_server_id": encrypted_server_id_str,
                    "server_public_key": server_public_key_str
                }
                s.sendall(json.dumps(payload).encode('utf-8'))
                logger.info(f"Sent out encrypted server ID and public key to TTP: {payload}")
                cert_response = s.recv(4096)
                if cert_response:
                    logger.info(f"Received certificate from TTP: {cert_response.decode('utf-8')}")
                    
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
        logger.info(f"Server listening at {server_port}")
    
        try:
            while True:
                conn, addr = s.accept()
                with conn:
                    logger.info(f"Connected to client: {addr}")
                    data = conn.recv(4096)
                    if data:
                        data = json.loads(data.decode('utf-8'))
                        logger.info(f"Received data from client: {data}")
                        client_id = data.get("client_id")
                        request_type = data.get("type", "service_request")
                        if request_type == "service_request":    

                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ttp_s:
                                ttp_s.connect((host, port))
                                payload = {
                                    "type": "session_request",
                                    "server_id": GLOBAL_SERVER_ID,
                                    "client_id": client_id
                                }

                                ttp_s.sendall(json.dumps(payload).encode('utf-8'))
                                logger.info(f"Sent out ask for client authorization to TTP: {payload}")

                                ttp_response = ttp_s.recv(4096)
                                
                                if ttp_response:
                                    logger.info(f"Received an answer with session key from TTP: {ttp_response.decode('utf-8')}")
                                    ttp_response_data = json.loads(ttp_response.decode('utf-8'))
                                    
                                    if ttp_response_data.get("status") == "OK":
                                        encrypted_session_key = base64.b64decode(ttp_response_data["encrypted_session_key"])
                                        session_key = crypto.decrypt_data(server_private_key, encrypted_session_key)
                                        logger.info(f"Decrypted session key: {session_key.hex()}")
                                        active_sessions[client_id] = session_key

                        elif request_type =="secure_data":
                            logger.info(f"Received encrypted data from client: {data}")
                            session_key = active_sessions[client_id]
                            decrypted_data = crypto.decrypt_aes(session_key, base64.b64decode(data["encrypted_data"]))
                            logger.info(f"Decrypted data from client: {decrypted_data.decode('utf-8')}")
                        
                        else : 
                            logger.warning(f"Unknown client request type: {request_type}")
        
        except KeyboardInterrupt:
            logger.info("shutdown")

if __name__ == "__main__":
    main()