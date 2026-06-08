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


## @defgroup group2-ttp TTP app
## @ingroup group2_mains
## Files, methods, etc used to run the TTP application

## @ingroup group2-ttp
## @brief Starts the Trusted Third Party (TTP) server
## @details Initializes the TTP identity, generates an RSA key pair and self-signed certificate, then starts a TCP server.
##
## The server processes three types of requests:
## - register: registers a client or server and issues a certificate.
## - session_request: generates and distributes an AES session key.
## - fetch_key: allows a client to retrieve a pending encrypted session key.
##
## Registered entities are stored in memory together with their public keys and connection information.
## Generated session keys are encrypted using the recipient's RSA public key before transmission.

## @exception socket.error - raised when a network communication error occurs.
## @exception json.JSONDecodeError - raised when an invalid JSON message is received.
## @exception ValueError - raised when malformed cryptographic data is processed.
def main():
    logger.info("Generating a certificate via TTP")
    ttp_id = crypto.generate_random_id()
    
    logger.info(f"ttp id: {ttp_id}")

    ttp_public_key, ttp_private_key = crypto.generate_RSA_key_pair()
    ttp_cert = crypto.generate_certificate(ttp_id, ttp_public_key, ttp_id, ttp_private_key)
    
    logger.info(f"TTP certificate generated: {ttp_cert}")

    logger.info("TTP running")
    
    host = '0.0.0.0'
    port = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        logger.info(f"Listening on :{port}")
        
        registered_servers = {}
        pending_client_keys = {}
        while True:
            conn, addr = s.accept()

            with conn:
            
                logger.info(f"Connected : {addr}")
                
                data = conn.recv(4096)
                request = json.loads(data.decode('utf-8'))
                request_type = request.get("type")
                if request_type == "register":
                    logger.info(f"Received a registration attempt: {request}")
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
                    logger.info(f"server/client id: {server_id}")

                    registered_servers[server_id] = {
                        "public_key": server_public_key,
                        "callback_port": data.get("callback_port"),
                        "address": addr[0]
                    }

                    server_cert = crypto.generate_certificate(server_id, server_public_key, ttp_id, ttp_private_key)

                    serialized_cert = crypto.serialize_certificate(server_cert).decode('utf-8')
                    conn.sendall(serialized_cert.encode('utf-8'))
                    logger.info(f"Certificate sent to a server: {serialized_cert}")


                elif request_type == "session_request":
                    logger.info(f"Authorization request: {request}")
                    client_id = request.get("client_id")
                    server_id = request.get("server_id")

                    if server_id in registered_servers and client_id in registered_servers:
                        server_info = registered_servers[server_id]
                        client_info = registered_servers[client_id]

                        session_key = crypto.generate_aes_key()
                        logger.info(f"Generated 256 bit AES key")

                        encrypted_session_key_for_server = crypto.encrypt_data(server_info["public_key"], session_key)
                        encrypted_session_key_for_client = crypto.encrypt_data(client_info["public_key"], session_key)

                        response_to_server = {
                            "status": "OK",
                            "encrypted_session_key": base64.b64encode(encrypted_session_key_for_server).decode('utf-8'),
                        }
                        conn.sendall(json.dumps(response_to_server).encode('utf-8'))
                        logger.info(f"Sent out the encrypted session key to the server")

                        pending_client_keys[client_id] = base64.b64encode(encrypted_session_key_for_client).decode('utf-8')                        
                        logger.info(f"Saved the encrypted session key for client {client_id} as a pending key")

                    else:
                        logger.warning(f"Unknown server / client ID: {server_id}, {client_id}")

                elif request_type == "fetch_key":
                    client_id = request.get("client_id")
                    if client_id in pending_client_keys:
                        encrypted_session_key_for_client = pending_client_keys.pop(client_id)
                        response = {
                            "status": "OK",
                            "encrypted_session_key": encrypted_session_key_for_client
                        }
                        conn.sendall(json.dumps(response).encode('utf-8'))
                        logger.info(f"Sent out encrypted session key to the client {client_id}")
                        
                    else:
                        response = {
                            "status": "ERROR",
                            "message": "Missing session key for given client"
                        }
                        conn.sendall(json.dumps(response).encode('utf-8'))
                        logger.warning(f"Client {client_id} session key not found")
                else:
                    logger.warning(f"Unknown request type: {request_type}")
                # data = conn.recv(1024)
                # if data:
                #     logger.info(f"Message : {data.decode('utf-8')}")
                #     conn.sendall(b"ping od ttp dla serwera ")

if __name__ == "__main__":
    main()