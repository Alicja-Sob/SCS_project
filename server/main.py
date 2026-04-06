import logging
import time
import socket

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Server_App") 

def main():
    logger.info("server działa")
    
    host = 'ttp'
    port = 5000
    
    time.sleep(2)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            logger.info("server : connected")
            
            s.sendall(b"ping dla ttp od serwera")
            
            data = s.recv(1024)
            logger.info(f"wiadomosc : {data.decode('utf-8')}")
            
        except Exception as e:
            logger.error(f"error: {e}")
            
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("shutdown")

if __name__ == "__main__":
    main()