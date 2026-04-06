import logging
import socket

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("TTP_App") 

def main():
    logger.info("ttp dziala")
    
    host = '0.0.0.0'
    port = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        logger.info(f" naslucjiwanie na :{port}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                logger.info(f"polaczono : {addr}")
                data = conn.recv(1024)
                if data:
                    logger.info(f"wiadomosc : {data.decode('utf-8')}")
                    conn.sendall(b"ping od ttp dla serwera ")

if __name__ == "__main__":
    main()