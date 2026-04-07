import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("Server_App") 

def main():
    logger.info("working")
    
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("shutdown")

if __name__ == "__main__":
    main()