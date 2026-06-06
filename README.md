# Security of Computer Systems - Project 2025/2026

The goal of the project is developing a set of applications emulating an enviroment with trusted third party (TTP) and client-server data exchange scenario

# How to turn on

to track logs in same console :
docker-compose up --build 

to deatach docker from console : 
docker-compose up -d --build

to show logs : 
docker-compose logs -f

to turn off :
docker-compose down

# using client
cd user
python client_gui.py

# flow test 

1. Click **"Zaloguj do TTP"**.
   - Wait for the green "Autoryzacja poprawna" status (RSA keys are exchanged).
2. Click **"Pobierz klucz AES"**.
   - Wait for the green "klucz AES pobrany" status (AES session key is fetched from TTP).
3. Type a test message in the input box.
4. Click **"Wyślij wiadomość"**.
   - The message is encrypted with AES-256 and sent to the Server.
5. Check Docker logs.
   - You should see the Server receiving the secure payload and printing your decrypted message: `odszyfrowane dane od klienta: [your text]`.

* Server does everything automaticaly
