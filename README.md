# Security of Computer Systems - Project 2025/2026

The goal of the project is developing a set of applications emulating an environment with trusted third party (TTP) and client-server data exchange scenario

# How to use the simulated environment

to track logs in same console :
`docker-compose up --build `

to detach docker from console : 
`docker-compose up -d --build`

to show logs : 
`docker-compose logs -f`

to turn off :
`docker-compose down`

## Using client service
```
cd Code\user
python gui.py
```

## Flow test 

1. Click **"Log in with TTP"**.
   - Wait for the green "Authorization correct" status (RSA keys are exchanged).
2. Click **"Download AES key"**.
   - Wait for the green "AES key obtained" status (AES session key is fetched from TTP).
3. Type a test message in the input box.
4. Click **"Send message"**.
   - The message is encrypted with AES-256 and sent to the Server.
5. Check Docker logs.
   - You should see the Server receiving the secure payload and printing your decrypted message: `Decrypted data from client: [your text]`.

Server does everything automatically

# Documentation

### Code documentation

Code documentation is generated using [Doxygen](https://www.doxygen.nl/manual/lists.html).

To view generated documentation open the **index.html** file in **Documentation/html** folder

In order to generate the documentation run `doxygen Doxyfile` in main project folder.

### Project documentation
Project is documented in the **SCS_report.pdf** file in the **Report** folder.
