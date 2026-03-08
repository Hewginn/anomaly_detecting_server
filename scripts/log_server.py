import socket
import os

# --- BEÁLLÍTÁSOK ---
HOST = '0.0.0.0'  # Minden érkező kapcsolatot fogad
PORT = 5000       # Ezen a kapun várunk a laptopra
# Abszolút útvonal, hogy ne tévedjen el a Python
LOG_DIR = os.path.expanduser("/home/kristofejes/kutatas/data")
LOG_FILE = os.path.join(LOG_DIR, "target_test.log")

# Mappa létrehozása, ha hiányozna
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
    print(f"Mappa létrehozva: {LOG_DIR}")

# Szerver indítása
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Log gyűjtő szerver fut a {PORT} porton...")
    print(f"Mentés helye: {LOG_FILE}")

    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            if data:
                log_entry = data.decode('utf-8')
                with open(LOG_FILE, "a") as f:
                    f.write(log_entry + "\n")
                print(f"Log érkezett innen: {addr}")
