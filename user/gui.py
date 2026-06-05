import tkinter as tk

def simulate_auth():
    status_label.config(text="🟢 Autoryzacja poprawna", fg="green")
    service_btn.config(state=tk.NORMAL)

def request_service():
    status_label.config(text="🔵 Usługa aktywna", fg="blue")

root = tk.Tk()
root.title("Klient")
root.geometry("500x200")

status_label = tk.Label(root, text="🔴 Brak uwierzytelnienia", fg="red")
status_label.pack(pady=10)

auth_btn = tk.Button(root, text="Zaloguj do TTP", command=simulate_auth)
auth_btn.pack(pady=5)

service_btn = tk.Button(root, text="Wybierz usługę", state=tk.DISABLED, command=request_service)
service_btn.pack()

root.mainloop()