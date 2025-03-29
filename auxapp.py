import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import tkinter as tk
from tkinter import messagebox

def encrypt_private_key(private_key_pem, pin):
    key = hashlib.sha256(pin.encode()).digest()  
    cipher = AES.new(key, AES.MODE_EAX)  
    ciphertext, tag = cipher.encrypt_and_digest(private_key_pem)
    return cipher.nonce, tag, ciphertext

def generate_keys(pin, usb_path):
    
    key = RSA.generate(4096)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()

    nonce, tag, encrypted_private_key = encrypt_private_key(private_key_pem, pin)

    try:
        with open(os.path.join(usb_path, "private_key.enc"), "wb") as f:
            f.write(nonce + tag + encrypted_private_key)

        with open("public_key.pem", "wb") as f:
            f.write(public_key_pem)
        
        messagebox.showinfo("Success", "RSA keys generated and saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save keys: {e}")

def on_generate():
    pin = pin_entry.get()
    usb_path = "D:"
    if not pin:
        messagebox.showerror("Error", "Please enter a PIN.")
        return
    generate_keys(pin, usb_path)

root = tk.Tk()
root.title("Key Generator")
root.geometry("400x150")

tk.Label(root, text="Enter PIN:").pack(pady=5)
pin_entry = tk.Entry(root, show="*", width=30)
pin_entry.pack(pady=5)

generate_button = tk.Button(root, text="Generate Keys", command=on_generate)
generate_button.pack(pady=10)

root.mainloop()
