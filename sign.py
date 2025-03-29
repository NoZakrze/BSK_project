import os
import fitz  
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def decrypt_private_key(encrypted_data, pin):
    key = SHA256.new(pin.encode()).digest() 
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def load_private_key(usb_path, pin):
    try:
        with open(os.path.join(usb_path, "private_key.enc"), "rb") as f:
            encrypted_data = f.read()
        return RSA.import_key(decrypt_private_key(encrypted_data, pin))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load private key: {e}")
        return None

def hash_pdf(pdf_path):
    with open(pdf_path, "rb") as f:
        doc_data = f.read()
    hash_obj = SHA256.new(doc_data)
    return hash_obj

def sign_pdf(pdf_path, private_key):
    try:
        doc_hash = hash_pdf(pdf_path)
        signature = pkcs1_15.new(private_key).sign(doc_hash) 

        signature_txt_path = pdf_path.replace(".pdf", "_signature.txt")
        with open(signature_txt_path, "w") as sig_file:
            sig_file.write(signature.hex())
    
        messagebox.showinfo("Success", f"PDF signed and signature saved as {signature_txt_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign PDF: {e}")

def select_pdf():
    return filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])

def select_usb():
    return filedialog.askdirectory(title="Select USB Drive")

def on_sign():
    pin = pin_entry.get()
    usb_path = "D:"
    pdf_path = pdf_entry.get()
    
    if not pin or not usb_path or not pdf_path:
        messagebox.showerror("Error", "Please fill all fields.")
        return
    
    private_key = load_private_key(usb_path, pin)
    if private_key:
        sign_pdf(pdf_path, private_key)

root = tk.Tk()
root.title("PDF Signer")
root.geometry("400x300")

tk.Label(root, text="Enter PIN:").pack(pady=5)
pin_entry = tk.Entry(root, show="*", width=30)
pin_entry.pack(pady=5)

tk.Label(root, text="Select PDF File:").pack(pady=5)
pdf_entry = tk.Entry(root, width=30)
pdf_entry.pack(pady=5)
browse_pdf_button = tk.Button(root, text="Browse", command=lambda: pdf_entry.insert(0, select_pdf()))
browse_pdf_button.pack(pady=5)

generate_button = tk.Button(root, text="Sign PDF", command=on_sign)
generate_button.pack(pady=10)

root.mainloop()