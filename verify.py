import os
import fitz  
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def load_public_key(public_key_path):
    with open(public_key_path, "rb") as f:
        return RSA.import_key(f.read())

def load_signature(signature_path):
    try:
        with open(signature_path, "r") as f:
            return bytes.fromhex(f.read().strip())
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load signature: {e}")
        return None

def hash_pdf(pdf_path):
    with open(pdf_path, "rb") as f:
        doc_data = f.read()
    hash_obj = SHA256.new(doc_data)
    return hash_obj

def verify_pdf(pdf_path, public_key, signature_path):
    signature = load_signature(signature_path)
    if signature is None:
        return
    
    doc_hash = hash_pdf(pdf_path)
    try:
        pkcs1_15.new(public_key).verify(doc_hash, signature)
        messagebox.showinfo("Success", "✅ Signature is valid!")
    except (ValueError):
        messagebox.showerror("Error", "❌ Signature is invalid.")

def select_pdf():
    return filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])

def select_signature():
    return filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])

def on_verify():
    pdf_path = pdf_entry.get()
    signature_path = sig_entry.get()
    public_key_path = key_entry.get()
    
    if not pdf_path or not signature_path or not public_key_path:
        messagebox.showerror("Error", "Please fill all fields.")
        return
    
    public_key = load_public_key(public_key_path)
    verify_pdf(pdf_path, public_key, signature_path)

# GUI Setup
root = tk.Tk()
root.title("PDF Verifier")
root.geometry("400x400")

tk.Label(root, text="Select Public Key:").pack(pady=5)
key_entry = tk.Entry(root, width=30)
key_entry.pack(pady=5)
browse_key_button = tk.Button(root, text="Browse", command=lambda: key_entry.insert(0, filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])))
browse_key_button.pack(pady=5)

tk.Label(root, text="Select PDF File:").pack(pady=5)
pdf_entry = tk.Entry(root, width=30)
pdf_entry.pack(pady=5)
browse_pdf_button = tk.Button(root, text="Browse", command=lambda: pdf_entry.insert(0, select_pdf()))
browse_pdf_button.pack(pady=5)

tk.Label(root, text="Select Signature File:").pack(pady=5)
sig_entry = tk.Entry(root, width=30)
sig_entry.pack(pady=5)
browse_sig_button = tk.Button(root, text="Browse", command=lambda: sig_entry.insert(0, select_signature()))
browse_sig_button.pack(pady=5)

verify_button = tk.Button(root, text="Verify PDF", command=on_verify)
verify_button.pack(pady=10)

root.mainloop()
