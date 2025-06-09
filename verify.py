"""
@file verify.py
@brief Module responsible for verifying the pdf signature
@details Steps that user must perform:
1. Start Module
2. Select public key file
3. Select signed pdf
4. Click on "Verify PDF" button
When user clicks "Verify PDF" button the pdf signature will the
verified with public key. The user will recieve an information
if the verification was successful or not
"""
import os
from PyPDF2 import PdfReader, PdfWriter
import tkinter as tk
import binascii
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def load_public_key(public_key_path):
    """
    @brief Function that load private_key from file
    @param public_key_path path to public_key in string format
    @return RSA object with public key
    @details In this function file with public_key is opened, 
    public key isput in a RSA object
    """
    with open(public_key_path, "rb") as f:
        return RSA.import_key(f.read())

def hash_pdf(pdf_path):
    """
    @brief Function that caltulate hash function for a pdf file
    @param pdf_path path to pdf file in string format
    @return Hash object which contains calculated hash function
    @details In this function new SHA256 object is created. Next the hash
    function is calculated for the selected pdf file.
    """
    hash_obj = SHA256.new()
    with open(pdf_path, "rb") as f:
        pdf_reader = PdfReader(f)
        for page in pdf_reader.pages:
            text = page.extract_text()
            if text:
                hash_obj.update(text.encode('utf-8'))
    return hash_obj

def verify_pdf(pdf_path, public_key):
    """
    @brief Function that checks whether the PDF file
    contains a valid digital signature.
    @param pdf_path path to pdf file in string format
    @param public_key public key object
    @details In this function uses the RSA public key to verify
    the signature. After the verification it created a Messagebox 
    with information about the result.
    """
    with open(pdf_path, 'rb') as file:
        pdf_reader = PdfReader(file)
        signature = pdf_reader.metadata.get('/Signature')
        if signature is None:
            messagebox.showerror("Error", "Signature missing.")
            return
        signature = binascii.unhexlify(signature)
        doc_hash = hash_pdf(pdf_path)
        try:
            pkcs1_15.new(public_key).verify(doc_hash, signature)
            messagebox.showinfo("Success", "Signature is valid!")
        except (ValueError):
            messagebox.showerror("Error", "Signature is invalid.")

def select_pdf():
    """
    @brief Function that opens a dialog box that allows the user to select
    a PDF file from the file system.
    @return path to pdf file in string format
    """
    return filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])

def on_verify():
    """
    @brief Function that is called when user clicks "Verify PDF" button
    @details In this function pdf_path and public_key_path are collected
    from use input. Next "load_public_key" and "verify_pdf" functions
    are called. 
    """
    pdf_path = pdf_entry.get()
    public_key_path = key_entry.get()
    
    public_key = load_public_key(public_key_path)
    verify_pdf(pdf_path, public_key)

"""
@brief UI setup
@details UI contains input field for select public_key file, field for select pdf
file and "Verify PDF" button.
"""
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

verify_button = tk.Button(root, text="Verify PDF", command=on_verify)
verify_button.pack(pady=10)

root.mainloop()
