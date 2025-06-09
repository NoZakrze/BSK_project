"""
@file sign.py
@brief Module responsible for selected a pdf file and signing it with a private key
@details Steps that user must perform:
1. Enter pin code
2. Select PDF File
3. Click on "Sign PDF" button
When user clicks "Sign PDF" button pdf file will be singed with user's private key
"""
import os
from PyPDF2 import PdfReader, PdfWriter 
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def decrypt_private_key(encrypted_data, pin):
    """
    @brief Function that decrypt private key
    @param encrypted_data Encoded private key in bytes format
    @param pin User's pin in string format
    @return decrypted private_key in bytes format
    @details In this function pin code is transformed into 256-byte AES key.
    Then AES object is created and RSA private key is decrypted using key based on
    pin code
    """
    key = SHA256.new(pin.encode()).digest() 
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def load_private_key(usb_path, pin):
    """
    @brief Function that load private_key from usb
    @param usb_path path to private_key in string format
    @param pin User's pin in string format
    @return RSA object with private key
    @details In this function file with private_key is opened, private key is
    decrypted and put in a RSA object
    """
    try:
        with open(os.path.join(usb_path, "private_key.enc"), "rb") as f:
            encrypted_data = f.read()
        return RSA.import_key(decrypt_private_key(encrypted_data, pin))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load private key: {e}")
        return None

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

def sign_pdf(pdf_path, private_key):
    """
    @brief Function that add a sign to pdf file
    @param pdf_path path to pdf file in string format
    @param priate_key private key object
    @details This function uses an RSA private key to generate a signature based
    on the hash of the PDF document.
    """
    doc_hash = hash_pdf(pdf_path)
    try:
        with open(pdf_path, 'rb') as f:
            pdf_reader = PdfReader(f)
            pdf_writer = PdfWriter()
            
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)  

            signature = pkcs1_15.new(private_key).sign(doc_hash) 
            pdf_writer.add_metadata({'/Signature': signature.hex()})

            signed_path = pdf_path.replace(".pdf", "_signed.pdf")
            with open(signed_path, "wb") as sig_f:
                pdf_writer.write(sig_f)
        
            messagebox.showinfo("Success", f"PDF signed as {signed_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign PDF: {e}")

def select_pdf():
    """
    @brief Function that opens a dialog box that allows the user to select
    a PDF file from the file system.
    @return path to pdf file in string format
    """
    return filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])

def select_usb():
    """
    @brief Function that opens a dialog box that allows the user to select 
    a folder representing a connected USB drive or any directory.
    @return path to usb in string format
    """
    return filedialog.askdirectory(title="Select USB Drive")

def on_sign():
    """
    @brief Function that is called when user clicks "Sign PDF" button
    @details In this function pin is collected from user input. If the
    priate key was successfully loaded from file, the sign_pdf function 
    is called.
    """
    pin = pin_entry.get()
    usb_path = "F:"
    pdf_path = pdf_entry.get()
    
    if not pin or not usb_path or not pdf_path:
        messagebox.showerror("Error", "Please fill all fields.")
        return
    
    private_key = load_private_key(usb_path, pin)
    if private_key:
        sign_pdf(pdf_path, private_key)

"""
@brief UI setup
@details UI contains input field for the pin code, field for select pdf 
file  and "Sign pdf" button.
"""
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