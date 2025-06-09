"""
@file auxapp.py
@brief Module responsible for generating RSA keys and encrypting private key
@details Steps that user must perform:
1. Hook the pendrive
2. Start the module
3. Enter pin code
4. Click on "Generate Keys" button
When user clicks "Generate Keys" button RSA keys will be generated, private key
will be encrypted based on user's PIN and both keys will be stored in an
appropriate locations. 
"""
import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import tkinter as tk
from tkinter import messagebox

def encrypt_private_key(private_key_pem, pin):
    """
    @brief Function that encrypt private key
    @param private_key_pem Encoded private key in bytes format
    @param pin User's pin in string format
    @return cipher.nonce Unique nonce (bytes), tag Authentication tag(bytes), ciphertext Encrypted data(bytes)
    @details In this function pin code is transformed into 256-byte AES key.
    Then AES object is created and RSA private key is encrypted using key based on
    pin code
    """
    key = hashlib.sha256(pin.encode()).digest()  
    cipher = AES.new(key, AES.MODE_EAX)  
    ciphertext, tag = cipher.encrypt_and_digest(private_key_pem)
    return cipher.nonce, tag, ciphertext

def generate_keys(pin, usb_path):
    """
    @brief Function that generate RSA keys and write it into the appropriate files.
    @param pin User's pin in string format
    @param usb_path Root path to the usb in string format for example "D:"
    @return no return
    @details In this function a pair of RSA keys are generated. Then encrypt_private_key
    function is called. Then both keys are stored in appropriate location. At the end
    user will see message box which will inform about result of the saving operation
    """
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
    """
    @brief Function that is called when user clicks "Generate Keys" button
    @details In this function pin is collected from user input. If the pin
    is given by the user, the generate_keys function is called.
    """
    pin = pin_entry.get()
    usb_path = "D:"
    if not pin:
        messagebox.showerror("Error", "Please enter a PIN.")
        return
    generate_keys(pin, usb_path)


"""
@brief UI setup
@details UI contains input field for the pin code and "Generate Keys" button.
"""
root = tk.Tk()
root.title("Key Generator")
root.geometry("400x150")

tk.Label(root, text="Enter PIN:").pack(pady=5)
pin_entry = tk.Entry(root, show="*", width=30)
pin_entry.pack(pady=5)

generate_button = tk.Button(root, text="Generate Keys", command=on_generate)
generate_button.pack(pady=10)

root.mainloop()
