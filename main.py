import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet
import base64
import codecs

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Message Encryption App")

        self.style = ttk.Style()
        self.style.theme_use("clam")  # You can try other themes like "arc", "equilux", etc.

        self.label1 = ttk.Label(root, text="Enter Text to Encrypt:", font=('Arial', 12))
        self.label1.pack(pady=10)

        self.input_text = tk.Text(root, height=5, width=50, font=('Arial', 12))
        self.input_text.pack(pady=10)

        self.label2 = ttk.Label(root, text="Choose Encryption Method:", font=('Arial', 12))
        self.label2.pack(pady=10)

        self.encryption_method_var = tk.StringVar()
        self.encryption_method_var.set("Caesar Cipher")

        encryption_methods = ["Caesar Cipher", "Substitution Cipher", "ROT13", "Base64", "Fernet"]

        self.method_menu = ttk.Combobox(root, textvariable=self.encryption_method_var, values=encryption_methods, font=('Arial', 12))
        self.method_menu.pack(pady=10)

        self.encrypt_button = ttk.Button(root, text="Encrypt", command=self.encrypt_message, style="TButton")
        self.encrypt_button.pack(pady=20)

        self.label3 = ttk.Label(root, text="Encrypted Text:", font=('Arial', 12))
        self.label3.pack(pady=10)

        self.output_text = tk.Text(root, height=5, width=50, state=tk.DISABLED, font=('Arial', 12))
        self.output_text.pack(pady=10)

        self.style.configure("TButton", padding=10, font=('Arial', 12))

    def encrypt_message(self):
        clear_text = self.input_text.get("1.0", tk.END).strip()
        encryption_method = self.encryption_method_var.get()

        if encryption_method == "Caesar Cipher":
            encrypted_text = self.caesar_cipher_encrypt(clear_text)
        elif encryption_method == "Substitution Cipher":
            encrypted_text = self.substitution_cipher_encrypt(clear_text)
        elif encryption_method == "ROT13":
            encrypted_text = self.rot13_encrypt(clear_text)
        elif encryption_method == "Base64":
            encrypted_text = self.base64_encrypt(clear_text)
        elif encryption_method == "Fernet":
            encrypted_text = self.fernet_encrypt(clear_text)
        else:
            encrypted_text = "Invalid encryption method."

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)
        self.output_text.config(state=tk.DISABLED)

    def caesar_cipher_encrypt(self, text, shift=3):
        encrypted_text = ""
        for char in text:
            if char.isalpha():
                encrypted_text += chr((ord(char) - ord('A' if char.isupper() else 'a') + shift) % 26
                                      + ord('A' if char.isupper() else 'a'))
            else:
                encrypted_text += char
        return encrypted_text

    def substitution_cipher_encrypt(text, key):
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        encrypted_text = ''

        for char in text:
            if char.upper() in alphabet:
                index = (alphabet.index(char.upper()) + key) % 26
                encrypted_char = alphabet[index] if char.isupper() else alphabet[index].lower()
                encrypted_text += encrypted_char
            else:
                encrypted_text += char

        return encrypted_text


    def rot13_encrypt(self, text):
        return codecs.encode(text, 'rot_13')

    def base64_encrypt(self, text):
        return base64.b64encode(text.encode()).decode()

    def fernet_encrypt(self, text):
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_text = cipher_suite.encrypt(text.encode()).decode()
        return encrypted_text


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
