import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from xts_aes import XTSAES

class GUI:
    def __init__(self, master):
        self.master = master
        self.master.title("XTS-AES Encryption and Decryption")

        self.label = tk.Label(self.master, text="Select files for encryption/decryption:")
        self.label.pack(padx=3, pady=5)

        self.encrypt_button = tk.Button(self.master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(self.master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select plaintext file")
        if file_path:
            key_path = filedialog.askopenfilename(title="Select key file")
            if key_path:
                with open(file_path, 'rb') as file:
                    plaintext = file.read()
                with open(key_path, 'r') as key_file:
                    key_hex = key_file.read().strip()
                    key = bytes.fromhex(key_hex)
                    aes = XTSAES(key)
                
                self.label.config(text=f"Encrypting: {file_path}")
                self.master.update()

                ciphertext = aes.encrypt(plaintext)
                save_path = filedialog.asksaveasfilename(defaultextension=".enc")
                with open(save_path, 'wb') as encrypted_file:
                    encrypted_file.write(ciphertext)
                messagebox.showinfo("Encryption", f"File encrypted successfully!\nOutput saved as: {save_path}")

                self.label.config(text="Select files for encryption/decryption:")
                self.master.update()

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select ciphertext file")
        if file_path:
            key_path = filedialog.askopenfilename(title="Select key file")
            if key_path:
                with open(file_path, 'rb') as file:
                    ciphertext = file.read()
                with open(key_path, 'r') as key_file:
                    key_hex = key_file.read().strip()
                    key = bytes.fromhex(key_hex)
                    aes = XTSAES(key)
                
                self.label.config(text=f"Decrypting: {file_path}")
                self.master.update()

                decrypted_text = aes.decrypt(ciphertext)
                save_path = filedialog.asksaveasfilename(defaultextension=".txt")
                with open(save_path, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_text)
                messagebox.showinfo("Decryption", f"File decrypted successfully!\nOutput saved as: {save_path}")

                self.label.config(text="Select files for encryption/decryption:")
                self.master.update()

root = tk.Tk()
app = GUI(root)
root.mainloop()
