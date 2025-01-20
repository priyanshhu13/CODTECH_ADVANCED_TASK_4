import tkinter as tk
from tkinter import filedialog, messagebox
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import customtkinter as ctk
import threading

class EncryptionApp:
    def __init__(self):
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Create main window
        self.root = ctk.CTk()
        self.root.title("Advanced Encryption Tool")
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.8)
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Create gradient background frame
        self.bg_frame = ctk.CTkFrame(self.root)
        self.bg_frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Create main content frame with margin
        self.content_frame = ctk.CTkFrame(self.bg_frame, fg_color="transparent")
        self.content_frame.place(relx=0.05, rely=0.05, relwidth=0.9, relheight=0.9)

        # Title and Credits
        self.header_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=30, pady=(20, 0))

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="Advanced Encryption Tool",
            font=("Helvetica", 32, "bold"),
            text_color=("#1DA1F2")
        )
        self.title_label.pack(pady=(0, 5))

        # Main working area frame
        self.work_frame = ctk.CTkFrame(
            self.content_frame,
            fg_color=("gray90", "gray16")
        )
        self.work_frame.pack(fill="both", expand=True, padx=30, pady=20)

        # File selection frame
        self.file_frame = ctk.CTkFrame(self.work_frame, fg_color="transparent")
        self.file_frame.pack(fill="x", padx=30, pady=20)

        self.file_path = tk.StringVar()
        self.file_entry = ctk.CTkEntry(
            self.file_frame,
            placeholder_text="Select a file...",
            height=40,
            font=("Helvetica", 14),
            textvariable=self.file_path
        )
        self.file_entry.pack(side="left", padx=(0, 10), expand=True, fill="x")

        self.browse_button = ctk.CTkButton(
            self.file_frame,
            text="Browse",
            command=self.browse_file,
            width=120,
            height=40,
            font=("Helvetica", 14)
        )
        self.browse_button.pack(side="right")

        # Password frame
        self.password_frame = ctk.CTkFrame(self.work_frame, fg_color="transparent")
        self.password_frame.pack(fill="x", padx=30, pady=20)

        self.password = tk.StringVar()
        self.password_entry = ctk.CTkEntry(
            self.password_frame,
            placeholder_text="Enter password...",
            show="\u2022",
            height=40,
            font=("Helvetica", 14),
            textvariable=self.password
        )
        self.password_entry.pack(side="left", padx=(0, 10), expand=True, fill="x")

        self.show_password = tk.BooleanVar()
        self.show_password_cb = ctk.CTkCheckBox(
            self.password_frame,
            text="Show password",
            variable=self.show_password,
            command=self.toggle_password_visibility,
            font=("Helvetica", 14)
        )
        self.show_password_cb.pack(side="right")

        # Hash algorithm selection
        self.hash_frame = ctk.CTkFrame(self.work_frame, fg_color="transparent")
        self.hash_frame.pack(fill="x", padx=30, pady=20)

        self.hash_label = ctk.CTkLabel(
            self.hash_frame,
            text="Hash Algorithm:",
            font=("Helvetica", 14)
        )
        self.hash_label.pack(side="left", padx=(0, 10))

        self.hash_algorithm = tk.StringVar(value="SHA256")
        self.hash_menu = ctk.CTkOptionMenu(
            self.hash_frame,
            values=["MD5", "SHA256", "SHA512", "SHA1"],
            variable=self.hash_algorithm,
            width=200,
            height=40,
            font=("Helvetica", 14)
        )
        self.hash_menu.pack(side="left")

        # Action buttons
        self.button_frame = ctk.CTkFrame(self.work_frame, fg_color="transparent")
        self.button_frame.pack(fill="x", padx=30, pady=20)

        self.encrypt_button = ctk.CTkButton(
            self.button_frame,
            text="Encrypt File",
            command=lambda: self.process_file("encrypt"),
            width=200,
            height=50,
            font=("Helvetica", 16, "bold"),
            fg_color="#2ecc71",
            hover_color="#27ae60"
        )
        self.encrypt_button.pack(side="left", padx=10, expand=True)

        self.decrypt_button = ctk.CTkButton(
            self.button_frame,
            text="Decrypt File",
            command=lambda: self.process_file("decrypt"),
            width=200,
            height=50,
            font=("Helvetica", 16, "bold"),
            fg_color="#e74c3c",
            hover_color="#c0392b"
        )
        self.decrypt_button.pack(side="left", padx=10, expand=True)

        # Progress bar and status
        self.progress_frame = ctk.CTkFrame(self.work_frame, fg_color="transparent")
        self.progress_frame.pack(fill="x", padx=30, pady=20)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ctk.CTkProgressBar(
            self.progress_frame,
            mode="determinate",
            variable=self.progress_var,
            height=15
        )
        self.progress_bar.pack(fill="x", pady=(0, 10))
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            self.progress_frame,
            text="Ready",
            font=("Helvetica", 14),
            text_color=("#6C757D")
        )
        self.status_label.pack()

        # Footer with version and credits
        self.footer_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.footer_frame.pack(fill="x", padx=30, pady=10)

        self.version_label = ctk.CTkLabel(
            self.footer_frame,
            text="v1.0.0",
            font=("Helvetica", 12),
            text_color=("#6C757D")
        )
        self.version_label.pack(side="left")

        self.credits_label = ctk.CTkLabel(
            self.footer_frame,
            text="Created by: Premkumar Soni",
            font=("Helvetica", 12),
            text_color=("#6C757D")
        )
        self.credits_label.pack(side="right")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="\u2022")

    def generate_key(self, password, salt, hash_algorithm='SHA256'):
        hash_algorithms = {
            'MD5': hashes.MD5(),
            'SHA256': hashes.SHA256(),
            'SHA512': hashes.SHA512(),
            'SHA1': hashes.SHA1(),
        }

        if hash_algorithm not in hash_algorithms:
            raise ValueError("Unsupported hash algorithm")

        kdf = PBKDF2HMAC(
            algorithm=hash_algorithms[hash_algorithm],
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, filepath, password, hash_algorithm):
        try:
            salt = os.urandom(16)
            iv = os.urandom(16)
            key = self.generate_key(password, salt, hash_algorithm)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            with open(filepath, 'rb') as f:
                plaintext = f.read()

            padding = 16 - len(plaintext) % 16
            plaintext += bytes([padding]) * padding

            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            with open(filepath + '.enc', 'wb') as f:
                f.write(salt + iv + ciphertext)

            return True, "File encrypted successfully!"
        except Exception as e:
            return False, f"Encryption error: {str(e)}"

    def decrypt_file(self, filepath, password, hash_algorithm):
        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            salt, iv, ciphertext = content[:16], content[16:32], content[32:]
            key = self.generate_key(password, salt, hash_algorithm)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            padding = plaintext[-1]
            if padding < 1 or padding > 16:
                raise ValueError("Invalid padding")
            plaintext = plaintext[:-padding]

            original_path = filepath.replace('.enc', '')
            with open(original_path, 'wb') as f:
                f.write(plaintext)

            return True, "File decrypted successfully!"
        except Exception as e:
            return False, f"Decryption error: {str(e)}"

    def update_progress(self, value):
        self.progress_var.set(value)
        self.root.update_idletasks()

    def process_file(self, action):
        filepath = self.file_path.get()
        password = self.password.get()
        hash_algorithm = self.hash_algorithm.get()

        if not filepath or not password:
            messagebox.showerror("Error", "Please select a file and enter a password")
            return

        self.encrypt_button.configure(state="disabled")
        self.decrypt_button.configure(state="disabled")
        self.status_label.configure(text="Processing...", text_color="#f39c12")
        self.update_progress(0)

        def process():
            if action == "encrypt":
                success, message = self.encrypt_file(filepath, password, hash_algorithm)
            else:
                success, message = self.decrypt_file(filepath, password, hash_algorithm)

            self.root.after(0, lambda: self.update_progress(1))
            self.root.after(0, lambda: self.status_label.configure(
                text=message, text_color=("#2ecc71" if success else "#e74c3c")
            ))
            self.root.after(0, lambda: self.encrypt_button.configure(state="normal"))
            self.root.after(0, lambda: self.decrypt_button.configure(state="normal"))

            if success:
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)

        threading.Thread(target=process, daemon=True).start()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = EncryptionApp()
    app.run()
