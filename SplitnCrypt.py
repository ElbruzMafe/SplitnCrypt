import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
import os
import hashlib
import gnupg
import shutil

# GNUPG ayarı
gpg = gnupg.GPG(gnupghome=os.path.expanduser("~/.gnupg"))

# Log fonksiyonu
def log(msg):
    info_text.config(state='normal')
    info_text.insert(tk.END, msg + '\n')
    info_text.see(tk.END)
    info_text.config(state='disabled')

def dosya_sec():
    dosya = filedialog.askopenfilename()
    if dosya:
        secilen_dosya.set(dosya)

def bol():
    file_path = secilen_dosya.get()
    output_folder = "divided_files"
    if not file_path:
        messagebox.showerror("Hata", "Please select an input file.")
        return
    chunk_size_mb = 1
    try:
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        with open(file_path, 'rb') as f:
            i = 0
            while chunk := f.read(chunk_size_mb * 1024 * 1024):
                part_path = os.path.join(output_folder, f'divided_part_{i:03}')
                with open(part_path, 'wb') as chunk_file:
                    chunk_file.write(chunk)
                log(f"Created: {part_path}")
                i += 1
        log(f"\n{i} parts created and saved to '{output_folder}'.\n")
        messagebox.showinfo("Success", "File splitting completed.")
    except Exception as e:
        log(f"Error: {e}")
        messagebox.showerror("Error", str(e))

def get_original_extension():
    file_path = secilen_dosya.get()
    if file_path:
        _, ext = os.path.splitext(file_path)
        return ext
    return ''

def birlestir():
    input_folder = "divided_files"
    output_folder = "merged_files"
    ext = get_original_extension()
    output_filename = f"merged_file{ext}"
    if not os.path.exists(input_folder):
        messagebox.showerror("Error", f"'{input_folder}' folder not found.")
        return
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    output_path = os.path.join(output_folder, output_filename)
    try:
        # Clean output folder
        for f in os.listdir(output_folder):
            fp = os.path.join(output_folder, f)
            if os.path.isfile(fp):
                os.remove(fp)
        with open(output_path, 'wb') as outfile:
            i = 0
            while True:
                part_name = f'divided_part_{i:03}'
                part_path = os.path.join(input_folder, part_name)
                if not os.path.exists(part_path):
                    break
                with open(part_path, 'rb') as infile:
                    outfile.write(infile.read())
                log(f'Merged: {part_name}')
                i += 1
        log(f"\nMerging completed: '{output_path}'\n")
        messagebox.showinfo("Success", f"Merging completed. Output: {output_filename}")
    except Exception as e:
        log(f"Error: {e}")
        messagebox.showerror("Error", str(e))

def hash_al():
    def hash_parts():
        input_folder = "divided_files"
        if not os.path.exists(input_folder):
            messagebox.showerror("Error", f"'{input_folder}' folder not found.")
            return
        try:
            for file in sorted(os.listdir(input_folder)):
                if file.startswith('divided_part_'):
                    full_path = os.path.join(input_folder, file)
                    log(hash_file(full_path))
            messagebox.showinfo("Success", "Hashes of divided files calculated.")
        except Exception as e:
            log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def hash_selected_file():
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            log(hash_file(file_path))
            messagebox.showinfo("Success", "Hash of selected file calculated.")
        except Exception as e:
            log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    secim = simpledialog.askstring("Hash Option", "Select hash type:\n1 - Hash divided files\n2 - Hash a specific file\n(Type 1 or 2)")
    if secim == '1':
        hash_parts()
    elif secim == '2':
        hash_selected_file()
    else:
        messagebox.showinfo("Cancelled", "Operation cancelled or invalid selection.")

def hash_file(file_path):
    hashes = {
        'md5': hashlib.md5(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    result = f"\n📄 {file_path}:"
    for name, h in hashes.items():
        result += f"\n  {name.upper()}: {h.hexdigest()}"
    return result

def pgp_sifrele():
    file_path = secilen_dosya.get()
    ext = get_original_extension()
    output_file = f"pgp_encrypted{ext}"
    recipient = pgp_recipient.get()
    if not file_path or not recipient:
        messagebox.showerror("Error", "Please select an input file and enter recipient email.")
        return
    try:
        with open(file_path, 'rb') as f:
            status = gpg.encrypt_file(
                f,
                recipients=[recipient],
                output=output_file
            )
        if status.ok:
            log(f"[✓] Encryption successful: {output_file}")
            messagebox.showinfo("Success", "PGP encryption completed.")
        else:
            log(f"[X] Encryption failed: {status.stderr}")
            messagebox.showerror("Error", status.stderr)
    except Exception as e:
        log(f"Error: {e}")
        messagebox.showerror("Error", str(e))

def pgp_coz():
    ext = get_original_extension()
    input_file = f"pgp_encrypted{ext}"
    output_file = f"pgp_decrypted{ext}"
    passphrase = pgp_passphrase.get()
    if not passphrase:
        messagebox.showerror("Error", "Please enter passphrase.")
        return
    try:
        with open(input_file, 'rb') as f:
            status = gpg.decrypt_file(
                f,
                passphrase=passphrase,
                output=output_file
            )
        if status.ok:
            log(f"[✓] Decryption successful: {output_file}")
            messagebox.showinfo("Success", "PGP decryption completed.")
        else:
            log(f"[X] Decryption failed: {status.stderr}")
            messagebox.showerror("Error", status.stderr)
    except Exception as e:
        log(f"Error: {e}")
        messagebox.showerror("Error", str(e))

def delete_outputs():
    deleted = []
    # Delete divided_files folder
    if os.path.exists("divided_files"):
        shutil.rmtree("divided_files")
        deleted.append("divided_files/")
    # Delete merged_files folder
    if os.path.exists("merged_files"):
        shutil.rmtree("merged_files")
        deleted.append("merged_files/")
    # Delete pgp_encrypted.* and pgp_decrypted.* in cwd
    for fname in os.listdir():
        if fname.startswith("pgp_encrypted") or fname.startswith("pgp_decrypted"):
            try:
                os.remove(fname)
                deleted.append(fname)
            except Exception:
                pass
    if deleted:
        log("Deleted: " + ", ".join(deleted))
        messagebox.showinfo("Deleted", "All output files and folders have been deleted.")
    else:
        messagebox.showinfo("No Output", "No output files or folders to delete.")

# --- ARAYÜZ ---
pencere = tk.Tk()
pencere.title("File Manager")
pencere.geometry("650x520")

secilen_dosya = tk.StringVar()
pgp_recipient = tk.StringVar()
pgp_passphrase = tk.StringVar()

frm = tk.Frame(pencere)
frm.pack(pady=10)

row = 0
tk.Label(frm, text="Input File:").grid(row=row, column=0, sticky='e')
tk.Entry(frm, textvariable=secilen_dosya, width=40).grid(row=row, column=1)
tk.Button(frm, text="Select", command=dosya_sec).grid(row=row, column=2)
row += 1
tk.Label(frm, text="PGP Recipient Email:").grid(row=row, column=0, sticky='e')
tk.Entry(frm, textvariable=pgp_recipient, width=40).grid(row=row, column=1)
row += 1
tk.Label(frm, text="PGP Passphrase:").grid(row=row, column=0, sticky='e')
tk.Entry(frm, textvariable=pgp_passphrase, width=40, show='*').grid(row=row, column=1)
row += 1

btnfrm = tk.Frame(pencere)
btnfrm.pack(pady=10)
tk.Button(btnfrm, text="Split File", command=bol, width=20).grid(row=0, column=0, padx=5)
tk.Button(btnfrm, text="Merge Files", command=birlestir, width=20).grid(row=0, column=1, padx=5)
tk.Button(btnfrm, text="Hash", command=hash_al, width=20).grid(row=0, column=2, padx=5)
tk.Button(btnfrm, text="PGP Encrypt", command=pgp_sifrele, width=20).grid(row=1, column=0, padx=5, pady=5)
tk.Button(btnfrm, text="PGP Decrypt", command=pgp_coz, width=20).grid(row=1, column=1, padx=5, pady=5)
tk.Button(btnfrm, text="Delete All Outputs", command=delete_outputs, width=20, fg='red').grid(row=1, column=2, padx=5, pady=5)

info_text = scrolledtext.ScrolledText(pencere, width=80, height=15, state='disabled')
info_text.pack(padx=10, pady=10)

pencere.mainloop()
