import os
import hashlib
import json
import tkinter as tk
from tkinter import filedialog, messagebox
import datetime

class FileIntegrityMonitor:
    def __init__(self, master):
        self.master = master                                            # main window
        self.master.title("File Integrity Monitor")                     # name the application window
        self.master.geometry("500x400")                                 # define window geometry
        
        self.monitored_files = {}                                       # empty dictionary to store informations about the files
        self.file_listbox = tk.Listbox(master, width=50)                # listbox is used to display items
        self.file_listbox.pack(pady=10)
        
        # Window Buttons 
        
        add_button = tk.Button(master, text="Add File", command=self.add_file)
        add_button.pack()
        
        check_button = tk.Button(master, text="Check Integrity", command=self.check_integrity)
        check_button.pack()

        save_button = tk.Button(master, text="Save List", command=self.save_list)
        save_button.pack()

        load_button = tk.Button(master, text="Load List", command=self.load_list)
        load_button.pack()
        
        # Window Buttons
        
    # adds files to listbox and also calculates hashes    
    def add_file(self):
        file_path = filedialog.askopenfilename()                                    # Opens file explorer
        if file_path:
            self.monitored_files[file_path] = self.calculate_hash(file_path)        # calls calculate_hash method for the files in the monitored_files dictionary
            self.update_listbox()                                                   # call update_listbox method
            
    def calculate_hash(self, file_path):
        sha256_hash = hashlib.sha256()                              # create hash object and use the chosen algorithm
        with open(file_path, "rb") as f:                            # read file path
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()                              # return the hexadecimal representation of the SHA-256 hash
       
    def mod_time(self):
        pass
    
    # insert files selected in file explorer and insert them into listbox
    def update_listbox(self):
        self.file_listbox.delete(0, tk.END)
        for file_path in self.monitored_files:
            self.file_listbox.insert(tk.END, file_path) 
    
    def check_integrity(self):
        for file_path, original_hash in self.monitored_files.items():
            if os.path.exists(file_path):
                current_hash = self.calculate_hash(file_path) # calculate the current hash for the file 
                # if the hashes are not equal warning messages will appear on screen
                if current_hash != original_hash:
                    messagebox.showinfo("Integrity Check", f"File has been modified: {file_path}\n Original Hash: {original_hash} \n, Current Hash: {current_hash}")
            else:
                messagebox.showinfo("Integrity Check", f"File not found: {file_path}")
        messagebox.showinfo("Integrity Check", "Check completed.")
    
    # save a list of documents and the respective hashes to a json file
    # this list will be used in the check_integrity function 
    # the respective hashes will be compared with the documents current hashes
    def save_list(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json")
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(self.monitored_files, f, indent=4) # save a list of file paths and their hashes
    
    #load files from selected json file
    def load_list(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")]) # will only open json files
        if file_path:
            with open(file_path, 'r') as f:
                self.monitored_files = json.load(f)
            self.update_listbox()
                      
if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityMonitor(root)
    root.mainloop()



