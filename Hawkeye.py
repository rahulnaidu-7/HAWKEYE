import customtkinter as ctk
import yara
import os
import shutil
import threading
import datetime
import string
import subprocess
import platform
import psutil  # Required for killing processes: pip install psutil
from tkinter import filedialog, messagebox

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark") 
ctk.set_default_color_theme("blue")

# --- PALETTE (Your Custom Colors) ---
COLOR_BG = ("#FFFFFF", "#1a1a1a")
COLOR_SIDEBAR = ("#F1F2F4", "#111111")
COLOR_CARD = ("#EFEFEF", "#2b2b2b")
COLOR_TEXT = ("#1C1C1E", "#DCE4EE")
COLOR_TEXT_DIM = ("#8E8E93", "#9CA3AF")
COLOR_ACCENT = ("#007AFF", "#1f6aa5")
COLOR_SELECTED = ("#E3E3E5", "#3A3A3C")
COLOR_HOVER = ("#EAEAEA", "#252525")
COLOR_BORDER = ("#E5E5E5", "#404040")
COLOR_DANGER = "#C60202"
COLOR_SUCCESS = "#34C759"

APP_WIDTH = 1050
APP_HEIGHT = 750

# Directories
QUARANTINE_DIR = "quarantine"
CUSTOM_RULES_FILE = "user_rules.yar"

for p in [QUARANTINE_DIR]:
    if not os.path.exists(p): os.makedirs(p)

if not os.path.exists(CUSTOM_RULES_FILE):
    with open(CUSTOM_RULES_FILE, "w") as f: f.write("// Add your custom YARA rules here\n")

# --- CORE RULES ---
DEFAULT_RULES_SOURCE = """
import "pe"

rule Hawkeye_Self_Test {
    strings:
        $text_sig = "MALWARE_TEST_SIGNATURE"
    condition:
        $text_sig
}

rule EICAR_Test_File {
    strings:
        $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Webshell_PHP {
    strings:
        $php = "<?php"
        $cmd = "shell_exec"
    condition:
        $php and $cmd
}
"""

class HawkeyeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.show_splash()
        
        self.title("Hawkeye - YARA Malware Detector")
        self.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        
        # --- TITLE BAR LOGO FIX ---
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.ico")
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
        except Exception:
            pass 
        # --------------------------
        
        self.rules = None
        self.exclusions = []
        self.scan_running = False
        
        self.current_editor_file = os.path.abspath(CUSTOM_RULES_FILE) 
        
        self.layout_ui()
        self.after(500, self.reload_engine)

    # --- SPLASH ---
    def show_splash(self):
        splash = ctk.CTkToplevel(self)
        splash.title("")
        width, height = APP_WIDTH, APP_HEIGHT
        x = (self.winfo_screenwidth() - width) // 2
        y = (self.winfo_screenheight() - height) // 2
        splash.geometry(f"{width}x{height}+{x}+{y}")
        splash.overrideredirect(True)
        splash.attributes('-topmost', True)
        splash.attributes('-alpha', 0.0)

        bg = ctk.CTkFrame(splash, fg_color="#0F0F0F", corner_radius=0)
        bg.pack(fill="both", expand=True)
        center = ctk.CTkFrame(bg, fg_color="transparent")
        center.place(relx=0.5, rely=0.45, anchor="center")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(script_dir, "logo.png")
        if os.path.exists(logo_path):
            try:
                from PIL import Image
                pil_img = Image.open(logo_path)
                img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(140, 140))
                ctk.CTkLabel(center, image=img, text="").pack(pady=(0, 25))
            except: ctk.CTkLabel(center, text="🦅", font=("Arial", 100)).pack(pady=(0, 15))
        else: ctk.CTkLabel(center, text="🦅", font=("Arial", 100)).pack(pady=(0, 15))

        ctk.CTkLabel(center, text="HAWKEYE", font=("Impact", 70), text_color="#FFFFFF").pack(pady=(0, 5))
        ctk.CTkLabel(center, text="YARA based Malware Detector", font=("Helvetica", 14, "bold"), text_color=COLOR_ACCENT[1]).pack(pady=(0, 40))
        
        self.splash_prog = ctk.CTkProgressBar(center, width=400, height=6, progress_color=COLOR_ACCENT[1], fg_color="#333")
        self.splash_prog.set(0)
        self.splash_prog.pack()
        
        self.splash_stat = ctk.CTkLabel(center, text="Initializing...", font=("Consolas", 12), text_color="gray")
        self.splash_stat.pack(pady=(15, 0))

        def fade_in(a=0):
            a += 0.05
            splash.attributes('-alpha', a)
            if a < 1.0: self.after(15, lambda: fade_in(a))
            else: self.after(200, boot_seq)

        def boot_seq(s=0):
            steps = [(0.1, "Loading Core..."), (0.5, "Verifying Signatures..."), (1.0, "Ready.")]
            if s < len(steps):
                p, t = steps[s]
                self.splash_prog.set(p)
                self.splash_stat.configure(text=t)
                self.after(600, lambda: boot_seq(s+1))
            else: self.after(500, fade_out)

        def fade_out(a=1.0):
            a -= 0.05
            splash.attributes('-alpha', a)
            if a > 0: self.after(15, lambda: fade_out(a))
            else: splash.destroy(); self.deiconify()

        fade_in()

    # --- LAYOUT ---
    def layout_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Header Container
        t = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        t.pack(pady=(40, 30), padx=20, anchor="w")

        # --- LOGO & TITLE ROW ---
        # Create a frame to hold Text + Logo horizontally
        title_row = ctk.CTkFrame(t, fg_color="transparent")
        title_row.pack(anchor="w")

        # 1. HAWKEYE Text (Left)
        ctk.CTkLabel(title_row, text="HAWKEYE", font=("Helvetica", 20, "bold"), text_color=COLOR_TEXT).pack(side="left")

        # 2. Logo Logic (Right of Text)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(script_dir, "logo.png")
        
        if os.path.exists(logo_path):
            try:
                from PIL import Image
                pil_img = Image.open(logo_path)
                # Resize slightly smaller (28x28) to sit nicely next to text
                sidebar_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(28, 28))
                ctk.CTkLabel(title_row, image=sidebar_img, text="").pack(side="left", padx=(10, 0))
            except:
                ctk.CTkLabel(title_row, text="🦅", font=("Arial", 24)).pack(side="left", padx=(10, 0))
        else:
            ctk.CTkLabel(title_row, text="🦅", font=("Arial", 24)).pack(side="left", padx=(10, 0))
        # -----------------------------

        # Subtitle below
        ctk.CTkLabel(t, text="YARA Engine", font=("Helvetica", 11), text_color=COLOR_TEXT_DIM).pack(anchor="w")

        self.nav_buttons = {}
        btns = [("Scanner        🛡️", "scanner"),
                ("Editor            📝", "rules"), 
                ("Quarantine    ☣️", "quarantine"), 
                ("Exclusions     ⚙️", "settings")]
        for text, name in btns:
            btn = ctk.CTkButton(self.sidebar, text=text, command=lambda n=name: self.show_view(n),
                                fg_color="transparent", text_color=COLOR_TEXT, hover_color=COLOR_HOVER,
                                anchor="w", height=45, corner_radius=8, font=("Helvetica", 13))
            btn.pack(fill="x", pady=4, padx=15)
            self.nav_buttons[name] = btn

        bot = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bot.pack(side="bottom", fill="x", padx=20, pady=30)
        
        self.use_default_engine = ctk.BooleanVar(value=True)
        self.engine_switch = ctk.CTkSwitch(bot, text="Built-in Rules", command=self.reload_engine, 
                                           variable=self.use_default_engine, onvalue=True, offvalue=False, 
                                           progress_color=COLOR_ACCENT, font=("Helvetica", 12), text_color=COLOR_TEXT)
        self.engine_switch.pack(anchor="w", pady=(0, 15))

        self.theme_var = ctk.StringVar(value="Dark") 
        self.theme_switch = ctk.CTkSwitch(bot, text="Dark Mode", command=self.toggle_theme, 
                                          variable=self.theme_var, onvalue="Dark", offvalue="Light", 
                                          progress_color="#555", font=("Helvetica", 12), text_color=COLOR_TEXT)
        self.theme_switch.pack(anchor="w")

        self.lbl_status = ctk.CTkLabel(bot, text="● Loading...", text_color="gray", font=("Helvetica", 11))
        self.lbl_status.pack(anchor="w", pady=(20, 0))

        self.main_area = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_BG)
        self.main_area.grid(row=0, column=1, sticky="nsew")
        
        self.frames = {}
        self.create_scanner()
        self.create_rules()
        self.create_quarantine()
        self.create_settings()
        self.show_view("scanner")

    def toggle_theme(self): 
        mode = self.theme_var.get()
        if ctk.get_appearance_mode().lower() != mode.lower():
            ctk.set_appearance_mode(mode)
            self.log(f"Appearance switched to {mode} Mode", "info")

    def show_view(self, name):
        for f in self.frames.values(): f.pack_forget()
        self.frames[name].pack(fill="both", expand=True, padx=50, pady=50)
        for btn_name, btn in self.nav_buttons.items():
            btn.configure(fg_color=COLOR_SELECTED if btn_name == name else "transparent")

    # --- VIEWS ---
    def create_scanner(self):
        frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["scanner"] = frame
        ctk.CTkLabel(frame, text="System Scanner", font=("Helvetica", 32, "bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 10))
        
        card = ctk.CTkFrame(frame, fg_color=COLOR_CARD, corner_radius=15, border_width=1, border_color=COLOR_BORDER)
        card.pack(fill="x")
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(padx=30, pady=30, fill="x")

        btns = ctk.CTkFrame(inner, fg_color="transparent")
        btns.pack(side="left")
        
        # Scan Buttons
        self.btn_scan_file = ctk.CTkButton(btns, text="Scan File", command=self.scan_file, height=45, width=130, fg_color=COLOR_ACCENT, text_color="white")
        self.btn_scan_file.pack(side="left", padx=(0, 10))
        
        self.btn_scan_folder = ctk.CTkButton(btns, text="Scan Folder", command=self.scan_folder, height=45, width=130, fg_color="transparent", text_color=COLOR_ACCENT, border_width=2, border_color=COLOR_ACCENT)
        self.btn_scan_folder.pack(side="left", padx=(0, 10))
        
        self.btn_scan_system = ctk.CTkButton(btns, text="⚡ Full System", command=self.scan_full_system, height=45, width=160, fg_color="#8E44AD", text_color="white")
        self.btn_scan_system.pack(side="left")
        
        # Stop Button (Initially Disabled)
        self.btn_stop = ctk.CTkButton(btns, text=" Stop", command=self.stop_scan, height=45, width=100, fg_color= "#D91C1C" , text_color="white", state="disabled")
        self.btn_stop.pack(side="left", padx=(20, 0))

        self.lbl_main_status = ctk.CTkLabel(inner, text="Ready", font=("Helvetica", 16, "bold"), text_color=COLOR_SUCCESS)
        self.lbl_main_status.pack(side="right")

        ctk.CTkLabel(frame, text="Live Activity Log", font=("Helvetica", 14, "bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(30, 10))
        self.progress = ctk.CTkProgressBar(frame, height=8, progress_color=COLOR_ACCENT, fg_color=COLOR_BORDER)
        self.progress.set(0)
        self.progress.pack(fill="x")
        self.log_box = ctk.CTkTextbox(frame, fg_color=COLOR_CARD, text_color=COLOR_TEXT, border_color=COLOR_BORDER, border_width=1, font=("Consolas", 12))
        self.log_box.pack(fill="both", expand=True, pady=(10, 0))

    # --- IMPROVED EDITOR UI ---
    def create_rules(self):
        frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["rules"] = frame
        h = ctk.CTkFrame(frame, fg_color="transparent"); h.pack(fill="x", pady=(0, 10))
        
        title_box = ctk.CTkFrame(h, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(title_box, text="Rule Editor", font=("Helvetica", 28, "bold"), text_color=COLOR_TEXT).pack(anchor="w")
        self.lbl_editor_file = ctk.CTkLabel(title_box, text=f"Editing: {os.path.basename(self.current_editor_file)}", font=("Consolas", 12), text_color=COLOR_TEXT_DIM)
        self.lbl_editor_file.pack(anchor="w")
        
        ctrl = ctk.CTkFrame(h, fg_color="transparent"); ctrl.pack(side="right", anchor="e")
        ctk.CTkButton(ctrl, text="💾 Save", command=self.save_file, fg_color=COLOR_SUCCESS, width=70, text_color="white").pack(side="left", padx=5)
        ctk.CTkButton(ctrl, text="💾 Save As...", command=self.save_file_as, fg_color=COLOR_SUCCESS, width=90, text_color="white").pack(side="left", padx=5)
        ctk.CTkButton(ctrl, text="🆕 New", command=self.new_file, fg_color=COLOR_ACCENT, width=70, text_color="white").pack(side="left", padx=5)
        ctk.CTkButton(ctrl, text="📂 Open", command=self.open_file, fg_color=COLOR_ACCENT, width=70, text_color="white").pack(side="left", padx=5)
        ctk.CTkButton(ctrl, text="📁 Folder", command=self.open_rules_folder, fg_color="transparent", border_width=1, border_color=COLOR_ACCENT, text_color=COLOR_ACCENT, width=70).pack(side="left", padx=5)
        
        self.rule_text = ctk.CTkTextbox(frame, font=("Consolas", 13), wrap="none", fg_color=COLOR_CARD, text_color=COLOR_TEXT, corner_radius=10, border_color=COLOR_BORDER, border_width=1)
        self.rule_text.pack(fill="both", expand=True)
        self.load_editor_content(self.current_editor_file)

    def create_quarantine(self):
        frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["quarantine"] = frame
        h = ctk.CTkFrame(frame, fg_color="transparent"); h.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(h, text="Quarantine", font=("Helvetica", 28, "bold"), text_color=COLOR_TEXT).pack(side="left")
        ctk.CTkButton(h, text="Refresh", command=self.refresh_q, fg_color="transparent", border_width=1, border_color=COLOR_BORDER, text_color=COLOR_TEXT).pack(side="right")
        self.q_scroll = ctk.CTkScrollableFrame(frame, fg_color=COLOR_CARD, corner_radius=10)
        self.q_scroll.pack(fill="both", expand=True)

    def create_settings(self):
        frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.frames["settings"] = frame
        ctk.CTkLabel(frame, text="Exclusions", font=("Helvetica", 28, "bold"), text_color=COLOR_TEXT).pack(anchor="w", pady=(0, 20))
        self.excl_box = ctk.CTkTextbox(frame, height=200, fg_color=COLOR_CARD, text_color=COLOR_TEXT, corner_radius=10)
        self.excl_box.pack(fill="x", pady=(0, 10))
        ctk.CTkButton(frame, text="Add Folder", command=self.add_excl, fg_color=COLOR_ACCENT, text_color="white").pack(anchor="w")

    # --- LOGIC ---
    def stop_scan(self):
        if self.scan_running:
            self.scan_running = False
            self.log("Stopping scan...", "info")
            self.lbl_main_status.configure(text="Stopping...", text_color=COLOR_DANGER)
            self.btn_stop.configure(state="disabled")

    def scan_file(self):
        p = filedialog.askopenfilename()
        if p: self.run_scan_t([p])

    def scan_folder(self):
        d = filedialog.askdirectory()
        if d: 
            self.lbl_main_status.configure(text="Indexing...", text_color=COLOR_ACCENT)
            self.log("Indexing...", "info")
            self.scan_running = True
            self.btn_stop.configure(state="normal")
            threading.Thread(target=self.bg_ind, args=([d],), daemon=True).start()

    def scan_full_system(self):
        if not messagebox.askyesno("Confirm Full Scan", "Scan ALL drives?\nThis may take a long time."): return
        self.lbl_main_status.configure(text="Detecting Drives...", text_color=COLOR_ACCENT)
        drives = []
        if os.name == 'nt':
            for letter in string.ascii_uppercase:
                root = f"{letter}:\\"
                if os.path.exists(root): drives.append(root)
        else: drives.append("/")
        self.log(f"Starting Scan on: {', '.join(drives)}", "info")
        self.scan_running = True
        self.btn_stop.configure(state="normal")
        threading.Thread(target=self.bg_ind, args=(drives,), daemon=True).start()

    def bg_ind(self, paths):
        # Calculate app directory to protect source files
        # Normalize to handle case sensitivity on Windows and separators
        app_dir = os.path.normcase(os.path.normpath(os.path.dirname(os.path.abspath(__file__))))
        
        files_found = []
        for path in paths:
            if not self.scan_running: break 
            
            for root, dirs, filenames in os.walk(path):
                if not self.scan_running: break 
                
                # Normalize root for checks
                normalized_root = os.path.normcase(os.path.normpath(root))
                
                # Check exclusions
                is_excluded = False
                for excl in self.exclusions:
                    normalized_excl = os.path.normcase(os.path.normpath(excl))
                    if normalized_root == normalized_excl or normalized_root.startswith(normalized_excl + os.sep):
                        is_excluded = True
                        break
                
                if is_excluded:
                    dirs[:] = [] 
                    continue
                
                for f in filenames:
                    file_path = os.path.join(root, f)
                    
                    try:
                        abs_path = os.path.abspath(file_path)
                        # Normalize path for comparison
                        norm_abs_path = os.path.normcase(os.path.normpath(abs_path))
                        
                        # --- SAFETY CHECKS ---
                        # 1. Ignore YARA rule files
                        if f.endswith(".yar") or f.endswith(".yara"):
                            continue
                        
                        # 2. Ignore the running script itself
                        script_path = os.path.normcase(os.path.normpath(os.path.abspath(__file__)))
                        if norm_abs_path == script_path:
                            continue
                            
                        # 3. Ignore ALL .py files in the app directory and subdirectories (to protect source code)
                        file_dir = os.path.dirname(norm_abs_path)
                        
                        # Check if file is in app_dir OR a subdirectory of app_dir
                        is_in_app_dir = file_dir == app_dir or file_dir.startswith(app_dir + os.sep)
                        
                        if is_in_app_dir and f.endswith(".py"):
                            continue
                        # ---------------------
                        
                        files_found.append(file_path)
                    except Exception:
                        pass
        
        if not self.scan_running:
            self.log("Scan stopped by user.", "info")
            self.after(0, lambda: self.lbl_main_status.configure(text="Stopped", text_color=COLOR_DANGER))
            self.after(0, lambda: self.progress.set(0))
            return

        if not files_found:
            self.log("No files found or all files excluded.", "info")
            self.after(0, lambda: self.lbl_main_status.configure(text="Idle", text_color=COLOR_SUCCESS))
            self.after(0, lambda: self.btn_stop.configure(state="disabled"))
            return
        self.run_scan_t(files_found)

    def run_scan_t(self, fs):
        if not self.rules: messagebox.showwarning("Error", "No active engine rules."); return
        self.scan_running = True
        self.btn_stop.configure(state="normal") # Ensure enabled for file scan too
        threading.Thread(target=self.scan_logic, args=(fs,), daemon=True).start()

    def scan_logic(self, fs):
        tot = len(fs)
        thr = 0
        self.after(0, lambda: self.lbl_main_status.configure(text="Scanning...", text_color=COLOR_ACCENT))
        for i, f in enumerate(fs):
            if not self.scan_running: 
                self.after(0, lambda: self.lbl_main_status.configure(text="Stopped", text_color=COLOR_DANGER))
                self.log("Scan stopped by user.", "info")
                break
            
            if i % 10 == 0 or i == 0: p = (i+1)/tot; self.after(0, lambda prog=p: self.progress.set(prog))
            try:
                matches = self.rules.match(f)
                if matches:
                    thr += 1; self.neutralize_threat(f)
                    self.after(0, lambda msg=f"[THREAT] {f} ({matches[0].rule})": self.log(msg, "threat"))
                else:
                    self.after(0, lambda msg=f"[CLEAN]  {f}": self.log(msg, "clean"))
            except: self.after(0, lambda msg=f"[ERROR]  {f}": self.log(msg, "info"))
        
        if self.scan_running: # Only show finished if not stopped
            self.after(0, lambda: self.lbl_main_status.configure(text="Scan Finished", text_color=COLOR_SUCCESS))
            self.after(0, lambda: self.progress.set(1.0))
            if thr > 0: self.after(0, lambda: messagebox.showwarning("Scan Complete", f"Found {thr} threats!")); self.after(0, self.refresh_q)
            else: self.after(0, lambda: messagebox.showinfo("Scan Complete", "System is Clean."))
        
        self.scan_running = False
        self.after(0, lambda: self.btn_stop.configure(state="disabled"))

    def log(self, m, type="normal"):
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        full_msg = f"[{timestamp}] {m}\n"
        if hasattr(self, 'log_box'):
            self.log_box.configure(state="normal")
            tag = "normal"
            if type == "threat": tag = "threat"; self.log_box.tag_config("threat", foreground=COLOR_DANGER)
            elif type == "clean": tag = "clean"; color = "#27ae60" if ctk.get_appearance_mode()=="Light" else "#2ecc71"; self.log_box.tag_config("clean", foreground=color)
            self.log_box.insert("end", full_msg, tag)
            self.log_box.see("end")
            self.log_box.configure(state="disabled")

    def reload_engine(self):
        use_def = self.use_default_engine.get()
        custom = ""
        self.log(f"Reloading Engine (Source: {'Default' if use_def else 'Custom'})...", "info")
        if os.path.exists(CUSTOM_RULES_FILE):
            with open(CUSTOM_RULES_FILE, "r") as f: custom = f.read()
        src = (DEFAULT_RULES_SOURCE + "\n" + custom) if use_def else custom
        if not use_def and not custom.strip(): 
            self.rules = None
            self.lbl_status.configure(text="● No Rules", text_color=COLOR_DANGER)
            self.log("Engine failed: No rules found.", "threat")
            return
        try:
            self.rules = yara.compile(source=src)
            txt = "Standard" if use_def else "Custom"
            self.lbl_status.configure(text=f"● Active ({txt})", text_color=COLOR_SUCCESS)
            self.log(f"Engine Online. Ruleset: {txt}", "clean")
        except yara.Error as e:
            self.lbl_status.configure(text="● Error", text_color=COLOR_DANGER)
            messagebox.showerror("Engine Error", f"{e}")
            self.log(f"Engine compilation error: {e}", "threat")

    # --- EDITOR LOGIC ---
    def load_editor_content(self, filepath):
        if os.path.exists(filepath):
            try:
                try:
                    with open(filepath, "r", encoding="utf-8") as f: content = f.read()
                except UnicodeDecodeError:
                    with open(filepath, "r", encoding="latin-1") as f: content = f.read()
                self.rule_text.configure(state="normal")
                self.rule_text.delete("0.0", "end") 
                self.rule_text.insert("0.0", content) 
                self.rule_text.see("0.0")
                self.current_editor_file = filepath
                self.lbl_editor_file.configure(text=f"Editing: {os.path.basename(filepath)}")
                self.log(f"Editor opened: {os.path.basename(filepath)}", "info")
            except Exception as e:
                messagebox.showerror("Read Error", f"Could not read file:\n{e}")

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("YARA Rules", "*.yar *.yara"), ("Text Files", "*.txt"), ("All Files", "*.*")])
        if path: self.load_editor_content(path)

    def new_file(self):
        if messagebox.askyesno("New File", "Are you sure? This will clear the current editor."):
            self.rule_text.configure(state="normal")
            self.rule_text.delete("0.0", "end")
            self.current_editor_file = "untitled.yar" 
            self.lbl_editor_file.configure(text="Editing: Untitled.yar")
            self.log("Editor cleared for new file.", "info")

    def open_rules_folder(self):
        path = os.getcwd()
        try:
            if platform.system() == "Windows": os.startfile(path)
            elif platform.system() == "Darwin": subprocess.Popen(["open", path])
            else: subprocess.Popen(["xdg-open", path])
            self.log("Opened rules folder in Explorer", "info")
        except Exception as e: self.log(f"Failed to open folder: {e}", "info")

    def save_file(self):
        if self.current_editor_file == "untitled.yar": self.save_file_as(); return
        try:
            with open(self.current_editor_file, "w", encoding="utf-8") as f:
                f.write(self.rule_text.get("0.0", "end-1c")) 
            self.log(f"Saved file: {os.path.basename(self.current_editor_file)}", "info")
            if os.path.abspath(self.current_editor_file) == os.path.abspath(CUSTOM_RULES_FILE):
                self.reload_engine()
                messagebox.showinfo("Saved", "Rules updated and Engine reloaded.")
            else: messagebox.showinfo("Saved", f"Changes saved to {os.path.basename(self.current_editor_file)}")
        except Exception as e: messagebox.showerror("Save Error", f"Could not save file:\n{e}")

    def save_file_as(self):
        path = filedialog.asksaveasfilename(defaultextension=".yar", filetypes=[("YARA Rules", "*.yar"), ("Text Files", "*.txt")])
        if path:
            self.current_editor_file = path
            self.lbl_editor_file.configure(text=f"Editing: {os.path.basename(path)}")
            self.save_file()

    def add_excl(self):
        d = filedialog.askdirectory()
        if d:
            # FIX: Normalize path before adding
            normalized_d = os.path.normpath(d)
            self.exclusions.append(normalized_d)
            self.excl_box.insert("end", f"{normalized_d}\n")

    def refresh_q(self):
        for w in self.q_scroll.winfo_children(): w.destroy()
        files = os.listdir(QUARANTINE_DIR)
        if not files: ctk.CTkLabel(self.q_scroll, text="No items found.", text_color="gray").pack(pady=20); return
        for f in files:
            r = ctk.CTkFrame(self.q_scroll, fg_color="transparent", corner_radius=8, border_color=COLOR_BORDER, border_width=1)
            r.pack(fill="x", pady=4, padx=5)
            ctk.CTkLabel(r, text=f, text_color=COLOR_TEXT, font=("Helvetica", 13)).pack(side="left", padx=15)
            ctk.CTkButton(r, text="Delete", width=70, fg_color=COLOR_DANGER, text_color="white", command=lambda x=f: self.q_del(x)).pack(side="right", padx=5, pady=5)
            ctk.CTkButton(r, text="Restore", width=70, fg_color=COLOR_SUCCESS, text_color="white", command=lambda x=f: self.q_rest(x)).pack(side="right", padx=5, pady=5)

    def q_del(self, f):
        try: os.chmod(os.path.join(QUARANTINE_DIR, f), 0o777); os.remove(os.path.join(QUARANTINE_DIR, f)); self.refresh_q()
        except: pass
    def q_rest(self, f):
        try: dst = filedialog.asksaveasfilename(initialfile=f)
        except: pass
        if dst: os.chmod(os.path.join(QUARANTINE_DIR, f), 0o777); shutil.move(os.path.join(QUARANTINE_DIR, f), dst); self.refresh_q()

    # --- NEUTRALIZE THREAT ---
    def neutralize_threat(self, file_path):
        """
        1. Checks if the file is running (by name) and kills it.
        2. Renames file to .vir to break file association.
        3. Moves to quarantine.
        4. Locks permissions (sets to read-only for all).
        """
        try:
            filename = os.path.basename(file_path)
            
            # 1. KILL PROCESS
            for proc in psutil.process_iter(['name', 'exe']):
                try:
                    # Check if the process name matches the file OR if the full path matches
                    if proc.info['name'] == filename or proc.info['exe'] == file_path:
                        self.log(f"Killing active process: {proc.info['name']}", "info")
                        proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # 2. RENAME & MOVE (Quarantine)
            # We rename it to .vir so Windows cannot accidentally run it
            new_name = filename + ".vir"
            dest = os.path.join(QUARANTINE_DIR, new_name)
            
            # Move the file
            shutil.move(file_path, dest)
            
            # 3. LOCK PERMISSIONS (Remove Write/Execute)
            # 0o444 = Read only for everyone (Owner, Group, Others)
            os.chmod(dest, 0o444)
            
        except Exception as e:
            self.log(f"Failed to neutralize {file_path}: {e}", "info")

if __name__ == "__main__":
    app = HawkeyeApp()
    app.mainloop()