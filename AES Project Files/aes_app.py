
import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto_engine import encrypt_file, decrypt_file


#  Color palette 
BG_DARK      = "#0d1117"
BG_CARD      = "#161b22"
BG_INPUT     = "#21262d"
ACCENT_BLUE  = "#1f6feb"
ACCENT_GREEN = "#238636"
ACCENT_RED   = "#da3633"
ACCENT_GOLD  = "#d29922"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
BORDER       = "#30363d"


class Tooltip:
    """Simple hover tooltip."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x, y, *_ = self.widget.bbox("insert") if hasattr(self.widget, "bbox") else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 30
        y += self.widget.winfo_rooty() + 20
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(self.tip, text=self.text, background="#2d333b",
                       foreground=TEXT_MUTED, relief="flat", borderwidth=1,
                       font=("Consolas", 9), padx=6, pady=3)
        lbl.pack()

    def hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class AESApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("AES File Encryption Software  •  Saud Hussain")
        self.geometry("820x680")
        self.resizable(False, False)
        self.configure(bg=BG_DARK)

        # State
        self.selected_file = tk.StringVar()
        self.password_var  = tk.StringVar()
        self.confirm_var   = tk.StringVar()
        self.show_pass     = tk.BooleanVar(value=False)
        self.mode          = tk.StringVar(value="encrypt")  # "encrypt" | "decrypt"
        self.strength_var  = tk.StringVar(value="")

        self._build_ui()

    #  UI BUILD 

    def _build_ui(self):
        self._header()
        self._mode_tabs()
        self._file_section()
        self._password_section()
        self._action_section()
        self._log_section()
        self._footer()

    def _header(self):
        hdr = tk.Frame(self, bg=BG_DARK, pady=18)
        hdr.pack(fill="x", padx=30)

        # Shield icon (unicode) + title
        tk.Label(hdr, text="🔐", font=("Segoe UI Emoji", 32),
                 bg=BG_DARK, fg=ACCENT_BLUE).pack(side="left")

        title_frame = tk.Frame(hdr, bg=BG_DARK)
        title_frame.pack(side="left", padx=14)
        tk.Label(title_frame, text="AES File Encryption Software",
                 font=("Segoe UI", 18, "bold"),
                 bg=BG_DARK, fg=TEXT_PRIMARY).pack(anchor="w")
        tk.Label(title_frame,
                 text="AES-256-CBC  •  PBKDF2-SHA256 Key Derivation  •  Information Security Lab",
                 font=("Segoe UI", 9), bg=BG_DARK, fg=TEXT_MUTED).pack(anchor="w")

        # Student badge (top-right)
        # badge = tk.Frame(hdr, bg=BG_CARD, padx=12, pady=6)
        # badge.pack(side="right")
        # tk.Label(badge, text="Saud Hussain", font=("Segoe UI", 9, "bold"),
        #          bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="e")
        # tk.Label(badge, text="Roll: 0000948599", font=("Segoe UI", 8),
        #          bg=BG_CARD, fg=TEXT_MUTED).pack(anchor="e")



        # Divider
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=30)

    def _mode_tabs(self):
        outer = tk.Frame(self, bg=BG_DARK, pady=16)
        outer.pack(fill="x", padx=30)

        tab_frame = tk.Frame(outer, bg=BG_CARD, pady=4, padx=4)
        tab_frame.pack(anchor="w")

        self.enc_btn = self._tab_btn(tab_frame, "🔒  Encrypt", "encrypt")
        self.enc_btn.pack(side="left")
        self.dec_btn = self._tab_btn(tab_frame, "🔓  Decrypt", "decrypt")
        self.dec_btn.pack(side="left")

        self._refresh_tabs()

    def _tab_btn(self, parent, text, mode_val):
        return tk.Button(parent, text=text, font=("Segoe UI", 10, "bold"),
                         bg=BG_CARD, fg=TEXT_MUTED,
                         relief="flat", padx=20, pady=7, cursor="hand2",
                         bd=0, activebackground=ACCENT_BLUE,
                         command=lambda: self._set_mode(mode_val))

    def _set_mode(self, m):
        self.mode.set(m)
        self._refresh_tabs()
        self._clear_log()
        # Hide confirm field for decrypt
        if m == "decrypt":
            self.confirm_row.pack_forget()
        else:
            self.confirm_row.pack(fill="x", pady=4)

    def _refresh_tabs(self):
        if self.mode.get() == "encrypt":
            self.enc_btn.configure(bg=ACCENT_BLUE, fg="white")
            self.dec_btn.configure(bg=BG_CARD, fg=TEXT_MUTED)
        else:
            self.dec_btn.configure(bg=ACCENT_BLUE, fg="white")
            self.enc_btn.configure(bg=BG_CARD, fg=TEXT_MUTED)

    # File selection 
    def _file_section(self):
        card = self._card("📁  File Selection")

        row = tk.Frame(card, bg=BG_CARD)
        row.pack(fill="x", pady=6)

        self.file_entry = tk.Entry(row, textvariable=self.selected_file,
                                   font=("Consolas", 10),
                                   bg=BG_INPUT, fg=TEXT_PRIMARY,
                                   insertbackground=TEXT_PRIMARY,
                                   relief="flat", bd=0,
                                   disabledbackground=BG_INPUT,
                                   disabledforeground=TEXT_MUTED)
        self.file_entry.pack(side="left", fill="x", expand=True,
                             ipady=8, ipadx=10)

        tk.Button(row, text="Browse…", font=("Segoe UI", 9, "bold"),
                  bg=ACCENT_BLUE, fg="white", relief="flat",
                  padx=14, pady=8, cursor="hand2", bd=0,
                  activebackground="#388bfd",
                  command=self._browse_file).pack(side="left", padx=(8, 0))

        self.file_info = tk.Label(card, text="No file selected.",
                                  font=("Segoe UI", 8), bg=BG_CARD, fg=TEXT_MUTED)
        self.file_info.pack(anchor="w")

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select File to Encrypt/Decrypt")
        if path:
            self.selected_file.set(path)
            size = os.path.getsize(path)
            self.file_info.configure(
                text=f"Size: {self._human_size(size)}   |   {os.path.basename(path)}",
                fg=TEXT_MUTED)

    # ── Password section ─────────────────────────────────────────────

    def _password_section(self):
        card = self._card("🔑  Password")

        # Password row
        pw_row = tk.Frame(card, bg=BG_CARD)
        pw_row.pack(fill="x", pady=4)
        tk.Label(pw_row, text="Password:", width=12, anchor="w",
                 font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_PRIMARY).pack(side="left")
        self.pw_entry = tk.Entry(pw_row, textvariable=self.password_var,
                                 show="•", font=("Consolas", 11),
                                 bg=BG_INPUT, fg=TEXT_PRIMARY,
                                 insertbackground=TEXT_PRIMARY,
                                 relief="flat", bd=0)
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)
        self.pw_entry.bind("<KeyRelease>", self._update_strength)

        # Confirm row (only for encrypt)
        self.confirm_row = tk.Frame(card, bg=BG_CARD)
        self.confirm_row.pack(fill="x", pady=4)
        tk.Label(self.confirm_row, text="Confirm:", width=12, anchor="w",
                 font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_PRIMARY).pack(side="left")
        self.confirm_entry = tk.Entry(self.confirm_row, textvariable=self.confirm_var,
                                      show="•", font=("Consolas", 11),
                                      bg=BG_INPUT, fg=TEXT_PRIMARY,
                                      insertbackground=TEXT_PRIMARY,
                                      relief="flat", bd=0)
        self.confirm_entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)

        # Show/hide toggle
        toggle_row = tk.Frame(card, bg=BG_CARD)
        toggle_row.pack(fill="x", pady=(4, 0))
        tk.Checkbutton(toggle_row, text="Show passwords",
                       variable=self.show_pass,
                       font=("Segoe UI", 9),
                       bg=BG_CARD, fg=TEXT_MUTED,
                       selectcolor=BG_INPUT,
                       activebackground=BG_CARD,
                       command=self._toggle_show).pack(side="left")

        # Strength meter
        self.strength_label = tk.Label(toggle_row, textvariable=self.strength_var,
                                       font=("Segoe UI", 9, "bold"),
                                       bg=BG_CARD, fg=ACCENT_GOLD)
        self.strength_label.pack(side="right")

        self.strength_bar = ttk.Progressbar(card, maximum=100, length=700,
                                            mode="determinate", style="Strength.Horizontal.TProgressbar")
        self.strength_bar.pack(fill="x", pady=(4, 0))
        self._style_progressbar()

    def _toggle_show(self):
        ch = "" if self.show_pass.get() else "•"
        self.pw_entry.configure(show=ch)
        self.confirm_entry.configure(show=ch)

    def _update_strength(self, _=None):
        pw = self.password_var.get()
        score = self._password_score(pw)
        self.strength_bar["value"] = score
        if score < 30:
            label, color = "Weak ⚠", ACCENT_RED
        elif score < 60:
            label, color = "Moderate ●", ACCENT_GOLD
        elif score < 85:
            label, color = "Strong ✓", ACCENT_GREEN
        else:
            label, color = "Very Strong ✓✓", "#56d364"
        self.strength_var.set(label)
        self.strength_label.configure(fg=color)

    @staticmethod
    def _password_score(pw):
        if not pw:
            return 0
        score = min(len(pw) * 4, 40)
        if any(c.isupper() for c in pw): score += 15
        if any(c.islower() for c in pw): score += 10
        if any(c.isdigit() for c in pw): score += 15
        if any(c in "!@#$%^&*()-_=+[]{}|;':\",./<>?" for c in pw): score += 20
        return min(score, 100)

    def _style_progressbar(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Strength.Horizontal.TProgressbar",
                        troughcolor=BG_INPUT, background=ACCENT_BLUE,
                        bordercolor=BORDER, lightcolor=ACCENT_BLUE,
                        darkcolor=ACCENT_BLUE, thickness=6)

    # ── Action section ───────────────────────────────────────────────

    def _action_section(self):
        card = self._card("")

        btn_row = tk.Frame(card, bg=BG_CARD)
        btn_row.pack(fill="x")

        self.action_btn = tk.Button(btn_row,
                                    text="🔒  Encrypt File",
                                    font=("Segoe UI", 12, "bold"),
                                    bg=ACCENT_GREEN, fg="white",
                                    relief="flat", padx=28, pady=12,
                                    cursor="hand2", bd=0,
                                    activebackground="#2ea043",
                                    command=self._start_action)
        self.action_btn.pack(side="left")
        Tooltip(self.action_btn, "Click to encrypt / decrypt the selected file")

        tk.Button(btn_row, text="✖  Clear",
                  font=("Segoe UI", 10),
                  bg=BG_INPUT, fg=TEXT_MUTED,
                  relief="flat", padx=16, pady=12,
                  cursor="hand2", bd=0,
                  command=self._clear_all).pack(side="left", padx=12)

        self.progress = ttk.Progressbar(card, maximum=100, mode="determinate",
                                        style="Strength.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(12, 0))
        self.status_lbl = tk.Label(card, text="Ready.",
                                   font=("Segoe UI", 9), bg=BG_CARD, fg=TEXT_MUTED)
        self.status_lbl.pack(anchor="w", pady=(4, 0))

        # Watch mode changes to update button label/color
        self.mode.trace_add("write", self._update_action_btn)
        self._update_action_btn()

    def _update_action_btn(self, *_):
        if self.mode.get() == "encrypt":
            self.action_btn.configure(text="🔒  Encrypt File", bg=ACCENT_GREEN)
        else:
            self.action_btn.configure(text="🔓  Decrypt File", bg=ACCENT_BLUE)

    # ── Log section ──────────────────────────────────────────────────

    def _log_section(self):
        card = self._card("📋  Activity Log")
        self.log = tk.Text(card, height=7, font=("Consolas", 9),
                           bg=BG_INPUT, fg=TEXT_PRIMARY,
                           insertbackground=TEXT_PRIMARY,
                           relief="flat", bd=0, state="disabled",
                           wrap="word", padx=10, pady=8)
        self.log.pack(fill="both", expand=True)
        # Tag colors
        self.log.tag_configure("ok",      foreground=ACCENT_GREEN)
        self.log.tag_configure("error",   foreground=ACCENT_RED)
        self.log.tag_configure("info",    foreground=ACCENT_BLUE)
        self.log.tag_configure("warning", foreground=ACCENT_GOLD)
        self.log.tag_configure("muted",   foreground=TEXT_MUTED)

    def _footer(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(4, 0))
        ft = tk.Frame(self, bg=BG_DARK, pady=8)
        ft.pack(fill="x", padx=30)
        tk.Label(ft,
                 text="AES-256-CBC  •  PBKDF2-HMAC-SHA256 (200,000 iterations)  •  "
                      "Department of Computer Science  •  Information Security Lab",
                 font=("Segoe UI", 8), bg=BG_DARK, fg=TEXT_MUTED).pack()

    # ─────────────────────────── HELPERS ─────────────────────────────

    def _card(self, title):
        outer = tk.Frame(self, bg=BG_DARK)
        outer.pack(fill="x", padx=30, pady=6)
        card = tk.Frame(outer, bg=BG_CARD, padx=16, pady=12,
                        highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill="x")
        if title:
            tk.Label(card, text=title, font=("Segoe UI", 10, "bold"),
                     bg=BG_CARD, fg=TEXT_PRIMARY).pack(anchor="w", pady=(0, 8))
        return card

    def _log_write(self, text, tag="muted"):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _clear_all(self):
        self.selected_file.set("")
        self.password_var.set("")
        self.confirm_var.set("")
        self.file_info.configure(text="No file selected.")
        self.progress["value"] = 0
        self.strength_bar["value"] = 0
        self.strength_var.set("")
        self.status_lbl.configure(text="Ready.")
        self._clear_log()

    @staticmethod
    def _human_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    # ─────────────────────────── ACTION ──────────────────────────────

    def _start_action(self):
        path = self.selected_file.get().strip()
        pw   = self.password_var.get()
        conf = self.confirm_var.get()
        mode = self.mode.get()

        # Validation
        if not path:
            messagebox.showerror("No File", "Please select a file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("File Not Found", f"File not found:\n{path}")
            return
        if not pw:
            messagebox.showerror("No Password", "Please enter a password.")
            return
        if mode == "encrypt" and pw != conf:
            messagebox.showerror("Password Mismatch",
                                 "Passwords do not match. Please re-enter.")
            return
        if mode == "encrypt" and self._password_score(pw) < 20:
            if not messagebox.askyesno("Weak Password",
                                       "Your password is very weak.\n"
                                       "Continue anyway?"):
                return

        # Determine output path
        if mode == "encrypt":
            out_path = path + ".enc"
        else:
            # Remove .enc extension if present, else append _decrypted
            if path.endswith(".enc"):
                out_path = path[:-4]
            else:
                base, ext = os.path.splitext(path)
                out_path = base + "_decrypted" + ext

        # Warn if output exists
        if os.path.exists(out_path):
            if not messagebox.askyesno("File Exists",
                                       f"Output file already exists:\n{out_path}\n\nOverwrite?"):
                return

        self._run_in_thread(mode, path, out_path, pw)

    def _run_in_thread(self, mode, in_path, out_path, pw):
        """Run encryption/decryption in background thread."""
        self.action_btn.configure(state="disabled")
        self.progress["value"] = 0
        self._clear_log()
        self._log_write(f"Input  : {in_path}", "info")
        self._log_write(f"Output : {out_path}", "info")
        self._log_write(f"Mode   : {mode.upper()}  |  Algorithm: AES-256-CBC", "info")
        self._log_write("─" * 60, "muted")

        def update_progress(pct):
            self.progress["value"] = pct
            self.status_lbl.configure(text=f"Processing… {pct}%")
            self.update_idletasks()

        def task():
            try:
                if mode == "encrypt":
                    self._log_write("Deriving key with PBKDF2-HMAC-SHA256 (200,000 iterations)…", "muted")
                    result = encrypt_file(in_path, out_path, pw, update_progress)
                    self.progress["value"] = 100
                    self._log_write("Key derivation complete.", "muted")
                    self._log_write(f"Original size : {self._human_size(result['original_size'])}", "muted")
                    self._log_write("✓ Encryption successful!", "ok")
                    self._log_write(f"  Saved to: {out_path}", "ok")
                    self.status_lbl.configure(text="✓ Encryption complete!")
                else:
                    self._log_write("Verifying file header…", "muted")
                    result = decrypt_file(in_path, out_path, pw, update_progress)
                    self.progress["value"] = 100
                    self._log_write(f"Decrypted size: {self._human_size(result['decrypted_size'])}", "muted")
                    self._log_write("✓ Decryption successful!", "ok")
                    self._log_write(f"  Saved to: {out_path}", "ok")
                    self.status_lbl.configure(text="✓ Decryption complete!")

            except ValueError as e:
                self._log_write(f"✗ Error: {e}", "error")
                self.status_lbl.configure(text=f"✗ Failed: {e}")
                self.progress["value"] = 0
                messagebox.showerror("Operation Failed", str(e))
            except Exception as e:
                self._log_write(f"✗ Unexpected error: {e}", "error")
                self.status_lbl.configure(text="✗ Unexpected error.")
                messagebox.showerror("Error", str(e))
            finally:
                self.action_btn.configure(state="normal")

        threading.Thread(target=task, daemon=True).start()


# ─────────────────────────── Entry Point ─────────────────────────────

if __name__ == "__main__":
    app = AESApp()
    app.mainloop()
