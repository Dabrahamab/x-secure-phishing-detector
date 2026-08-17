import re
import smtplib
import threading
import time
import tkinter as tk
from email.message import EmailMessage
from tkinter import ttk, scrolledtext, messagebox, filedialog

from PIL import Image, ImageTk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from phishing_system import PhishingTakedownSystem


class PhishingDetectorGUI:
    def __init__(self, root, phishing_system):
        self.root = root
        self.system = phishing_system
        self.current_results = []
        self.animation_running = False
        self.dashboard_data = {
            'total_analyzed': 0,
            'phishing_count': 0,
            'suspicious_count': 0,
            'safe_count': 0,
            'takedowns_sent': 0,
            'success_rate': 0
        }
        self.stats_labels = {}
        self.setup_gui()

    def _normalize_urls(self, raw_text):
        urls = []
        for line in str(raw_text or "").splitlines():
            candidate = line.strip()
            if candidate and not candidate.startswith("#"):
                urls.append(candidate)
        return urls

    def _classify_score(self, score):
        if score > 0.4:
            return "Phishing"
        if score > 0.2:
            return "Suspicious"
        return "Safe"

    def _detect_fraud_type(self, url, score):
        normalized = url.lower()
        if "ponzi" in normalized or "pyramid" in normalized or "scam" in normalized:
            return "Ponzi Scheme"
        if score > 0.7:
            return "High-Risk Phishing"
        if score > 0.4:
            return "Phishing"
        if score > 0.2:
            return "Suspicious"
        return "Safe"

    def _is_valid_email(self, email):
        if not email:
            return False
        return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}", email)) and any(
            email.lower().endswith(tld) for tld in (".com", ".org", ".net")
        )

    def _send_requester_notification(self, requester_email, target_sites):
        smtp_config = {
            "smtp_server": self.smtp_entries["SMTP Server:"].get(),
            "smtp_port": int(self.smtp_entries["Port:"].get()),
            "username": self.smtp_entries["Username:"].get(),
            "password": self.smtp_entries["Password:"].get(),
            "from_email": self.smtp_entries["From Email:"].get(),
        }

        message = EmailMessage()
        message["Subject"] = "Phishing takedown request submitted"
        message["From"] = smtp_config["from_email"]
        message["To"] = requester_email

        body_lines = [
            "Your takedown request has been submitted to the host providers.",
            "They will review the reported URLs and follow up as appropriate.",
            "",
            "Reported URLs:",
        ]

        for item in target_sites:
            body_lines.append(
                f"- {item.url} ({self._detect_fraud_type(item.url, float(item.similarity_score))}, "
                f"suspicious {round(float(item.similarity_score) * 100, 1)}%, safe {round((1.0 - float(item.similarity_score)) * 100, 1)}%)"
            )

        body_lines.extend(["", "Thank you for reporting this content."])
        message.set_content("\n".join(body_lines))

        try:
            with smtplib.SMTP(smtp_config["smtp_server"], smtp_config["smtp_port"]) as smtp:
                smtp.starttls()
                smtp.login(smtp_config["username"], smtp_config["password"])
                smtp.send_message(message)
            return True
        except Exception:
            return False

    def setup_gui(self):
        # Main window configuration
        # 1. Change True to False so Minimize/Exit buttons appear
        self.root.overrideredirect(False)

        # 2. Set the window title for the taskbar
        self.root.title("d_abX.secure - Phish Guard AI")

        # 3. Ensure the window can be resized/minimized
        self.root.resizable(True, True)
        self.root.geometry("1200x800")

        # Header frame with gradient
        header_frame = tk.Frame(self.root, bg="#f5f5f5", height=120)
        header_frame.pack(fill="x", padx=0, pady=0)

        # Add logo and title
        # Placeholder for actual logo
        self.logo_img = self.load_image("logo.png", (80, 80))
        logo_label = tk.Label(header_frame, image=self.logo_img, bg="#f5f5f5")
        logo_label.image = self.logo_img
        logo_label.pack(side="left", padx=20, pady=10)

        title_frame = tk.Frame(header_frame, bg="#f5f5f5")
        title_frame.pack(side="left", fill="y", expand=True)

        title_label = tk.Label(
            title_frame,
            text="d.abX_secure",
            font=("Montserrat", 28, "bold"),
            bg="#f5f5f5",
            fg="#2c3e50"
        )
        title_label.pack(anchor="w", pady=(20, 0))

        subtitle_label = tk.Label(
            title_frame,
            text="Advanced Phishing Detection & Takedown System",
            font=("Montserrat", 12),
            bg="#f5f5f5",
            fg="#7f8c8d"
        )
        subtitle_label.pack(anchor="w")

        # Stats bar
        self.stats_bar = tk.Frame(header_frame, bg="#3498db", height=40)
        self.stats_bar.pack(side="right", padx=20, pady=10, fill="y")

        stats = [
            ("Total Analyzed", "0", "#3498db"),
            ("Phishing", "0", "#e74c3c"),
            ("Suspicious", "0", "#f39c12"),
            ("Safe", "0", "#2ecc71"),
            ("Takedowns", "0", "#9b59b6")
        ]

        for text, value, color in stats:
            frame = tk.Frame(self.stats_bar, bg=color, padx=10, pady=5)
            frame.pack(side="left", padx=5)

            tk.Label(frame, text=text, bg=color, fg="white",
                     font=("Montserrat", 9)).pack()
            self.stats_labels[text] = tk.Label(
                frame, text=value, bg=color, fg="white", font=("Montserrat", 11, "bold"))
            self.stats_labels[text].pack()

        # Main content frame
        main_frame = tk.Frame(self.root, bg="#ecf0f1")
        main_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Left panel (input)
        left_panel = tk.Frame(main_frame, bg="#ffffff", width=400, bd=0, highlightthickness=0,
                              relief="solid", padx=15, pady=15)
        left_panel.pack(side="left", fill="y", padx=(0, 10), pady=5)

        # URL input section
        input_frame = tk.LabelFrame(left_panel, text="URL Analysis", bg="#ffffff", fg="#2c3e50",
                                    font=("Montserrat", 12, "bold"), bd=1, relief="solid")
        input_frame.pack(fill="x", padx=0, pady=(0, 15))

        tk.Label(input_frame, text="Enter URL(s) to analyze (one per line):", bg="#ffffff",
                 font=("Montserrat", 10)).pack(anchor="w", padx=5, pady=(5, 2))

        self.url_entry = tk.Text(input_frame, height=8, width=50, wrap="word", font=("Montserrat", 10),
                                 bd=1, relief="solid", padx=10, pady=10)
        self.url_entry.pack(fill="x", padx=5, pady=5)

        # File upload button
        upload_btn = tk.Button(input_frame, text="Upload URL List", command=self.upload_urls,
                               bg="#3498db", fg="white", font=("Montserrat", 10, "bold"),
                               relief="flat", padx=10, pady=5, bd=0)
        upload_btn.pack(fill="x", padx=5, pady=(0, 5))

        # SMTP configuration (collapsible)
        self.smtp_frame = tk.LabelFrame(left_panel, text="SMTP Configuration (Optional)", bg="#ffffff",
                                        fg="#2c3e50", font=("Montserrat", 12, "bold"), bd=1, relief="solid")
        self.smtp_frame.pack(fill="x", padx=0, pady=(0, 15))

        self.smtp_toggle = tk.Button(self.smtp_frame, text="▲", command=self.toggle_smtp,
                                     bg="#ffffff", fg="#2c3e50", font=("Montserrat", 8), bd=0)
        self.smtp_toggle.pack(anchor="e", padx=5, pady=0)

        self.smtp_content = tk.Frame(self.smtp_frame, bg="#ffffff")
        self.smtp_content.pack(fill="x", padx=5, pady=5)

        fields = [
            ("SMTP Server:", "smtp.gmail.com"),
            ("Port:", "587"),
            ("Username:", ""),
            ("Password:", ""),
            ("From Email:", ""),
            ("Requester Email:", "")
        ]

        self.smtp_entries = {}
        for label, default in fields:
            frame = tk.Frame(self.smtp_content, bg="#ffffff")
            frame.pack(fill="x", padx=5, pady=2)

            tk.Label(frame, text=label, bg="#ffffff", font=(
                "Montserrat", 9)).pack(side="left", padx=5)

            entry = tk.Entry(frame, font=("Montserrat", 10),
                             bd=1, relief="solid")
            entry.pack(fill="x", expand=True)
            entry.insert(0, default)

            if "Password" in label:
                entry.config(show="*")

            self.smtp_entries[label] = entry

        # Action buttons
        button_frame = tk.Frame(left_panel, bg="#ffffff")
        button_frame.pack(fill="x", padx=0, pady=(0, 15))

        analyze_btn = tk.Button(
            button_frame,
            text="Analyze URLs",
            command=self.start_analysis,
            bg="#2ecc71",
            fg="white",
            font=("Montserrat", 12, "bold"),
            relief="flat",
            padx=20,
            pady=10,
            bd=0,
            activebackground="#27ae60"
        )
        analyze_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))

        takedown_btn = tk.Button(
            button_frame,
            text="Send Takedown",
            command=self.send_takedown,
            bg="#e74c3c",
            fg="white",
            font=("Montserrat", 12, "bold"),
            relief="flat",
            padx=20,
            pady=10,
            bd=0,
            activebackground="#c0392b"
        )
        takedown_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))

        # Progress section
        progress_frame = tk.LabelFrame(left_panel, text="Progress", bg="#ffffff", fg="#2c3e50",
                                       font=("Montserrat", 12, "bold"), bd=1, relief="solid")
        progress_frame.pack(fill="x", padx=0, pady=0)

        self.progress_label = tk.Label(progress_frame, text="Ready", bg="#ffffff", fg="#7f8c8d",
                                       font=("Montserrat", 10))
        self.progress_label.pack(anchor="w", padx=5, pady=(5, 2))

        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate",
                                            style="custom.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x", padx=5, pady=(0, 5))

        # Right panel (results)
        right_panel = tk.Frame(main_frame, bg="#ecf0f1")
        right_panel.pack(side="right", fill="both",
                         expand=True, padx=0, pady=5)

        # Results notebook with modern style
        style = ttk.Style()
        style.configure("TNotebook", background="#ecf0f1", borderwidth=0)
        style.configure("TNotebook.Tab", background="#bdc3c7", foreground="#2c3e50",
                        font=("Montserrat", 10, "bold"), padding=[15, 5], borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", "#ffffff")],
                  foreground=[("selected", "#2c3e50")])

        self.results_notebook = ttk.Notebook(right_panel)
        self.results_notebook.pack(fill="both", expand=True)

        # Analysis tab
        analysis_tab = tk.Frame(self.results_notebook, bg="#ffffff")
        self.results_notebook.add(analysis_tab, text="Analysis Results")

        self.results_text = scrolledtext.ScrolledText(
            analysis_tab,
            wrap="word",
            font=("Consolas", 10),
            bg="#ffffff",
            padx=15,
            pady=15,
            bd=0,
            highlightthickness=0

        )
        self.results_text.pack(fill="both", expand=True)

        # Dashboard tab
        dashboard_tab = tk.Frame(self.results_notebook, bg="#ffffff")
        self.results_notebook.add(dashboard_tab, text="Dashboard")

        # Create dashboard widgets
        self.create_dashboard(dashboard_tab)

        # Status bar
        self.status_bar = tk.Label(
            self.root,
            text="Ready",
            bd=0,
            relief="flat",
            anchor="w",
            bg="#2c3e50",
            fg="white",
            font=("Montserrat", 10),
            padx=15
        )
        self.status_bar.pack(fill="x", side="bottom")

        # Configure custom styles
        self.configure_styles()

        # Start animation loop
        self.animate_stats()

    def toggle_smtp(self):
        if self.smtp_content.winfo_ismapped():
            self.smtp_content.pack_forget()
            self.smtp_toggle.config(text="▼")
        else:
            self.smtp_content.pack(fill="x", padx=5, pady=5)
            self.smtp_toggle.config(text="▲")

    def configure_styles(self):
        style = ttk.Style()

        # Configure progress bar style
        style.theme_use('clam')
        style.configure("custom.Horizontal.TProgressbar",
                        thickness=15,
                        troughcolor="#ecf0f1",
                        troughrelief="flat",
                        background="#3498db",
                        lightcolor="#3498db",
                        darkcolor="#2980b9",
                        bordercolor="#ecf0f1")

        # Configure button styles
        style.configure("TButton",
                        font=("Montserrat", 10),
                        padding=6,
                        relief="flat",
                        background="#3498db",
                        foreground="white")

        style.map("TButton",
                  background=[("active", "#2980b9")],
                  foreground=[("active", "white")])

    def create_dashboard(self, parent):
        # Main dashboard frame
        dashboard_frame = tk.Frame(parent, bg="#ffffff")
        dashboard_frame.pack(fill="both", expand=True, padx=15, pady=15)

        # Top row - Summary cards
        summary_frame = tk.Frame(dashboard_frame, bg="#ffffff")
        summary_frame.pack(fill="x", pady=(0, 15))

        summary_cards = [
            ("Total Analyzed", "0", "#3498db", "database"),
            ("Phishing", "0", "#e74c3c", "shield-off"),
            ("Suspicious", "0", "#f39c12", "alert-triangle"),
            ("Safe", "0", "#2ecc71", "shield"),
            ("Takedowns", "0", "#9b59b6", "send")
        ]

        for title, value, color, icon in summary_cards:
            card = tk.Frame(summary_frame, bg=color, bd=0, highlightthickness=0,
                            relief="solid", padx=15, pady=10)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))

            # Icon placeholder (would use actual icons in production)
            icon_label = tk.Label(card, text="⬤", bg=color, fg="white",
                                  font=("Montserrat", 14))
            icon_label.pack(anchor="w")

            tk.Label(card, text=title, bg=color, fg="white",
                     font=("Montserrat", 10)).pack(anchor="w")

            value_label = tk.Label(card, text=value, bg=color, fg="white",
                                   font=("Montserrat", 18, "bold"))
            value_label.pack(anchor="w", pady=(5, 0))

            # Store reference to update later
            self.stats_labels[title] = value_label

        # Middle row - Charts
        chart_frame = tk.Frame(dashboard_frame, bg="#ffffff")
        chart_frame.pack(fill="both", expand=True, pady=(0, 15))

        # Left chart - Detection results
        left_chart_frame = tk.Frame(
            chart_frame, bg="#ffffff", bd=1, relief="solid")
        left_chart_frame.pack(side="left", fill="both",
                              expand=True, padx=(0, 10))

        tk.Label(left_chart_frame, text="Detection Results", bg="#ffffff",
                 font=("Montserrat", 11, "bold")).pack(pady=10)

        self.detection_chart = self.create_pie_chart(left_chart_frame)

        # Right chart - Takedown success
        right_chart_frame = tk.Frame(
            chart_frame, bg="#ffffff", bd=1, relief="solid")
        right_chart_frame.pack(side="right", fill="both", expand=True)

        tk.Label(right_chart_frame, text="Takedown Success Rate", bg="#ffffff",
                 font=("Montserrat", 11, "bold")).pack(pady=10)

        self.success_chart = self.create_gauge_chart(right_chart_frame)

        # Bottom row - Recent activity
        activity_frame = tk.Frame(
            dashboard_frame, bg="#ffffff", bd=1, relief="solid")
        activity_frame.pack(fill="both", expand=True)

        tk.Label(activity_frame, text="Recent Activity", bg="#ffffff",
                 font=("Montserrat", 11, "bold")).pack(pady=10)

        self.activity_text = scrolledtext.ScrolledText(
            activity_frame,
            wrap="word",
            font=("Montserrat", 9),
            bg="#ffffff",
            padx=10,
            pady=10,
            height=8,
            bd=0,
            highlightthickness=0
        )
        self.activity_text.pack(
            fill="both", expand=True, padx=10, pady=(0, 10))

    def create_pie_chart(self, parent):
        fig = Figure(figsize=(4, 3), dpi=80, facecolor='none')
        ax = fig.add_subplot(111)

        # Initial empty pie chart
        ax.pie([1], labels=['No Data'], colors=['#ecf0f1'], startangle=90)
        # Equal aspect ratio ensures that pie is drawn as a circle
        ax.axis('equal')

        canvas = FigureCanvasTkAgg(fig, master=parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

        return fig, ax

    def create_gauge_chart(self, parent):
        fig = Figure(figsize=(4, 3), dpi=80, facecolor='none')
        ax = fig.add_subplot(111, polar=True)

        # Initial empty gauge
        ax.set_axis_off()
        ax.text(0.5, 0.5, 'No Data', ha='center',
                va='center', transform=ax.transAxes)

        canvas = FigureCanvasTkAgg(fig, master=parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

        return fig, ax

    def update_pie_chart(self, phishing, suspicious, safe):
        fig, ax = self.detection_chart

        # Clear previous chart
        ax.clear()

        if phishing + suspicious + safe == 0:
            ax.pie([1], labels=['No Data'], colors=['#ecf0f1'], startangle=90)
        else:
            sizes = [phishing, suspicious, safe]
            labels = ['Phishing', 'Suspicious', 'Safe']
            colors = ['#e74c3c', '#f39c12', '#2ecc71']

            # Plot
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                   startangle=90, wedgeprops={'linewidth': 1, 'edgecolor': 'white'})
            ax.axis('equal')

        fig.canvas.draw()

    def update_gauge_chart(self, success_rate):
        fig, ax = self.success_chart

        # Clear previous chart
        ax.clear()

        # Gauge parameters
        if success_rate == 0:
            ax.set_axis_off()
            ax.text(0.5, 0.5, 'No Data', ha='center',
                    va='center', transform=ax.transAxes)
            fig.canvas.draw()
            return

        max_value = 100
        value = success_rate * 100

        # Create gauge
        ax.set_theta_zero_location('N')
        ax.set_theta_direction(-1)

        # Draw the outline
        x = [0, 0.5 * 3.14159, 3.14159, 1.5 * 3.14159, 2 * 3.14159]
        y = [0, 0.5, 0.5, 0.5, 0]
        ax.fill(x, y, color='#ecf0f1', alpha=0.3)

        # Draw the filled part based on value
        filled_angle = (value / max_value) * 3.14159
        x_filled = [0, filled_angle, filled_angle, 0, 0]
        y_filled = [0, 0.5, 0.5, 0, 0]
        ax.fill(x_filled, y_filled, color='#3498db')

        # Remove axis elements
        ax.set_xticklabels([])
        ax.set_yticklabels([])
        ax.grid(False)

        # Add value text
        ax.text(0, 0.2, f"{value:.1f}%", ha='center', va='center',
                fontsize=14, fontweight='bold')

        fig.canvas.draw()

    def animate_stats(self):
        if self.animation_running:
            return

        self.animation_running = True

        # Animate each stat with a counting effect
        for stat in self.stats_labels:
            target_value = int(self.dashboard_data.get(
                stat.lower().replace(" ", "_"), 0))
            current_value = int(self.stats_labels[stat].cget("text"))

            if current_value < target_value:
                new_value = min(
                    current_value + max(1, target_value // 20), target_value)
                self.stats_labels[stat].config(text=str(new_value))
                self.root.after(20, self.animate_stats)
                return
            elif current_value > target_value:
                new_value = max(
                    current_value - max(1, current_value // 20), target_value)
                self.stats_labels[stat].config(text=str(new_value))
                self.root.after(20, self.animate_stats)
                return

        self.animation_running = False

    def load_image(self, path, size):
        try:
            # Attempts to open your logo.png from the folder
            from PIL import Image, ImageTk
            img = Image.open(path)
            img = img.resize(size, Image.Resampling.LANCZOS)
            return ImageTk.PhotoImage(img)
        except Exception as e:
            # If the logo is missing, it shows a blue circle instead of crashing
            print(f"Error loading logo: {e}")
            return ImageTk.PhotoImage(Image.new('RGB', size, '#3498db'))

    def upload_urls(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    urls = f.read()
                    self.url_entry.delete("1.0", "end")
                    self.url_entry.insert("1.0", urls)
                    self.status_bar.config(
                        text=f"Loaded URLs from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")

    def start_analysis(self):
        urls = self._normalize_urls(self.url_entry.get("1.0", "end"))

        if not urls:
            messagebox.showerror(
                "Error", "Please enter at least one URL to analyze")
            return

        self.progress_bar["value"] = 0
        self.progress_label.config(text="Starting analysis...")
        self.status_bar.config(text="Analyzing URLs...")
        self.results_text.delete("1.0", "end")

        # Disable buttons during analysis
        self.toggle_buttons(False)

        # Run analysis in a separate thread
        analysis_thread = threading.Thread(
            target=self.run_analysis,
            args=(urls,),
            daemon=True
        )
        analysis_thread.start()

    def run_analysis(self, urls):
        try:
            self.current_results = []
            total_urls = len(urls)

            for i, url in enumerate(urls):
                self.update_progress(f"Analyzing {url}...", (i/total_urls)*100)

                try:
                    site = self.system.analyze_url(url)
                    if site:
                        self.current_results.append(site)

                        result_text = f"""
{'='*80}
URL: {site.url}
Domain: {site.domain}
IP Address: {site.ip_address}
Target Brand: {site.target_brand}
Similarity Score: {site.similarity_score:.2f}
Hosting Provider: {site.hosting_provider}
Registrar: {site.registrar}
Creation Date: {site.creation_date}
Expiration Date: {site.expiration_date}
Nameservers: {', '.join(site.nameservers)}
Abuse Contacts: {', '.join(site.abuse_contacts)}
Status: {'✅ Phishing detected!' if site.similarity_score > 0.4 else '⚠️ Suspicious' if site.similarity_score > 0.2 else '❌ Not phishing'}
"""
                        self.append_result(result_text)

                        # Update dashboard data
                        if site.similarity_score > 0.4:
                            self.dashboard_data['phishing_count'] += 1
                        elif site.similarity_score > 0.2:
                            self.dashboard_data['suspicious_count'] += 1
                        else:
                            self.dashboard_data['safe_count'] += 1

                        self.dashboard_data['total_analyzed'] += 1

                        # Update dashboard
                        self.update_dashboard()
                except Exception as e:
                    error_msg = f"Error analyzing {url}: {str(e)}"
                    self.append_result(error_msg)
                    self.append_activity(f"Analysis failed for {url}")

            self.update_progress("Analysis complete!", 100)
            self.status_bar.config(text="Analysis complete")
            self.append_activity(f"Analysis completed for {len(urls)} URLs")

        finally:
            # Re-enable buttons
            self.root.after(0, lambda: self.toggle_buttons(True))

    def send_takedown(self):
        if not self.current_results:
            messagebox.showerror(
                "Error", "No analysis results available. Please analyze URLs first.")
            return

        smtp_config = {
            'smtp_server': self.smtp_entries["SMTP Server:"].get(),
            'smtp_port': int(self.smtp_entries["Port:"].get()),
            'username': self.smtp_entries["Username:"].get(),
            'password': self.smtp_entries["Password:"].get(),
            'from_email': self.smtp_entries["From Email:"].get()
        }

        requester_email = self.smtp_entries["Requester Email:"].get().strip()

        # Validate SMTP config
        if not all(smtp_config.values()):
            messagebox.showerror(
                "Error", "Please complete all SMTP configuration fields")
            return

        if requester_email and not self._is_valid_email(requester_email):
            messagebox.showerror(
                "Error", "Please provide a valid requester email ending with .com, .org, or .net.")
            return

        # Confirm before sending
        if not messagebox.askyesno("Confirm", "Send takedown requests to all abuse contacts?"):
            return

        # Disable buttons during sending
        self.toggle_buttons(False)

        self.progress_bar["value"] = 0
        self.progress_label.config(text="Preparing takedown requests...")
        self.status_bar.config(text="Sending takedown requests...")

        # Run in separate thread
        takedown_thread = threading.Thread(
            target=self.run_takedown,
            args=(smtp_config, requester_email),
            daemon=True
        )
        takedown_thread.start()

    def run_takedown(self, smtp_config, requester_email=""):
        try:
            total_sites = len(self.current_results)
            success_count = 0
            target_sites = []

            for i, site in enumerate(self.current_results):
                if site.similarity_score > 0.4:  # Only send for confirmed phishing
                    target_sites.append(site)
                    self.update_progress(
                        f"Sending takedown for {site.domain}...", (i/total_sites)*100)

                    try:
                        if not hasattr(site, 'evidence_path') or not site.evidence_path:
                            evidence_path = self.system.collect_evidence(site)
                            site.evidence_path = evidence_path

                        self.system.save_to_database(site, site.evidence_path)

                        if self.system.send_takedown_request(site, smtp_config):
                            success_count += 1
                            self.append_result(
                                f"\n✅ Takedown request sent for {site.url}\n")
                            self.append_activity(
                                f"Takedown sent for {site.url}")
                        else:
                            self.append_result(
                                f"\n❌ Failed to send takedown for {site.url}\n")
                            self.append_activity(
                                f"Takedown failed for {site.url}")
                    except Exception as e:
                        self.append_result(
                            f"\n⚠️ Error processing {site.url}: {str(e)}\n")
                        self.append_activity(
                            f"Error processing {site.url}: {str(e)}")

            if requester_email:
                notification_sent = self._send_requester_notification(
                    requester_email, target_sites)
                self.append_activity(
                    f"Requester notification sent: {'yes' if notification_sent else 'no'}")

            self.dashboard_data['takedowns_sent'] += success_count
            if total_sites > 0:
                self.dashboard_data['success_rate'] = success_count / total_sites

            self.update_progress(
                f"Sent {success_count} takedown requests", 100)
            self.status_bar.config(
                text=f"Sent {success_count} takedown requests")
            self.append_activity(
                f"Takedown process completed - {success_count} successful")

            self.update_dashboard()

        finally:
            self.root.after(0, lambda: self.toggle_buttons(True))

    def update_dashboard(self):
        # Update stats labels
        self.animate_stats()

        # Update pie chart
        self.update_pie_chart(
            self.dashboard_data['phishing_count'],
            self.dashboard_data['suspicious_count'],
            self.dashboard_data['safe_count']
        )

        # Update gauge chart
        self.update_gauge_chart(self.dashboard_data.get('success_rate', 0))

    def update_progress(self, message, value):
        self.root.after(0, lambda: self._update_progress(message, value))

    def _update_progress(self, message, value):
        self.progress_label.config(text=message)
        self.progress_bar["value"] = value
        self.status_bar.config(text=message)
        self.root.update_idletasks()

    def append_result(self, text):
        self.root.after(0, lambda: self._append_result(text))

    def _append_result(self, text):
        self.results_text.insert("end", text)
        self.results_text.see("end")
        self.root.update_idletasks()

    def append_activity(self, text):
        self.root.after(0, lambda: self._append_activity(text))

    def _append_activity(self, text):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.activity_text.insert("end", f"[{timestamp}] {text}\n")
        self.activity_text.see("end")
        self.root.update_idletasks()

    def toggle_buttons(self, enable):
        state = "normal" if enable else "disabled"

        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Button):
                widget.config(state=state)


# Main application
if __name__ == "__main__":
    root = tk.Tk()

    # Initialize the phishing system
    phishing_system = PhishingTakedownSystem()

    # Create and run the GUI
    app = PhishingDetectorGUI(root, phishing_system)
    root.mainloop()
