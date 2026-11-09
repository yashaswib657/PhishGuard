
import tkinter as tk
from tkinter import messagebox

from detector import analyze_email
from database import create_database, save_analysis, get_history


# COLOUR PALETTE
BG = "#F7F6F1"
WHITE = "#FFFFFF"
DARK = "#292B28"
MUTED = "#85877F"
GREEN = "#829985"
GREEN_DARK = "#526D59"
PALE_GREEN = "#E8EEE7"
YELLOW = "#F4EACB"
BORDER = "#EAE9E2"
RED = "#B96860"

FONT = "Arial"
HEADING = "Georgia"


create_database()

root = tk.Tk()
root.title("PhishGuard | Email Security Workspace")
root.geometry("1150x780")
root.minsize(950, 680)
root.configure(bg=BG)

current_page = None


# ---------------- NAVIGATION ----------------

sidebar = tk.Frame(root, bg=WHITE, width=220)
sidebar.pack(side="left", fill="y")
sidebar.pack_propagate(False)

content = tk.Frame(root, bg=BG)
content.pack(side="left", fill="both", expand=True)


def clear_content():
    for widget in content.winfo_children():
        widget.destroy()


def nav_button(label, command):
    button = tk.Label(
        sidebar,
        text=label,
        bg=WHITE,
        fg=DARK,
        font=(FONT, 11),
        anchor="w",
        padx=18,
        pady=13,
        cursor="hand2"
    )

    button.pack(fill="x", padx=12, pady=2)

    button.bind(
        "<Button-1>",
        lambda event: command()
    )

    button.bind(
        "<Enter>",
        lambda event: button.config(bg=PALE_GREEN)
    )

    button.bind(
        "<Leave>",
        lambda event: button.config(bg=WHITE)
    )

# Sidebar brand
tk.Label(
    sidebar,
    text="phishguard.",
    bg=WHITE,
    fg=GREEN_DARK,
    font=(HEADING, 22, "bold")
).pack(anchor="w", padx=23, pady=(35, 5))

tk.Label(
    sidebar,
    text="EMAIL SECURITY WORKSPACE",
    bg=WHITE,
    fg=MUTED,
    font=(FONT, 8, "bold")
).pack(anchor="w", padx=24, pady=(0, 35))

tk.Label(
    sidebar,
    text="WORKSPACE",
    bg=WHITE,
    fg=MUTED,
    font=(FONT, 9, "bold")
).pack(anchor="w", padx=24, pady=(0, 10))




# ---------------- HELPERS ----------------

def make_label(parent, text, size=11, color=DARK, bold=False, font=FONT):
    return tk.Label(
        parent,
        text=text,
        bg=parent.cget("bg"),
        fg=color,
        font=(font, size, "bold" if bold else "normal")
    )


def make_card(parent, padding=20):
    return tk.Frame(
        parent,
        bg=WHITE,
        padx=padding,
        pady=padding,
        highlightbackground=BORDER,
        highlightthickness=1
    )


def heading(parent, text, size=25):
    return tk.Label(
        parent,
        text=text,
        bg=BG,
        fg=DARK,
        font=(HEADING, size)
    )


def get_statistics():
    records = get_history()
    total = len(records)
    suspicious = sum(1 for r in records if r[3] == "SUSPICIOUS")
    high = sum(1 for r in records if r[3] == "HIGH RISK")
    return total, suspicious, high

def show_risk_popup(risk, score, findings):

    overlay = tk.Frame(root, bg="#F7F6F1")
    overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
    overlay.lift()

    if risk == "LOW RISK":
        color = "#27804B"
        badge_bg = "#E2F0E5"
        status = "No suspicious phrases detected"

    elif risk == "SUSPICIOUS":
        color = "#A87919"
        badge_bg = "#F8EECF"
        status = "Some suspicious indicators were found"

    else:
        color = "#B84444"
        badge_bg = "#F5E3E0"
        status = "Multiple suspicious indicators were found"

    # Alert card
    card = tk.Frame(
        overlay,
        bg="#FFFFFF",
        padx=35,
        pady=30,
        highlightbackground="#EAE9E2",
        highlightthickness=1
    )
    card.place(relx=0.5, rely=0.5, anchor="center", width=440)

    # Small label
    tk.Label(
        card,
        text="PHISHGUARD  /  SECURITY REPORT",
        bg="#FFFFFF",
        fg="#85877F",
        font=("Arial", 9, "bold")
    ).pack(anchor="w", pady=(0, 22))

    # Risk status
    tk.Label(
        card,
        text=risk,
        bg="#FFFFFF",
        fg=color,
        font=("Georgia", 27, "bold")
    ).pack(anchor="w")

    # Score
    tk.Label(
        card,
        text=f"{score} / 100",
        bg="#FFFFFF",
        fg="#292B28",
        font=("Georgia", 21)
    ).pack(anchor="w", pady=(8, 12))

    # Status badge
    tk.Label(
        card,
        text=status,
        bg=badge_bg,
        fg=color,
        font=("Arial", 10),
        padx=12,
        pady=10
    ).pack(anchor="w", pady=(0, 20))

    # Findings
    tk.Label(
        card,
        text="DETECTION DETAILS",
        bg="#FFFFFF",
        fg="#85877F",
        font=("Arial", 9, "bold")
    ).pack(anchor="w", pady=(0, 8))

    for finding in findings:
        tk.Label(
            card,
            text="•  " + finding,
            bg="#FFFFFF",
            fg="#292B28",
            font=("Arial", 10),
            wraplength=350,
            justify="left"
        ).pack(anchor="w", pady=3)

    # Dismiss button
    tk.Button(
        card,
        text="Dismiss",
        command=overlay.destroy,
        bg="#E8EEE7",
        fg="#292B28",
        activebackground="#DCE7DB",
        activeforeground="#292B28",
        font=("Arial", 11, "bold"),
        relief="flat",
        cursor="hand2",
        padx=30,
        pady=11
    ).pack(fill="x", pady=(25, 0))



# ---------------- SCANNER ----------------


def show_scanner():
    clear_content()

    top = tk.Frame(content, bg=BG)
    top.pack(fill="x", padx=40, pady=(35, 20))

    make_label(top, "EMAIL SECURITY / SCANNER", 9, MUTED, True).pack(anchor="w")
    heading(top, "Email scanner", 27).pack(anchor="w", pady=(8, 5))
    make_label(
        top,
        "Inspect an email for potentially suspicious phrases.",
        11, MUTED
    ).pack(anchor="w")

    card = make_card(content, 25)
    card.pack(fill="both", expand=True, padx=40, pady=10)

    tk.Label(
        card,
        text="Email content",
        bg=WHITE,
        fg=DARK,
        font=(FONT, 13, "bold")
    ).pack(anchor="w")

    tk.Label(
        card,
        text="Paste the email you want to inspect below.",
        bg=WHITE,
        fg=MUTED,
        font=(FONT, 10)
    ).pack(anchor="w", pady=(5, 15))

    email_box = tk.Text(
        card,
        height=9,
        bg="#FAFAF7",
        fg=DARK,
        insertbackground=GREEN_DARK,
        font=(FONT, 11),
        relief="flat",
        padx=15,
        pady=15,
        wrap="word",
        highlightbackground=BORDER,
        highlightthickness=1
    )
    email_box.pack(fill="x")

    result_area = tk.Frame(card, bg=WHITE)
    result_area.pack(fill="both", expand=True, pady=20)

    tk.Label(
        result_area,
        text="ANALYSIS RESULT",
        bg=WHITE,
        fg=MUTED,
        font=(FONT, 9, "bold")
    ).pack(anchor="w")

    result_label = tk.Label(
        result_area,
        text="Awaiting analysis",
        bg=WHITE,
        fg=GREEN_DARK,
        font=(HEADING, 22)
    )
    result_label.pack(anchor="w", pady=10)

    details = tk.Label(
        result_area,
        text="Your detection findings will appear here.",
        bg=WHITE,
        fg=MUTED,
        font=(FONT, 10),
        justify="left",
        anchor="w"
    )
    details.pack(anchor="w", pady=5)

    def run_analysis():
        email = email_box.get("1.0", "end-1c").strip()

        if not email:
            messagebox.showwarning("Empty email", "Please paste an email first.")
            return

        result = analyze_email(email)
        save_analysis(email, result)

        risk = result["risk"]
        color = GREEN_DARK

        if risk == "SUSPICIOUS":
            color = "#A17B35"
        elif risk == "HIGH RISK":
            color = RED

        result_label.config(
            text=f"{risk}     {result['score']}/100",
            fg=color
        )

        details.config(
            text="\n".join("•  " + item for item in result["findings"]),
            fg=DARK
        )
        show_risk_popup(risk, result["score"], result["findings"])

    tk.Button(
        card,
        text="Analyze email  →",
        command=run_analysis,
        bg=GREEN_DARK,
        fg="#292B28",
        activebackground=GREEN,
        activeforeground=WHITE,
        font=(FONT, 11, "bold"),
        relief="flat",
        cursor="hand2",
        pady=13
    ).pack(fill="x", pady=(15, 0))


# ---------------- HISTORY ----------------

def show_history():
    clear_content()

    top = tk.Frame(content, bg=BG)
    top.pack(fill="x", padx=40, pady=(35, 20))

    make_label(top, "WORKSPACE / RECORDS", 9, MUTED, True).pack(anchor="w")
    heading(top, "Recent scans", 27).pack(anchor="w", pady=(8, 5))
    make_label(top, "Review your previously analysed emails.", 11, MUTED).pack(anchor="w")

    records = get_history()

    card = make_card(content, 22)
    card.pack(fill="both", expand=True, padx=40, pady=10)

    history_box = tk.Text(
        card,
        bg=WHITE,
        fg=DARK,
        font=(FONT, 10),
        relief="flat",
        padx=10,
        pady=10,
        wrap="word"
    )
    history_box.pack(fill="both", expand=True)

    if not records:
        history_box.insert("end", "No previous analyses found.")
    else:
        for record in reversed(records):
            history_box.insert(
                "end",
                f"EMAIL\n{record[1]}\n\n"
                f"SCORE      {record[2]}/100\n"
                f"RISK       {record[3]}\n\n"
                f"FINDINGS\n{record[4]}\n"
                f"{'─' * 55}\n\n"
            )

    history_box.config(state="disabled")


# ---------------- DASHBOARD ----------------

def show_dashboard():
    clear_content()

    top = tk.Frame(content, bg=BG)
    top.pack(fill="x", padx=40, pady=(35, 15))

    make_label(top, "MONDAY, YOUR SECURITY WORKSPACE", 9, MUTED, True).pack(anchor="w")

    heading(top, "Welcome to PhishGuard.", 29).pack(anchor="w", pady=(12, 5))

    make_label(
        top,
        "A clearer view of what's entering your inbox.",
        11, MUTED
    ).pack(anchor="w")

    total, suspicious, high = get_statistics()

    # Statistics
    stats = tk.Frame(content, bg=BG)
    stats.pack(fill="x", padx=40, pady=15)

    stat_items = [
        ("TOTAL SCANS", total, PALE_GREEN),
        ("SUSPICIOUS", suspicious, YELLOW),
        ("HIGH RISK", high, "#F4E4E0")
    ]

    for title, value, color in stat_items:
        box = tk.Frame(
            stats,
            bg=color,
            padx=18,
            pady=18,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        box.pack(side="left", fill="both", expand=True, padx=(0, 12))

        tk.Label(
            box,
            text=title,
            bg=color,
            fg=MUTED,
            font=(FONT, 9, "bold")
        ).pack(anchor="w")

        tk.Label(
            box,
            text=str(value),
            bg=color,
            fg=DARK,
            font=(HEADING, 27)
        ).pack(anchor="w", pady=(8, 0))

    # Main dashboard cards
    lower = tk.Frame(content, bg=BG)
    lower.pack(fill="both", expand=True, padx=40, pady=10)

    overview = make_card(lower, 22)
    overview.pack(side="left", fill="both", expand=True, padx=(0, 12))

    tk.Label(
        overview,
        text="Quick actions",
        bg=WHITE,
        fg=DARK,
        font=(HEADING, 19)
    ).pack(anchor="w", pady=(0, 12))

    tk.Label(
        overview,
        text="Start a new email security check.",
        bg=WHITE,
        fg=MUTED,
        font=(FONT, 10)
    ).pack(anchor="w", pady=(0, 20))

    tk.Button(
        overview,
        text="Open email scanner  →",
        command=show_scanner,
        bg=GREEN_DARK,
        fg="#292B28",
        activebackground=GREEN,
        activeforeground=WHITE,
        relief="flat",
        font=(FONT, 10, "bold"),
        cursor="hand2",
        pady=12
    ).pack(fill="x",pady=(15,0))

    tk.Label(
        overview,
        text="Detection insights",
        bg=WHITE,
        fg=DARK,
        font=(HEADING, 17)
    ).pack(anchor="w", pady=(30, 10))

    tk.Label(
        overview,
        text="PhishGuard currently uses rule-based keyword matching. A higher score indicates more matching phrases.",
        bg=WHITE,
        fg=MUTED,
        font=(FONT, 10),
        wraplength=300,
        justify="left"
    ).pack(anchor="w")

    recent = make_card(lower, 22)
    recent.pack(side="left", fill="both", expand=True)

    tk.Label(
        recent,
        text="Recent activity",
        bg=WHITE,
        fg=DARK,
        font=(HEADING, 19)
    ).pack(anchor="w", pady=(0, 15))

    records = get_history()

    if not records:
        tk.Label(
            recent,
            text="No scans yet.\nYour recent activity will appear here.",
            bg=WHITE,
            fg=MUTED,
            font=(FONT, 10),
            justify="left"
        ).pack(anchor="w")
    else:
        for record in reversed(records[-4:]):
            risk_color = GREEN_DARK

            if record[3] == "SUSPICIOUS":
                risk_color = "#A17B35"
            elif record[3] == "HIGH RISK":
                risk_color = RED

            tk.Label(
                recent,
                text=f"{record[3]}     {record[2]}/100",
                bg=WHITE,
                fg=risk_color,
                font=(FONT, 10, "bold")
            ).pack(anchor="w", pady=(5, 2))

            tk.Label(
                recent,
                text=record[1][:45] + ("..." if len(record[1]) > 45 else ""),
                bg=WHITE,
                fg=MUTED,
                font=(FONT, 9),
                wraplength=280,
                justify="left"
            ).pack(anchor="w", pady=(0, 8))

    tk.Label(
        content,
        text="PHISHGUARD     •     EDUCATIONAL CYBERSECURITY PROJECT",
        bg=BG,
        fg=MUTED,
        font=(FONT, 8)
    ).pack(pady=15)


# Sidebar navigation
nav_button("⌂    Dashboard", show_dashboard)
nav_button("✉    Email scanner", show_scanner)
nav_button("◷    Scan history", show_history)

tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=20, pady=25)

tk.Label(
    sidebar,
    text="ABOUT",
    bg=WHITE,
    fg=MUTED,
    font=(FONT, 9, "bold")
).pack(anchor="w", padx=24, pady=5)

tk.Label(
    sidebar,
    text="Version 2.0\nEducational use only",
    bg=WHITE,
    fg=MUTED,
    font=(FONT, 9),
    justify="left"
).pack(anchor="w", padx=24, pady=5)

show_dashboard()

print("PhishGuard workspace started.")

root.mainloop()
