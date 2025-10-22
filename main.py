import customtkinter as ctk
from tkinter import messagebox
from db import (get_login_data, store_password, database_exists,
                delete_login, change_master_password, backup_database, load_theme_preference,
                save_theme_preference, load_appear_preference, save_appear_preference,
                save_username, load_username, delete_master_user, edit_login, get_user_salt, reset_attempts,
                get_category, get_login_info, toggle_favorite, open_for_user, increment_attempts,
                bootstrap_first_user, init_meta_db, create_user)
from pwhandler import password_strength, gen_set_password, toggle_password_visibility, copy_to_clipboard
from encryption import derive_key

user_theme = load_theme_preference()
ctk.set_default_color_theme(user_theme)

user_appear = load_appear_preference()
ctk.set_appearance_mode(user_appear)

app = ctk.CTk()
app.geometry("400x543")
app.title("Cypher")

#
def entry_screen():
    if database_exists():
        login_screen()
    else:
        welcome_screen()

# Clears all widgets from the tkinter container
def clear_screen(name):
    for widget in name.winfo_children():
        widget.destroy()

# Displays login GUI and handles user authentication flow
def login_screen():
    clear_screen(app)
    app.geometry("370x500")

    details_frame = ctk.CTkFrame(app, fg_color="transparent")
    details_frame.pack(pady=5, padx=20, fill='both', expand=True)

    header_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
    header_frame.pack(pady=(20, 10), padx=10, fill='x')

    ctk.CTkLabel(header_frame,
                 text="Cypher Login",
                 font=("Tahoma", 24, "bold"),
                 text_color="#FFFFFF").pack(side="left")

    login_card = ctk.CTkFrame(details_frame,
                              corner_radius=15,
                              border_width=1,
                              border_color="#3C3C3C")
    login_card.pack(pady=20, padx=20, fill='both', expand=True)

    entry_frame = ctk.CTkFrame(login_card, fg_color="transparent")
    entry_frame.pack(pady=10, padx=20, fill='x')

    # Username section
    username_label = ctk.CTkLabel(entry_frame,
                                  text="Username",
                                  font=("Tahoma", 14),
                                  text_color="#A0A0A0")
    username_label.pack(pady=(0, 5), anchor='w')

    username_entry = ctk.CTkEntry(entry_frame,
                                  width=300,
                                  height=40,
                                  corner_radius=10,
                                  border_width=1,
                                  border_color="#3C3C3C",
                                  fg_color="#1F1F1F",
                                  text_color="white")
    username_entry.pack(pady=(0, 15))

    # Password section
    password_label = ctk.CTkLabel(entry_frame,
                                  text="Password",
                                  font=("Tahoma", 14),
                                  text_color="#A0A0A0")
    password_label.pack(pady=(0, 5), anchor='w')

    password_entry = ctk.CTkEntry(entry_frame, width=300, height=40, show="*", corner_radius=10, border_width=1, border_color="#3C3C3C", fg_color="#1F1F1F", text_color="white")
    password_entry.pack(pady=(0, 15))

    remember_var = ctk.StringVar(value="off")
    remember_me_checkbox = ctk.CTkCheckBox(entry_frame,
                                           text="Remember Me",
                                           font=("Tahoma", 12),
                                           checkbox_width=20,
                                           checkbox_height=20,
                                           variable=remember_var,
                                           onvalue="on",
                                           offvalue="off",
                                           text_color="#A0A0A0")
    remember_me_checkbox.pack(pady=(0, 20))

    # Login button
    login_button = ctk.CTkButton(entry_frame,
                                 text="Log In",
                                 font=("Tahoma", 16, "bold"),
                                 corner_radius=10,
                                 height = 40, command = lambda: attempt_login())
    login_button.pack(fill='x', pady=(0, 10))

    # Attempts login locally and via Supabase, handles session setup
    def attempt_login():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        allowed = get_login_info(username)
        if not allowed:
            messagebox.showerror(
                "Too many attempts.",
                "Your account is temporarily locked.")
            return

        try:
            conn, dek, user_id = open_for_user(username, password)
        except ValueError as e:
            increment_attempts(username)
            messagebox.showerror("Login Failed", str(e))
            return

        # success path
        reset_attempts(username)
        salt = get_user_salt(username)
        encryption_key = derive_key(password, salt)

        # After commit & close, proceed to main UI
        save_username(remember_var, username)
        password_entry.delete(0, "end")
        app.withdraw()
        cypher(user_id, encryption_key, conn, dek)

    load_username(remember_var, username_entry)
    username_entry.bind("<Return>", lambda event: attempt_login())
    password_entry.bind("<Return>", lambda event: attempt_login())

# Displays registration GUI and handles new user sign-ups
def register_screen():
    clear_screen(app)
    register_frame = ctk.CTkFrame(app, fg_color="transparent")
    register_frame.pack(pady=20, padx=20, fill='both', expand=True)

    # Header
    header_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
    header_frame.pack(pady=(5, 5), padx=10, fill='x')

    ctk.CTkLabel(header_frame, text="Create Account", font=("Tahoma", 24, "bold"), text_color="#FFFFFF").pack(side="left")

    # Card container
    registration_card = ctk.CTkFrame(register_frame, corner_radius=15, border_width=1,border_color="#3C3C3C")
    registration_card.pack(pady=20, padx=20, fill='both', expand=True)

    # Main content frame
    content_frame = ctk.CTkFrame(registration_card, fg_color="transparent")
    content_frame.pack(pady=10, padx=20, fill='both', expand=True)

    # Username section
    username_label = ctk.CTkLabel(content_frame, text="Username", font=("Tahoma", 14), text_color="#A0A0A0")
    username_label.pack(pady=(0, 5), anchor='w')

    username_container = ctk.CTkFrame(content_frame, fg_color="transparent")
    username_container.pack(fill='x')

    username_entry = ctk.CTkEntry(username_container, width= 235, height=40, corner_radius=10,  border_width=1, border_color="#3C3C3C", fg_color="#1F1F1F", text_color="white")
    username_entry.pack(side = "left", pady=(0, 15), padx = (0,5))

    # Password section
    password_var = ctk.StringVar()
    password_label = ctk.CTkLabel(content_frame,
                                  text="Password",
                                  font=("Tahoma", 14),
                                  text_color="#A0A0A0")
    password_label.pack(pady=(0, 5), anchor='w')

    # Password entry with toggle visibility container
    password_container = ctk.CTkFrame(content_frame, fg_color="transparent")
    password_container.pack(fill='x')

    password_entry = ctk.CTkEntry(password_container,
                                  width=235,
                                  height=40,
                                  corner_radius=10,
                                  border_width=1,
                                  border_color="#3C3C3C",
                                  fg_color="#1F1F1F",
                                  text_color="white",
                                  show="*",
                                  textvariable=password_var)
    password_entry.pack(side='left', pady=(0, 15), padx=(0, 5))

    # Password visibility toggle
    toggle_button = ctk.CTkButton(password_container, text="👁", font=("Arial", 16), fg_color="transparent", width=30, height=40, hover_color="gray", command=lambda: toggle_password_visibility(password_entry, password_confirm_entry))
    toggle_button.pack(side='left', pady=(0, 10))

    # Confirm Password section
    password_confirm_var = ctk.StringVar()
    confirm_password_label = ctk.CTkLabel(content_frame, text="Confirm Password", font=("Tahoma", 14), text_color="#A0A0A0")
    confirm_password_label.pack(pady=(0, 5), anchor='w')

    # Confirm password entry with toggle visibility container
    confirm_password_container = ctk.CTkFrame(content_frame, fg_color="transparent")
    confirm_password_container.pack(fill='x')

    password_confirm_entry = ctk.CTkEntry(confirm_password_container,
                                          width=235,
                                          height=40,
                                          corner_radius=10,
                                          border_width=1,
                                          border_color="#3C3C3C",
                                          fg_color="#1F1F1F",
                                          text_color="white",
                                          show="*",
                                          textvariable=password_confirm_var)
    password_confirm_entry.pack(side='left', pady=(0, 15), padx=(0, 5))

    # Strength bar frame
    strength_bar_frame = ctk.CTkFrame(content_frame,
                                      fg_color="transparent",
                                      width=300)
    strength_bar_frame.pack(fill='x', pady=(0, 10))

    strength_bar = ctk.CTkProgressBar(strength_bar_frame, width = 220)
    strength_bar.pack(side = "left", fill='x')
    strength_bar.set(0)
    strength_label = ctk.CTkLabel(strength_bar_frame, text = "Weak", text_color = "red", font = ("Tahoma", 12))
    strength_label.pack(side = "left", padx = 10)

    password_entry.bind("<KeyRelease>", lambda event: password_strength(password_var.get(), strength_label, strength_bar))

    # Register button
    register_button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    register_button_frame.pack(fill='x')
    register_button = ctk.CTkButton(register_button_frame,
                                    text="Register",
                                    font=("Tahoma", 16, "bold"),
                                    corner_radius=10,
                                    height=40, command = lambda: attempt_register())
    register_button.pack(fill='x', pady= 5)

    username_entry.bind("<Return>", lambda event: attempt_register())
    password_entry.bind("<Return>", lambda event: attempt_register())

    # Validates input, bootstraps first user, creates account locally, and returns to log in
    def attempt_register():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        password_confirm = password_confirm_entry.get().strip()

        if not username or not password or not password_confirm:
            messagebox.showerror("Error", "All fields must be filled.")
            return

        if password != password_confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        if len(username) < 4:
            messagebox.showerror("Error", "Username must be at least 4 characters long.")
            return
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return

        try:
            created = bootstrap_first_user(username, password)
        except RuntimeError:
            messagebox.showerror("Not Allowed", "A vault already exists on this machine.\nPlease log in first, then use the 'Add User' button in Cypher.")
            return
        except Exception as e:
            messagebox.showerror("Setup Error", f"Failed to register user:\n{e}")
            return

        if created:
            messagebox.showinfo("Success", "Master account created successfully!")
            login_screen()
        else:
            messagebox.showerror("Error", "Username already exists.")

# If no database exists on machine, display welcome screen
def welcome_screen():
    clear_screen(app)

    details_frame = ctk.CTkFrame(app, fg_color="transparent")
    details_frame.pack(pady=5, padx=20, fill='both', expand=True)

    header_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
    header_frame.pack(pady=(15,0), padx=10, fill='x')

    ctk.CTkLabel(header_frame,
                 text="Welcome to Cypher!",
                 font=("Tahoma", 26, "bold"),
                 text_color="#FFFFFF").pack()

    # App description
    description = ctk.CTkLabel(
        header_frame,
        text="Your secure password manager",
        font=("Tahoma", 14, "bold"),
        text_color="#FFFFFF"
    )
    description.pack(pady = (5,0))

    welcome_card = ctk.CTkFrame(details_frame,
                                corner_radius=15,
                                border_width=1,
                                border_color="#3C3C3C")
    welcome_card.pack(pady=20, padx=20, fill='both', expand=True)

    content_frame = ctk.CTkFrame(welcome_card, fg_color="transparent")
    content_frame.pack(pady=10, padx=20, fill='x')

    sub_description = ctk.CTkLabel(
        content_frame,
        text="Store, generate, and manage\nall your passwords in one secure place",
        font=("Tahoma", 14),
        text_color="#FFFFFF",
        wraplength=400,
        justify="center"
    )
    sub_description.pack(pady=(10, 15))

    # Features section with the same styling as your login form
    features_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    features_frame.pack(pady=(0,5), fill='x')

    # Feature 1
    feature1_frame = ctk.CTkFrame(features_frame, fg_color="#1F1F1F", corner_radius=10)
    feature1_frame.pack(pady=8, fill="x")

    feature1_inner = ctk.CTkFrame(feature1_frame, fg_color="transparent")
    feature1_inner.pack(padx=15, pady=15, fill="x")

    feature1_icon = ctk.CTkLabel(feature1_inner, text="🔐", font=("Tahoma", 20), width=30)
    feature1_icon.pack(side="left", padx=(0, 10))

    feature1_text = ctk.CTkLabel(
        feature1_inner,
        text="Encryption for all your passwords",
        font=("Tahoma", 13),
        text_color="#FFFFFF",
        anchor="w"
    )
    feature1_text.pack(side="left", fill="x")

    # Feature 2
    feature2_frame = ctk.CTkFrame(features_frame, fg_color="#1F1F1F", corner_radius=10)
    feature2_frame.pack(pady=8, fill="x")

    feature2_inner = ctk.CTkFrame(feature2_frame, fg_color="transparent")
    feature2_inner.pack(padx=15, pady=15, fill="x")

    feature2_icon = ctk.CTkLabel(feature2_inner, text="🔄", font=("Tahoma", 20), width=30)
    feature2_icon.pack(side="left", padx=(0, 10))

    feature2_text = ctk.CTkLabel(
        feature2_inner,
        text="Generate strong passwords instantly",
        font=("Tahoma", 13),
        text_color="#FFFFFF",
        anchor="w"
    )
    feature2_text.pack(side="left", fill="x")

    # Feature 3
    feature3_frame = ctk.CTkFrame(features_frame, fg_color="#1F1F1F", corner_radius=10)
    feature3_frame.pack(pady=8, fill="x")

    feature3_inner = ctk.CTkFrame(feature3_frame, fg_color="transparent")
    feature3_inner.pack(padx=15, pady=15, fill="x")

    feature3_icon = ctk.CTkLabel(feature3_inner, text="📂", font=("Tahoma", 20), width=30)
    feature3_icon.pack(side="left", padx=(0, 10))

    feature3_text = ctk.CTkLabel(
        feature3_inner,
        text="Organize passwords with categories",
        font=("Tahoma", 13),
        text_color="#FFFFFF",
        anchor="w"
    )
    feature3_text.pack(side="left", fill="x")

    # Buttons section
    buttons_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    buttons_frame.pack(pady=(15, 10), fill='x')

    # Get Started button styled like your login button
    get_started_button = ctk.CTkButton(
        buttons_frame,
        text="Get Started",
        font=("Tahoma", 16, "bold"),
        corner_radius=10,
        height=40,
        command=lambda: register_screen()
    )
    get_started_button.pack(fill='x', pady=(0, 5))

    # Version info at the bottom
    ctk.CTkLabel(
        welcome_card,
        text="Offline Version 1.0",
        font=("Tahoma", 12),
        text_color="#707070"
    ).pack(side="bottom", pady=5)

# Main application window: sidebar navigation and initializes content area
#user_id: local user identifier
#encryption_key: Key derived from master password for decrypting entries
# conn: Open local SQLite connection
# Data Encryption Key (DEK): Used for envelope encryption of each record
def cypher(user_id: int, encryption_key, conn, dek):
    manager_win = ctk.CTkToplevel()
    manager_win.title("Cypher")
    manager_win.geometry("570x555")

    sidebar = ctk.CTkFrame(manager_win, width=150)
    sidebar.pack(side="left", fill="y", padx=5, pady=5)

    ctk.CTkLabel(sidebar, text = "Cypher", font = ("Tahoma", 19, "bold")).pack(pady = 10)

    passwords_label = ctk.CTkLabel(sidebar, text = "Passwords", font = ("Tahoma", 12, "bold"), anchor = "w")
    passwords_label.pack(fill = "x", pady=(10,0))

    logins_btn = ctk.CTkButton(sidebar, text = "Categories", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: show_categories_screen(content_frame))
    logins_btn.pack(pady = 5)

    all_btn = ctk.CTkButton(sidebar, text = "All Logins", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: show_category(content_frame, user_id, "All"))
    all_btn.pack(pady = 5)

    fav_btn = ctk.CTkButton(sidebar, text = "Favorites", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: show_category(content_frame, user_id, "Favorites", "True"))
    fav_btn.pack(pady = (5,10))

    tools_label = ctk.CTkLabel(sidebar, text = "Tools", font = ("Tahoma", 12, "bold"), anchor = "w")
    tools_label.pack(fill = "x", pady=(10,0))

    gen_btn = ctk.CTkButton(sidebar, text = "Generator", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: generator_screen(content_frame))
    gen_btn.pack(pady = 5)

    new_login_btn = ctk.CTkButton(sidebar, text = "Add a login", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: show_add_login(user_id, content_frame))
    new_login_btn.pack(pady = 5)

    add_new_user_btn = ctk.CTkButton(sidebar, text = "Add a user", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: add_new_user_screen(content_frame))
    add_new_user_btn.pack(pady = 5)

    ctk.CTkLabel(
        sidebar,
        text="Offline mode • v1.0",
        font=("Inter", 12, "italic"),
        anchor="center",
        text_color=("#999999", "#777777")).pack(pady = (60,0), expand=True)

    bottom_frame = ctk.CTkFrame(sidebar)
    bottom_frame.pack(side = "bottom", pady = 5)

    logout_btn = ctk.CTkButton(bottom_frame, text = "🔓", font = ('Arial', 20), width = 40, height = 40, fg_color = 'transparent', hover_color = 'gray', command = lambda: logout(manager_win))
    logout_btn.pack(side = "left", padx = 5)

    settings_btn = ctk.CTkButton(bottom_frame, text = '⚙️', font = ('Arial', 15), width = 40, height = 40, fg_color = 'transparent', hover_color = 'gray', command = lambda: open_settings(content_frame))
    settings_btn.pack(side = 'left', padx = 5)

    content_frame = ctk.CTkFrame(manager_win, fg_color= "transparent")
    content_frame.pack(side = "right", expand = True, fill = "both")

    welcome_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    welcome_frame.pack(expand=True, fill="both")

    ctk.CTkLabel(welcome_frame, text="Welcome to Cypher!", font=("Tahoma", 20, "bold")).pack(pady=20)
    ctk.CTkLabel(welcome_frame, text = "Choose a category from the sidebar to get started.").pack()

    # Shows a grid of available categories with counts of saved logins
    def show_categories_screen(frame):
        clear_screen(frame)

        login_names = get_category(user_id, encryption_key, conn)
        categories = [
            {"name": "Websites", "count": 0, "color": "red", "services": []},
            {"name": "Games", "count": 0, "color": "green", "services": []},
            {"name": "Banks", "count": 0, "color": "blue", "services": []},
            {"name": "Work", "count": 0, "color": "purple", "services": []},
            {"name": "Socials", "count": 0, "color": "#2196F3", "services": []},
            {"name": "Email", "count": 0, "color": "orange", "services": []},
            {"name": "Shopping", "count": 0, "color": "#6628aa", "services": []},
            {"name": "Personal", "count": 0, "color": "#FF00A5", "services": []},
            {"name": "Other", "count": 0, "color": "#795548", "services": []}
        ]

        for category_name, website in login_names:
            for category in categories:
                if category["name"] == category_name:
                    category["services"].append(website)
                    break

        for category in categories:
            category["count"] = len(category["services"])

        # Main container
        main_frame = ctk.CTkFrame(frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)

        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent", height=60)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        header_frame.pack_propagate(False)

        # Left side - Title
        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(side="left", fill="y")

        ctk.CTkLabel(
            title_frame,
            text="Categories",
            font=("Tahoma", 22, "bold")
        ).pack(side="left", pady=10)

        info_frame = ctk.CTkScrollableFrame(main_frame)
        info_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Create category cards in a grid layout
        # Configure 3 columns with equal weight
        info_frame.grid_columnconfigure(0, weight=1)
        info_frame.grid_columnconfigure(1, weight=1)
        info_frame.grid_columnconfigure(2, weight=1)

        # Create category cards
        for i, category in enumerate(categories):
            row = i // 3  # Three columns layout
            col = i % 3

            card_frame = ctk.CTkFrame(
                info_frame,
                fg_color=("#FFFFFF", "#1F1F1F"),
                corner_radius=10,
                border_width=0)
            card_frame.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
            card_frame.bind("<Button-1>", lambda e, name=category["name"]: show_category(frame, user_id, name))

            color_bar = ctk.CTkFrame(
                card_frame,
                fg_color=category["color"],
                height=6,
                corner_radius=3)
            color_bar.pack(fill="x", padx=8, pady=(5, 0))

            color_bar.bind("<Button-1>", lambda e, name=category["name"]: show_category(frame, user_id, name))

            name_label = ctk.CTkLabel(
                card_frame,
                text=category["name"],
                font=("Tahoma", 15, "bold"),
                anchor="w")
            name_label.pack(fill="x", padx=12, pady=(12, 2))

            name_label.bind("<Button-1>", lambda e, name=category["name"]: show_category(frame, user_id, name))

            count_label = ctk.CTkLabel(
                card_frame,
                text=f"{category['count']} passwords",
                font=("Tahoma", 12),
                text_color=("#666666", "#AAAAAA"),
                anchor="w")
            count_label.pack(fill="x", padx=12, pady=(0, 5))

            count_label.bind("<Button-1>", lambda e, name=category["name"]: show_category(frame, user_id, name))

            # service list, shows max of 3
            services_shown = min(3, len(category["services"]))
            services_frame = ctk.CTkFrame(card_frame, fg_color="transparent")
            services_frame.pack(fill="x", padx=12, pady=(0, 15))

            services_frame.bind("<Button-1>", lambda e, name=category["name"]: show_category(frame, user_id, name))

            for j in range(services_shown):
                service_name = category["services"][j]
                service_label = ctk.CTkLabel(
                    services_frame,
                    text=f"• {service_name}",
                    font=("Tahoma", 12),
                    text_color=("#555555", "#BBBBBB"),
                    anchor="w")
                service_label.pack(fill="x", pady=1)

                service_label.bind("<Button-1>", lambda e, name=category["name"]: show_category(frame, user_id, name))

            # show more indicator. shows 3, subtracts 3 from total.
            if len(category["services"]) > 3:
                more_label = ctk.CTkLabel(
                    services_frame,
                    text=f"+ {len(category['services']) - 3} more...",
                    font=("Tahoma", 12, "italic"),
                    text_color=("#777777", "#999999"),
                    anchor="w")
                more_label.pack(fill="x", pady=(4, 0))

    # Displays form for adding a new login entry under the given user
    def show_add_login(uid: int, frame):
        clear_screen(frame)
        main_container = ctk.CTkFrame(frame, fg_color="transparent")
        main_container.pack(fill='both', expand=True)

        # Header frame
        header_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        header_frame.pack(pady=5, fill='x')

        ctk.CTkLabel(header_frame,
                     text="Add New Login",
                     font=("Tahoma", 20, "bold"),
                     text_color="white").pack(padx=10, pady = 5, side="left")

        # Card container frame
        card_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        card_frame.pack(pady=5, padx=10, fill='both', expand=True)

        login_card = ctk.CTkFrame(card_frame,
                                  corner_radius=15,
                                  border_width=1,
                                  border_color="#3C3C3C")
        login_card.pack(pady=10, padx=10, fill='both', expand=True)

        # Content frame
        content_frame = ctk.CTkFrame(login_card, fg_color="transparent")
        content_frame.pack(pady=5, padx=10, fill='both', expand=True)

        # Form container
        form_container = ctk.CTkFrame(content_frame, fg_color="transparent")
        form_container.pack(fill='both', expand=True)

        # 1. Website Frame
        website_frame = ctk.CTkFrame(form_container, fg_color="transparent")
        website_frame.pack(fill='x', pady=(0, 15))

        website_label = ctk.CTkLabel(website_frame,
                                     text="Website",
                                     font=("Tahoma", 14),
                                     text_color="#A0A0A0")
        website_label.pack(pady=(0, 5), anchor='w')

        # Website input container - keeping domain combo in same frame
        website_input_frame = ctk.CTkFrame(website_frame, fg_color="transparent")
        website_input_frame.pack(fill='x')

        website_entry = ctk.CTkEntry(website_input_frame,
                                     width=200,
                                     border_width=1,
                                     border_color="#3C3C3C",
                                     fg_color="#1F1F1F",
                                     text_color="white",
                                     placeholder_text="Website name")
        website_entry.pack(side="left", padx=(0, 5))

        domain_var = ctk.StringVar(value=".com")
        domain_menu = ctk.CTkComboBox(website_input_frame,
                                      values=[".com", ".net", ".org", ".edu", ".io"],
                                      variable=domain_var,
                                      corner_radius=10,
                                      border_width=1,
                                      border_color="#3C3C3C",
                                      fg_color="#1F1F1F",
                                      text_color="white",
                                      dropdown_fg_color="#1F1F1F",
                                      button_color="#3C3C3C",
                                      width=85,
                                      state="readonly")
        domain_menu.pack(side="left", padx = 10)

        # 2. Username Frame
        username_frame = ctk.CTkFrame(form_container, fg_color="transparent")
        username_frame.pack(fill='x', pady=(0, 15))

        username_label = ctk.CTkLabel(username_frame,
                                      text="Username",
                                      font=("Tahoma", 14),
                                      text_color="#A0A0A0")
        username_label.pack(pady=(0, 5), anchor='w')

        username_entry = ctk.CTkEntry(username_frame,
                                      width=200,
                                      border_width=1,
                                      border_color="#3C3C3C",
                                      fg_color="#1F1F1F",
                                      text_color="white",
                                      placeholder_text="Username or Email")
        username_entry.pack(side = "left")

        # 3. Password Frame
        password_frame = ctk.CTkFrame(form_container, fg_color="transparent")
        password_frame.pack(fill='x', pady=(0, 15))

        password_label = ctk.CTkLabel(password_frame,
                                      text="Password",
                                      font=("Tahoma", 14),
                                      text_color="#A0A0A0")
        password_label.pack(pady=(0, 5), anchor='w')

        password_input_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        password_input_frame.pack(fill='x')

        password_entry_var = ctk.StringVar()
        password_entry = ctk.CTkEntry(password_input_frame,
                                      width=200,
                                      border_width=1,
                                      border_color="#3C3C3C",
                                      fg_color="#1F1F1F",
                                      text_color="white",
                                      placeholder_text="Password",
                                      show="*",
                                      textvariable=password_entry_var)
        password_entry.pack(side="left", padx=(0, 5))

        toggle_button = ctk.CTkButton(password_input_frame,
                                      text="👁",
                                      font=("Arial", 16),
                                      fg_color="transparent",
                                      width=30,
                                      height=40,
                                      hover_color="gray",
                                      command=lambda: toggle_password_visibility(password_entry, confirm_password_entry))
        toggle_button.pack(side="left")

        generate_button = ctk.CTkButton(password_input_frame,
                                      text="🔄",
                                      font=("Arial", 16),
                                      corner_radius=10, command = lambda: gen_set_password(password_entry_var, confirm_password_entry_var, strength_label, strength_bar),
                                        fg_color="transparent",
                                        width=30,
                                        height=40,
                                        hover_color="gray")
        generate_button.pack(side="left", padx=1)

        copy_password_btn = ctk.CTkButton(password_input_frame, text = "📋", font = ("Arial", 16), fg_color = "transparent", hover_color="gray", width=30, height=30, command=lambda: copy_to_clipboard(password_input_frame, password_entry_var.get()))
        copy_password_btn.pack(side = "left")

        # 4. Strength Bar Frame
        strength_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        strength_frame.pack(fill='x', pady=(5, 0))

        strength_bar = ctk.CTkProgressBar(strength_frame, width=200)
        strength_bar.pack(side="left", fill='x')
        strength_bar.set(0)

        strength_label = ctk.CTkLabel(strength_frame, text="Weak", text_color="red", font=("Tahoma", 12))
        strength_label.pack(side="left", padx=10)

        password_entry.bind("<KeyRelease>", lambda event: password_strength(password_entry_var.get(), strength_label, strength_bar))

        # 5. Confirm Password Frame
        confirm_password_frame = ctk.CTkFrame(form_container, fg_color="transparent")
        confirm_password_frame.pack(fill='x', pady=(0, 15))

        confirm_password_label = ctk.CTkLabel(confirm_password_frame,
                                              text="Confirm Password",
                                              font=("Tahoma", 14),
                                              text_color="#A0A0A0")
        confirm_password_label.pack(pady=(0, 5), anchor='w')

        confirm_password_input_frame = ctk.CTkFrame(confirm_password_frame, fg_color="transparent")
        confirm_password_input_frame.pack(fill='x')

        confirm_password_entry_var = ctk.StringVar()
        confirm_password_entry = ctk.CTkEntry(confirm_password_input_frame,
                                              width=200,
                                              border_width=1,
                                              border_color="#3C3C3C",
                                              fg_color="#1F1F1F",
                                              text_color="white",
                                              placeholder_text="Confirm Password",
                                              show="*",
                                              textvariable=confirm_password_entry_var)
        confirm_password_entry.pack(side = "left")

        # 6. Category Frame
        category_frame = ctk.CTkFrame(form_container, fg_color="transparent")
        category_frame.pack(fill='x', pady=(0, 15))

        category_label = ctk.CTkLabel(category_frame,
                                      text="Category",
                                      font=("Tahoma", 14),
                                      text_color="#A0A0A0")
        category_label.pack(pady=(0, 5), anchor='w')

        category_var = ctk.StringVar(value="Websites")
        category_menu = ctk.CTkComboBox(category_frame,
                                        values=["Websites", "Banks", "Games", "Work", "Socials", "Email",
                                                "Shopping", "Personal", "Other"],
                                        variable=category_var,
                                        corner_radius=10,
                                        border_width=1,
                                        border_color="#3C3C3C",
                                        fg_color="#1F1F1F",
                                        text_color="white",
                                        dropdown_fg_color="#1F1F1F",
                                        button_color="#3C3C3C",
                                        state="readonly")
        category_menu.pack(side = "left")

        # 7. Button Frame
        button_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        button_frame.pack( fill="x", pady=(5, 10), padx = 10)

        add_button = ctk.CTkButton(button_frame,
                                   text="Add Login",
                                   font=("Tahoma", 14),
                                   height = 30,
                                   corner_radius=10,
                                   command = lambda: save_login())
        add_button.pack(side="left", padx=5)

        cancel_button = ctk.CTkButton(button_frame,
                                      text="Cancel",
                                      font=("Tahoma", 14),
                                      height= 30,
                                      corner_radius=10,
                                      command = lambda: show_category(frame, uid, "All"))
        cancel_button.pack(side="left", padx=5)

        # Saves the new login to local DB and confirms success
        def save_login():
            website = website_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            password_confirm = confirm_password_entry.get()
            category = category_var.get()
            top_level_domain = domain_var.get()

            if not website or not username or not password or not password_confirm:
                messagebox.showerror("Error", "All fields must be filled!")
                return

            if password != password_confirm:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            if len(password) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters!")
                return

            store_password(uid, website, username, password, category, encryption_key, top_level_domain, conn)
            messagebox.showinfo("Success", "Login saved successfully!")
            show_category(frame, uid, category)

    # Allows existing user to add a new user. New users cannot register themselves
    def add_new_user_screen(frame):
        clear_screen(frame)
        register_frame = ctk.CTkFrame(frame, fg_color="transparent")
        register_frame.pack(pady=20, padx=20, fill='both', expand=True)

        # Header
        header_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
        header_frame.pack(pady=(5, 5), padx=10, fill='x')

        ctk.CTkLabel(header_frame, text="Add User", font=("Tahoma", 24, "bold"), text_color="#FFFFFF").pack(side="left")

        registration_card = ctk.CTkFrame(register_frame, corner_radius=15, border_width=1,
                                         border_color="#3C3C3C")
        registration_card.pack(pady=20, padx=20, fill='both', expand=True)

        # Main content frame
        content_frame = ctk.CTkFrame(registration_card, fg_color="transparent")
        content_frame.pack(pady=10, padx=20, fill='both', expand=True)

        # Username section
        username_label = ctk.CTkLabel(content_frame, text="Username", font=("Tahoma", 14), text_color="#A0A0A0")
        username_label.pack(pady=(0, 5), anchor='w')

        username_container = ctk.CTkFrame(content_frame, fg_color="transparent")
        username_container.pack(fill='x')

        username_entry = ctk.CTkEntry(username_container, width=235, height=40, corner_radius=10, border_width=1,
                                      border_color="#3C3C3C", fg_color="#1F1F1F", text_color="white")
        username_entry.pack(side="left", pady=(0, 15), padx=(0, 5))

        # Password section
        password_var = ctk.StringVar()
        password_label = ctk.CTkLabel(content_frame,
                                      text="Password",
                                      font=("Tahoma", 14),
                                      text_color="#A0A0A0")
        password_label.pack(pady=(0, 5), anchor='w')

        # Password entry with toggle visibility container
        password_container = ctk.CTkFrame(content_frame, fg_color="transparent")
        password_container.pack(fill='x')

        password_entry = ctk.CTkEntry(password_container,
                                      width=235,
                                      height=40,
                                      corner_radius=10,
                                      border_width=1,
                                      border_color="#3C3C3C",
                                      fg_color="#1F1F1F",
                                      text_color="white",
                                      show="*",
                                      textvariable=password_var)
        password_entry.pack(side='left', pady=(0, 15), padx=(0, 5))

        # Password visibility toggle
        toggle_button = ctk.CTkButton(password_container, text="👁", font=("Arial", 16), fg_color="transparent",
                                      width=30, height=40, hover_color="gray",
                                      command=lambda: toggle_password_visibility(password_entry, password_confirm_entry))
        toggle_button.pack(side='left', pady=(0, 10))

        # Confirm Password section
        password_confirm_var = ctk.StringVar()
        confirm_password_label = ctk.CTkLabel(content_frame, text="Confirm Password", font=("Tahoma", 14),
                                              text_color="#A0A0A0")
        confirm_password_label.pack(pady=(0, 5), anchor='w')

        # Confirm password entry with toggle visibility container
        confirm_password_container = ctk.CTkFrame(content_frame, fg_color="transparent")
        confirm_password_container.pack(fill='x')

        password_confirm_entry = ctk.CTkEntry(confirm_password_container,
                                              width=235,
                                              height=40,
                                              corner_radius=10,
                                              border_width=1,
                                              border_color="#3C3C3C",
                                              fg_color="#1F1F1F",
                                              text_color="white",
                                              show="*",
                                              textvariable=password_confirm_var)
        password_confirm_entry.pack(side='left', pady=(0, 15), padx=(0, 5))

        # Strength bar frame
        strength_bar_frame = ctk.CTkFrame(content_frame,
                                          fg_color="transparent",
                                          width=300)
        strength_bar_frame.pack(fill='x', pady=(0, 10))

        strength_bar = ctk.CTkProgressBar(strength_bar_frame, width=220)
        strength_bar.pack(side="left", fill='x')
        strength_bar.set(0)
        strength_label = ctk.CTkLabel(strength_bar_frame, text="Weak", text_color="red", font=("Tahoma", 12))
        strength_label.pack(side="left", padx=10)

        password_entry.bind("<KeyRelease>", lambda event: password_strength(password_var.get(), strength_label, strength_bar))

        # Register button
        register_button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        register_button_frame.pack(fill='x')
        register_button = ctk.CTkButton(register_button_frame,
                                        text="Register",
                                        font=("Tahoma", 16, "bold"),
                                        corner_radius=10,
                                        height=40, command=lambda: attempt_add_user())
        register_button.pack(fill='x', pady=(0, 0))

        def attempt_add_user():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            password_confirm = password_confirm_entry.get().strip()

            if not username or not password or not password_confirm:
                messagebox.showerror("Error", "All fields must be filled.")
                return

            if password != password_confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return

            if len(username) < 4:
                messagebox.showerror("Error", "Username must be at least 4 characters long.")
                return
            if len(password) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters long.")
                return

            try:
                created = create_user(username_entry.get(), password_var.get(), conn, dek)
            except Exception as e:
                messagebox.showerror("Error", f"Error in adding a new user: {e}")
                return
            else:
                if created:
                    messagebox.showinfo("Success", f"User {username_entry.get()} created successfully!")
                    show_categories_screen(frame)
                else:
                    messagebox.showerror("Error", f"User {username_entry.get()} already exists!")

        username_entry.bind("<Return>", lambda event: attempt_add_user())
        password_entry.bind("<Return>", lambda event: attempt_add_user())
        password_confirm_entry.bind("<Return>", lambda event: attempt_add_user())

    # Lists saved logins filtered by category or favorites
    def show_category(frame, u_id, category, favorite = None):
        clear_screen(frame)

        details_frame = ctk.CTkFrame(frame, fg_color = "transparent")
        details_frame.pack(pady = 20, padx = 20, fill = "both", expand = True)

        header_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        header_frame.pack(pady = 10, padx = 20, fill = "x")

        if category == "Favorites":
            title_text = f"Showing Favorite Logins"
        elif category and category != "All":
            title_text = f"Showing {category} Logins"
        else:
            title_text = f"Showing All Logins"

        ctk.CTkLabel(header_frame, text = title_text, font = ("Tahoma", 18, "bold")).pack(side = "left", pady = 5)

        passwords_frame = ctk.CTkScrollableFrame(details_frame, orientation = "vertical")
        passwords_frame.pack(pady = 20, padx = 20, fill = "both", expand = True)

        passwords = get_login_data(u_id, encryption_key, conn, category, favorite)
        for login_data in passwords:
            login_frame = ctk.CTkFrame(passwords_frame, fg_color = "transparent")
            login_frame.pack(pady = 5, fill = "x")

            ctk.CTkButton(login_frame, text = f"{login_data[1]} | {login_data[0]}", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda p = login_data: show_password_details(frame, p, category)).pack(pady = 5)

    # Shows details for a selected entry and allows actions
    def show_password_details(frame, login_data, category):
        clear_screen(frame)

        details_frame = ctk.CTkFrame(frame, fg_color = "transparent")
        details_frame.pack(pady = 20, padx = 20, fill = "both", expand = True)

        header_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        header_frame.pack(pady = 10, fill = "x")

        ctk.CTkLabel(header_frame, text=f"Credentials For {login_data[0]}", font = ("Tahoma", 18, "bold")).pack(side = "left", padx = 10)
        back_btn = ctk.CTkButton(header_frame, text = "Back", width = 80, command = lambda: show_category(frame, user_id, category))
        back_btn.pack(side = "right", padx = 10)

        cred_card = ctk.CTkFrame(details_frame, corner_radius=15, border_width=1, border_color="#3C3C3C")
        cred_card.pack(pady=10, padx=10, fill='both', expand=True)

        cred_frame = ctk.CTkFrame(cred_card, fg_color = "transparent")
        cred_frame.pack(pady = 10, padx = 20, fill = "both", expand = True)

        website_frame = ctk.CTkFrame(cred_frame, fg_color = "transparent")
        website_frame.pack(fill = "x", pady = 5)
        ctk.CTkLabel(website_frame, text = "Website:", width=100, anchor="e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side="left")
        ctk.CTkLabel(website_frame, text = f"{login_data[0]}").pack(side="left", padx=10)

        username_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        username_frame.pack(fill = "x", pady = 5)
        ctk.CTkLabel(username_frame, text = "Username:", width = 100, anchor = "e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side = "left")
        ctk.CTkLabel(username_frame, text = f"{login_data[1]}").pack(side = "left", padx = 10)
        copy_username_btn = ctk.CTkButton(username_frame, text = "📋", font = ("Arial", 16), fg_color = "transparent", hover_color="gray", width=30, height=30, command=lambda: copy_to_clipboard(frame, login_data[1]))
        copy_username_btn.pack(side = "left")

        password_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        password_frame.pack(fill = "x", pady = 5)
        ctk.CTkLabel(password_frame, text = "Password:", width=100, anchor = "e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side = "left")

        password_var = ctk.StringVar(value = login_data[2])
        password_display = ctk.CTkEntry(password_frame, textvariable=password_var, width=150, show="*", border_color="#3C3C3C", fg_color="#1F1F1F", text_color= "white")
        password_display.pack(side="left", padx=10)

        creation_date_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        creation_date_frame.pack(fill = "x", pady = 5)

        ctk.CTkLabel(creation_date_frame, text = "Created On:", width=100, anchor = "e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side = "left")
        ctk.CTkLabel(creation_date_frame, text = f"{login_data[3]}").pack(side = "left", padx = 10)

        last_modified_date = ctk.CTkFrame(cred_frame, fg_color="transparent")
        last_modified_date.pack(fill = "x", pady = 5)

        ctk.CTkLabel(last_modified_date, text = "Last Modified:", width=100, anchor = "e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side = "left")
        ctk.CTkLabel(last_modified_date, text = f"{login_data[7]}").pack(side = "left", padx = 10)

        copy_pass_btn = ctk.CTkButton(password_frame, text="📋", font=("Arial", 16), fg_color="transparent", hover_color="gray", width=30, height=30, command=lambda: copy_to_clipboard(frame, login_data[2]))
        copy_pass_btn.pack(side="left")

        toggle_btn = ctk.CTkButton(password_frame, text="👁", font=("Arial", 16), fg_color="transparent", hover_color="gray", width=30, height=30, command=lambda: toggle_password_visibility(password_display))
        toggle_btn.pack(side = "left")

        favorite_btn_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        favorite_btn_frame.pack(fill = "x", pady = 5)

        is_favorite = "on" if login_data[6] == 1 else "off"

        favorite_var = ctk.StringVar(value="on" if is_favorite == "on" else "off")
        favorite_checkbox = ctk.CTkCheckBox(favorite_btn_frame,
                                            text="Favorite",
                                            font=("Tahoma", 12),
                                            checkbox_width=20,
                                            checkbox_height=20,
                                            variable=favorite_var,
                                            onvalue="on",
                                            offvalue="off",
                                            text_color="#A0A0A0",
                                            command = lambda: toggle_favorite(login_data[4], favorite_var, encryption_key, conn))
        favorite_checkbox.pack(side = "left", padx = 40,  pady=(0, 20))

        action_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
        action_frame.pack(pady = 20)

        ctk.CTkButton(action_frame, text="Edit", command = lambda: edit_login_gui(frame, login_data[0], login_data[1], login_data[2], "All", login_data)).pack(side = "left", padx = 5)
        ctk.CTkButton(action_frame, text="Delete", fg_color="red", command=lambda: delete_login_gui(frame, user_id, login_data[0], login_data[4])).pack(side="left", padx=5)

    # Displays UI for editing an existing login entry
    def edit_login_gui(frame1, website, username, password, category, all_login_data):
        clear_screen(frame1)

        details_frame = ctk.CTkFrame(frame1, fg_color = "transparent")
        details_frame.pack(pady = 20, padx = 20, fill = "both", expand = True)

        header_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        header_frame.pack(pady = 10, fill = "x")

        ctk.CTkLabel(header_frame, text=f"Edit Login", font = ("Tahoma", 18, "bold")).pack(side = "left", padx = 10)
        back_btn = ctk.CTkButton(header_frame, text = "Back", width = 80, command = lambda: show_password_details(frame1, all_login_data, category))
        back_btn.pack(side = "right", padx = 10)

        cred_card = ctk.CTkFrame(details_frame, corner_radius=15, border_width=1, border_color="#3C3C3C")
        cred_card.pack(pady=20, padx=20, fill='both', expand=True)

        cred_frame = ctk.CTkFrame(cred_card, fg_color = "transparent")
        cred_frame.pack(pady = 10 ,padx = 10, fill = "both", expand = True)

        website_frame = ctk.CTkFrame(cred_frame, fg_color = "transparent")
        website_frame.pack(fill = "x", pady = 5)
        ctk.CTkLabel(website_frame, text = "Website:", width=100, anchor="e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side="left")
        website_var = ctk.StringVar(value = website)
        website_entry = ctk.CTkEntry(website_frame, textvariable= website_var, width=150, show="", border_color="#3C3C3C", fg_color="#1F1F1F", text_color= "white")
        website_entry.pack(side="left", padx=10)

        username_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        username_frame.pack(fill = "x", pady = 5)
        ctk.CTkLabel(username_frame, text = "Username:", width = 100, anchor = "e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side = "left")
        username_var = ctk.StringVar(value = username)
        username_entry = ctk.CTkEntry(username_frame, textvariable=username_var, width=150, show="", border_color="#3C3C3C", fg_color="#1F1F1F", text_color= "white")
        username_entry.pack(side="left", padx=10)
        copy_username_btn = ctk.CTkButton(username_frame, text = "📋", font = ("Arial", 16), fg_color = "transparent", hover_color="gray", width=30, height=30, command=lambda: copy_to_clipboard(frame1, username))
        copy_username_btn.pack(side = "left")

        password_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        password_frame.pack(fill = "x", pady = 5)
        ctk.CTkLabel(password_frame, text = "Password:", width=100, anchor = "e", font=("Tahoma", 14), text_color="#A0A0A0").pack(side = "left")
        password_var = ctk.StringVar(value = password)
        password_entry = ctk.CTkEntry(password_frame, textvariable=password_var, width=150, show="*", border_color="#3C3C3C", fg_color="#1F1F1F", text_color= "white")
        password_entry.pack(side="left", padx=10)

        creation_date_frame = ctk.CTkFrame(cred_frame, fg_color="transparent")
        creation_date_frame.pack(fill = "x", pady = 5)

        copy_pass_btn = ctk.CTkButton(password_frame, text="📋", font=("Arial", 16), fg_color="transparent", hover_color="gray", width=30, height=30, command=lambda: copy_to_clipboard(frame1, password))
        copy_pass_btn.pack(side="left")

        toggle_btn = ctk.CTkButton(password_frame, text="👁", font=("Arial", 16), fg_color="transparent", hover_color="gray", width=30, height=30, command=lambda: toggle_password_visibility(password_entry))
        toggle_btn.pack(side = "left")

        action_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
        action_frame.pack(pady = 20)

        update_btn = ctk.CTkButton(action_frame, text="Update", height = 30, command = lambda: attempt_login_edit())
        update_btn.pack(side = "left", padx = 5)

        # Attempts to update credentials after confirmation
        def attempt_login_edit():
            confirm = messagebox.askyesno("Edit Login", "Are you sure you want to change your login credentials?")
            if website_entry.get() == website and username_entry.get() == username and password_entry.get() == password:
                messagebox.showerror("Error", "Credentials match information stored in database.")
                return

            if confirm:
                edit_login(user_id, username, website, website_var.get(), username_var.get(), password_var.get(), encryption_key, conn)
                messagebox.showinfo("Success", "Your login credentials have been changed.")

    # Confirms and deletes a selected login entry
    def delete_login_gui(frame, userid, website, password_id):
        confirm = messagebox.askyesno("Delete login", f'Are you sure you want to delete your login for {website}?')

        if confirm:
            delete_login(userid, password_id, conn)
            messagebox.showinfo("Deleted", "Login deleted successfully!")
            show_category(frame, userid, "All")

    manager_win.protocol("WM_DELETE_WINDOW", lambda: close_app(manager_win, conn))

    # Password generator tool: UI for specifying length, specials, then generate
    def generator_screen(frame):
        clear_screen(frame)

        details_frame = ctk.CTkFrame(frame, fg_color="transparent")
        details_frame.pack(pady=20, padx=20, fill="both", expand=True)

        header_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
        header_frame.pack(pady=(0, 15), fill="x")

        ctk.CTkLabel(
            header_frame,
            text="Password Generator",
            font=("Tahoma", 20, "bold")).pack(side="left", padx=5)

        # Main generator container
        generator_frame = ctk.CTkFrame(
            details_frame,
            border_width=1,
            border_color="#3C3C3C",
            corner_radius=8
        )
        generator_frame.pack(pady=15, fill="both", expand=True, padx=10)

        # Password display
        password_section = ctk.CTkFrame(generator_frame, fg_color="transparent")
        password_section.pack(padx=15, pady=15, fill="x")

        ctk.CTkLabel(
            password_section,
            text="Your Password:",
            font=("Tahoma", 14),
            text_color="#A0A0A0").pack(anchor="w", pady=(0, 5))

        # Password field
        generator_entry_frame = ctk.CTkFrame(password_section, fg_color="transparent")
        generator_entry_frame.pack(fill="x")

        generator_entry_var = ctk.StringVar()
        generator_entry = ctk.CTkEntry(
            generator_entry_frame,
            textvariable=generator_entry_var,
            width=150,
            height=36,
            show="*",
            font=("Tahoma", 13),
            fg_color="#1F1F1F",
            border_color="#3C3C3C"
        )
        generator_entry.pack(side="left", padx=(0, 10), fill="x", expand=True)

        toggle_button = ctk.CTkButton(
            generator_entry_frame,
            text="👁",
            font=("Arial", 16),
            fg_color="transparent",
            hover_color= "gray",
            width=36,
            height=36,
            corner_radius=6,
            command=lambda: toggle_password_visibility(generator_entry)
        )
        toggle_button.pack(side="left", padx=(0, 5))

        options_frame = ctk.CTkFrame(generator_frame, fg_color="transparent")
        options_frame.pack(padx=15, pady=(0, 15), fill="x")

        special_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        special_frame.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            special_frame,
            text="Minimum Special Characters:",
            font=("Tahoma", 13),
            text_color="#A0A0A0").pack(side="left")

        special_chars_var = ctk.StringVar(value="2")
        special_chars_menu = ctk.CTkComboBox(
            special_frame,
            values=["2", "3", "4", "5", "6", "7"],
            variable=special_chars_var,
            corner_radius=6,
            border_width=1,
            border_color="#3C3C3C",
            fg_color="#1F1F1F",
            text_color="white",
            dropdown_fg_color="#1F1F1F",
            button_color="#3C3C3C",
            width=70,
            height=32,
            state="readonly")
        special_chars_menu.pack(side="left", padx=(10, 0))

        length_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        length_frame.pack(fill="x", pady=(0, 10))

        length_label = ctk.CTkLabel(
            length_frame,
            text="Password Length:",
            font=("Tahoma", 13),
            text_color="#A0A0A0")
        length_label.pack(side="left")

        length_value_label = ctk.CTkLabel(
            length_frame,
            text="16",
            width=30,
            font=("Tahoma", 13),
            text_color="#A0A0A0")
        length_value_label.pack(side="left", padx=(5, 10))

        slider_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
        slider_frame.pack(fill="x", pady=(0, 10))

        length_slider = ctk.CTkSlider(
            slider_frame,
            from_=8,
            to=32,
            number_of_steps=24,
            command=lambda value: length_value_label.configure(text=str(int(value))))
        length_slider.pack(fill="x", padx=5)
        length_slider.set(16)  # Default length

        btns_frame = ctk.CTkFrame(generator_frame, fg_color="transparent")
        btns_frame.pack(pady=(5, 15), padx=15, fill="x")

        generator_btn = ctk.CTkButton(
            btns_frame,
            text="Generate",
            width=120,
            height=36,
            corner_radius=6,
            font=("Tahoma", 13),
            command=lambda: gen_set_password(generator_entry_var, None, None, None, int(length_slider.get()), int(special_chars_var.get())))
        generator_btn.pack(side="left", padx=(0, 10))

        copy_btn = ctk.CTkButton(
            btns_frame,
            text="Copy",
            width=100,
            height=36,
            corner_radius=6,
            font=("Tahoma", 13),
            command=lambda: copy_to_clipboard(generator_frame, generator_entry.get()))
        copy_btn.pack(side="left")

    # Screen for changing the master password with validation and update
    def change_password_screen(frame):
        clear_screen(frame)

        password_frame = ctk.CTkFrame(frame, fg_color = "transparent")
        password_frame.pack(fill = "both", pady = 20, padx = 20, expand = True)

        header_frame = ctk.CTkFrame(password_frame, fg_color = "transparent")
        header_frame.pack(fill = "x", pady = 5, padx = 5)
        ctk.CTkLabel(header_frame, text = "Change Master Password", font = ("Tahoma", 18, "bold"), anchor = "e").pack(side = "left", pady = 5)

        back_btn = ctk.CTkButton(header_frame, text = "Back", width = 80, command = lambda: open_settings(frame))
        back_btn.pack(side = "right", pady = 5)

        details_frame = ctk.CTkFrame(password_frame)
        details_frame.pack(fill = "both", pady = 15, padx = 15, expand = True)

        current_password_label_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        current_password_label_frame.pack(fill = "x", pady = 5, padx = 20)
        ctk.CTkLabel(current_password_label_frame, text = "Current Password", font = ("Tahoma", 14), text_color = "#A0A0A0").pack(side = "left", pady = (5,0), padx = 5)

        master_password_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        master_password_frame.pack(fill = "x", pady = 5, padx = 20)
        password_entry = ctk.CTkEntry(master_password_frame, width = 200, show = "*", border_color="#3C3C3C", fg_color="#1F1F1F")
        password_entry.pack(side = "left", pady = 1, padx = 5)

        new_password_label_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        new_password_label_frame.pack(fill = "x", pady = 3, padx = 20)
        ctk.CTkLabel(new_password_label_frame, text = "New Password", font = ("Tahoma", 14), text_color = "#A0A0A0").pack(side = "left", pady = 0, padx = 5)

        new_password_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        new_password_frame.pack(fill = "x", pady = 5, padx = 20)
        password_var = ctk.StringVar()
        new_password_entry = ctk.CTkEntry(new_password_frame, width = 200, show = "*", textvariable = password_var, border_color="#3C3C3C", fg_color="#1F1F1F")
        new_password_entry.pack(side = "left", pady = 1, padx = 5)

        copy_pass_btn = ctk.CTkButton(new_password_frame, text = "📋", font = ("Arial", 16), fg_color = "transparent", hover_color = "gray", width = 30, height = 30, command = lambda: copy_to_clipboard(frame, new_password_entry.get()))
        copy_pass_btn.pack(side = "left", padx = 0)

        toggle_btn = ctk.CTkButton(new_password_frame, text="👁", font=("Arial", 16), fg_color="transparent", hover_color="gray", width=30, height=30, command=lambda: toggle_password_visibility(new_password_entry, confirm_password_entry))
        toggle_btn.pack(side = "left", padx = 0)

        confirm_password_label_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        confirm_password_label_frame.pack(fill = "x", pady = 3, padx = 20)
        ctk.CTkLabel(confirm_password_label_frame, text="Confirm New Password", font = ("Tahoma", 14), text_color = "#A0A0A0").pack(side = "left", pady = 0, padx = 5)

        confirm_password_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        confirm_password_frame.pack(fill = "x", pady = 5, padx = 20)
        confirm_var = ctk.StringVar()
        confirm_password_entry = ctk.CTkEntry(confirm_password_frame, width = 200, show = "*", textvariable = confirm_var, border_color="#3C3C3C", fg_color="#1F1F1F")
        confirm_password_entry.pack(side = "left", pady = 5, padx = 5)

        strength_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        strength_frame.pack(side = "left", fill = "x", padx = 20)

        strength_bar_func(strength_frame, password_var, confirm_var, new_password_entry, 200)

        def attempt_change():
            old_password = password_entry.get()
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()

            if not old_password or not new_password or not confirm_password:
                messagebox.showerror("Error", "All fields must be filled!")
                return

            if confirm_password != new_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            if len(new_password) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters!")
                return

            success, msg = change_master_password(user_id, old_password, new_password, conn)

            if success:
                messagebox.showinfo("Success", "Password changed successfully!")
            else:
                messagebox.showerror("Error", msg)

        generate_password_btn = ctk.CTkFrame(frame, fg_color = "transparent")
        generate_password_btn.pack(side = "left", fill = "x", pady = 0, padx = 85)

        ctk.CTkButton(generate_password_btn, text = "Change Master Password", height = 35, command = lambda: attempt_change()).pack(pady = 10)

    # Allows user to backup database
    def backup_db_win(frame):
        confirm = messagebox.askyesno("Backup database", f'Are you sure you want to backup your database? This will replace a previously backed up database.')
        if confirm:
            if backup_database():
                messagebox.showinfo("Success", "Database backup saved successfully!")
            else:
                messagebox.showinfo("Error", "Unable to backup database!")

    # UI for deleting the master user account after credential re-entry
    def delete_master_user_page(frame):
        clear_screen(frame)

        details_frame = ctk.CTkFrame(frame, fg_color = "transparent")
        details_frame.pack(fill = "both", pady = 20, padx = 20, expand = True)

        header_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        header_frame.pack(fill = "x", pady = 0)
        header_frame_2 = ctk.CTkFrame(details_frame, fg_color = "transparent")
        header_frame_2.pack(fill = "x", pady = 5)

        back_btn = ctk.CTkButton(header_frame, text = "Back", width = 80, command = lambda: open_settings(frame))
        back_btn.pack(side = "right", pady = 5)

        ctk.CTkLabel(header_frame, text = "Delete Account", font = ("Tahoma", 18, "bold")).pack(side = "left", pady = 1)
        ctk.CTkLabel(header_frame_2, text = "Please re-enter your credentials", font = ("Tahoma", 13, "bold")).pack(side = "left", pady = 5)

        deletion_card = ctk.CTkFrame(details_frame, corner_radius=15, border_width=1, border_color="#3C3C3C")
        deletion_card.pack(pady=20, padx=20, fill='both', expand=True)

        entry_frame = ctk.CTkFrame(deletion_card, fg_color = "transparent")
        entry_frame.pack(pady = 10, padx = 20, fill = "both", expand = True)

        # Password section
        password_label = ctk.CTkLabel(entry_frame,
                                      text="Password",
                                      font=("Tahoma", 14),
                                      text_color="#A0A0A0")
        password_label.pack(pady=(0, 5), anchor='w')

        # Password entry
        password_container = ctk.CTkFrame(entry_frame, fg_color="transparent")
        password_container.pack(fill='x')

        password_entry = ctk.CTkEntry(password_container,
                                      width=235,
                                      height=40,
                                      corner_radius=10,
                                      border_width=1,
                                      border_color="#3C3C3C",
                                      fg_color="#1F1F1F",
                                      text_color="white",
                                      show="*",)
        password_entry.pack(side='left', pady=(0, 15), padx=(0, 5))

        # Confirm Password section
        confirm_password_label = ctk.CTkLabel(entry_frame, text="Confirm Password", font=("Tahoma", 14),
                                              text_color="#A0A0A0")
        confirm_password_label.pack(pady=(0, 5), anchor='w')

        # Confirm password entry
        confirm_password_container = ctk.CTkFrame(entry_frame, fg_color="transparent")
        confirm_password_container.pack(fill='x')

        confirm_password_entry = ctk.CTkEntry(confirm_password_container,
                                              width=235,
                                              height=40,
                                              corner_radius=10,
                                              border_width=1,
                                              border_color="#3C3C3C",
                                              fg_color="#1F1F1F",
                                              text_color="white",
                                              show="*")
        confirm_password_entry.pack(side='left', pady=(0, 15), padx=(0, 5))

        def attempt_account_deletion():
            password = password_entry.get()
            confirm_password = confirm_password_entry.get()

            if not password or not confirm_password:
                messagebox.showerror("Error", "All fields must be filled!")
                return

            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            confirm = messagebox.askyesno("Account Deletion", "Are you sure you want to delete your account?")
            if confirm:
                success, msg = delete_master_user(user_id, password, conn)
                if success:
                    messagebox.showinfo("Success", "Account and information permanently deleted.")
                    clear_screen(app)
                    app.deiconify()
                    app.destroy()
                else:
                    messagebox.showerror("Error", "Unable to delete account. Check your credentials.")

        delete_account_btn = ctk.CTkButton(frame, text = "Delete Account", height = 40,  fg_color = "red", hover_color = "red", command = lambda: attempt_account_deletion())
        delete_account_btn.pack(pady = 10)

    # Opens the settings menu: theme, appearance, backup, delete account
    def open_settings(settings_frame):
        clear_screen(settings_frame)

        details_frame = ctk.CTkFrame(settings_frame, fg_color = "transparent")
        details_frame.pack(pady = 20, padx = 20, fill = "both", expand = True)

        header_frame = ctk.CTkFrame(details_frame, fg_color = "transparent")
        header_frame.pack(fill = "x", pady = 5)

        buttons_card = ctk.CTkFrame(details_frame, corner_radius=15, border_width=1, border_color="#3C3C3C")
        buttons_card.pack(pady=10, padx=10, fill='both', expand=True)

        buttons_frame = ctk.CTkFrame(buttons_card, fg_color = "transparent")
        buttons_frame.pack(fill = "both", pady = 20, padx = 20, expand = True)

        ctk.CTkLabel(header_frame, text = 'Settings', font = ("Tahoma", 20, "bold")).pack(side = "left", pady = 5)

        change_btn_frame = ctk.CTkFrame(buttons_frame, fg_color = "transparent")
        change_btn_frame.pack(fill = "x", pady = 5)
        change_btn = ctk.CTkButton(change_btn_frame, text = 'Change Master Password', width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: change_password_screen(settings_frame))
        change_btn.pack(pady = 5)

        backup_btn_frame = ctk.CTkFrame(buttons_frame, fg_color = "transparent")
        backup_btn_frame.pack(fill = "x", pady = 5)
        backup_btn = ctk.CTkButton(backup_btn_frame, text = 'Backup Password Database', width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: backup_db_win(settings_frame))
        backup_btn.pack(pady = 5)

        change_theme_frame = ctk.CTkFrame(buttons_frame, fg_color = "transparent")
        change_theme_frame.pack(fill = "x", pady = 5)
        change_theme_btn = ctk.CTkButton(change_theme_frame, text = "Change Theme", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: change_theme_page(settings_frame))
        change_theme_btn.pack(pady = 5)

        sync_btn_frame = ctk.CTkFrame(buttons_frame, fg_color = "transparent")
        sync_btn_frame.pack(fill = "x", pady = 5)
        sync_btn = ctk.CTkButton(sync_btn_frame, text = "Sync To Cloud", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: messagebox.showinfo("Offline", "You need the online version of Cypher for this function."))
        sync_btn.pack(pady = 5)

        delete_account_frame = ctk.CTkFrame(buttons_frame, fg_color = "transparent")
        delete_account_frame.pack(side = "bottom", fill = "x", pady = 10)
        delete_account_btn = ctk.CTkButton(delete_account_frame, text = "Delete Account", fg_color="red",  width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: delete_master_user_page(settings_frame))
        delete_account_btn.pack(pady = 5)

    def change_theme_page(frame):
        clear_screen(frame)

        top_details_frame = ctk.CTkFrame(frame, fg_color = "transparent")
        top_details_frame.pack(pady = 20, padx = 20, fill = "both", expand = True)

        top_header_frame = ctk.CTkFrame(top_details_frame, fg_color = "transparent")
        top_header_frame.pack(fill = "x", pady = 0)

        back_btn = ctk.CTkButton(top_header_frame, text = "Back", width = 80, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: open_settings(frame))
        back_btn.pack(side = "right", pady = 5)

        themes_frame = ctk.CTkFrame(top_details_frame)
        themes_frame.pack(fill = "x", pady = 5)
        ctk.CTkLabel(top_header_frame, text = "Themes", font = ("Tahoma", 20, "bold")).pack(side = "left", pady = 5)
        ctk.CTkButton(themes_frame, text = "Dark Blue", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: change_theme("dark-blue")).pack(pady = 5)
        ctk.CTkButton(themes_frame, text = "Light Blue", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: change_theme("blue")).pack(pady = 5)
        ctk.CTkButton(themes_frame, text="Green", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command= lambda: change_theme("green")).pack(pady=5)

        bottom_details_frame = ctk.CTkFrame(frame, fg_color="transparent")
        bottom_details_frame.pack(pady= 5, padx=20, fill="both", expand=True)

        bottom_header_frame = ctk.CTkFrame(bottom_details_frame, fg_color = "transparent")
        bottom_header_frame.pack(fill = "x", pady = 5)

        appearances_frame = ctk.CTkFrame(bottom_details_frame)
        appearances_frame.pack(fill = "x", pady = 5)

        ctk.CTkLabel(bottom_header_frame, text="Appearances", font=("Tahoma", 20, "bold")).pack(side="left", pady=5)
        ctk.CTkButton(appearances_frame, text = "System", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: change_appearance("system")).pack(pady = 5)
        ctk.CTkButton(appearances_frame, text = "Dark", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda:  change_appearance("dark")).pack(pady = 5)
        ctk.CTkButton(appearances_frame, text = "Light", width = 120, height = 36, corner_radius = 6, font = ("Tahoma", 13), command = lambda: change_appearance("light")).pack(pady = 5)

        def change_theme(theme):
            ctk.set_default_color_theme(theme)
            save_theme_preference(theme)

        def change_appearance(appearance):
            ctk.set_appearance_mode(appearance)
            save_appear_preference(appearance)

    # Logs out the user, closes manager window, and returns to login
    def logout(win):
        confirm = messagebox.askyesno("Logout", f'Are you sure you want to logout?')
        if confirm:
            conn.commit()
            win.destroy()
            app.deiconify()
            conn.close()

# Utility: displays a strength bar and generate button for password fields
def strength_bar_func(frame, password_var, password_confirm_var, update_var, bar_width):
    strength_bar = ctk.CTkProgressBar(frame, width = bar_width)
    strength_bar.set(0)
    strength_bar.pack(pady = 5, padx = 10)
    strength_label = ctk.CTkLabel(frame, text = "Weak", text_color = "red")
    strength_label.pack(pady = 0)

    generate_button = ctk.CTkButton(frame, text = "Generate",  command = lambda: gen_set_password(password_var, password_confirm_var, strength_label, strength_bar))
    generate_button.pack(pady = 5)

    update_var.bind("<KeyRelease>", lambda event: password_strength(password_var.get(), strength_label, strength_bar))

# Closes app. Commits any changes to SQLite database and closes that connection
def close_app(win, conn):
    conn.commit()
    win.destroy()
    app.destroy()
    conn.close()
    exit()

# Start Cypher
init_meta_db()
entry_screen()
app.mainloop()
