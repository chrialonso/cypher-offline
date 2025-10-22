import random
import re
import string

def generate_password(length = 16, min_special_chars = 2):
    """
    Generate a random password meeting basic complexity requirements.
    """
    lowercase = random.choice(string.ascii_lowercase)
    uppercase = random.choice(string.ascii_uppercase)
    nums = random.choice(string.digits)
    special_chars = '!@#$%^&*(),.?":{}|<>'''

    required_chars = [lowercase, uppercase, nums]

    for _ in range(min_special_chars):
        required_chars.append(random.choice(special_chars))

    remaining_length = length - len(required_chars)

    all_chars = lowercase + uppercase + nums + special_chars
    remaining_chars = [random.choice(all_chars) for _ in range(remaining_length)]

    password = required_chars + remaining_chars

    random.shuffle(password)
    return ''.join(password)

def password_strength(password: str, strength_label, strength_bar):
    """
    Evaluate password strength and update UI label and progress bar.
    """
    strength = 0

    if len(password) >= 6:
        strength += 3
    if re.search(r"[A-Z]", password):
        strength += 2
    if re.search(r"[0-9]", password):
        strength += 2

    special_chars = re.findall(r"[!@#$%^&*(),.?\":{}|<>]", password)
    if len(special_chars) == 1:
        strength +=2
    if len(special_chars) > 1:
        strength +=3

    if len(password) <= 6:
        strength -= 3
    upper_chars = re.findall(r"[A-Z]", password)
    if len(upper_chars) < 1:
        strength -= 1
    lower_chars = re.findall(r"[a-z]", password)
    if len(lower_chars) < 1:
        strength -= 1

    strength = min(strength, 10)

    if strength < 3:
        strength_label.configure(text = "Weak", text_color = "red")
        strength_bar.set(0.1)
    elif strength < 5:
        strength_label.configure(text = "Fair", text_color = "yellow")
        strength_bar.set(0.3)
    elif strength < 7:
        strength_label.configure(text = "Good", text_color = "orange")
        strength_bar.set(0.6)
    elif strength < 9:
        strength_label.configure(text = "Strong", text_color = "green")
        strength_bar.set(0.8)
    else:
        strength_label.configure(text = "Excellent", text_color = "#00FF00")
        strength_bar.set(1)

def gen_set_password(password_var, password_confirm_var = None, strength_label = None, strength_bar = None, password_length = None, special_chars_num = None):
    """
    Generate a new password and set it in provided UI variables,
    optionally updating confirmation field and strength indicators.
    """
    if password_length and special_chars_num:
        new_password = generate_password(password_length, special_chars_num)
        password_var.set(new_password)
    else:
        new_password = generate_password()
        password_var.set(new_password)

    if password_confirm_var:
        password_confirm_var.set(new_password)
        password_strength(new_password, strength_label, strength_bar)

def toggle_password_visibility(password_entry, password_confirm_entry = None):
    """
    Toggle the "show" attribute of password entry widgets between hidden (*) and plaintext.
    """
    if password_entry.cget("show") == "*":
        password_entry.configure(show = "")
    else:
        password_entry.configure(show = "*")

    if password_confirm_entry:
        if password_confirm_entry.cget("show") == "*":
            password_confirm_entry.configure(show = "")
        else:
            password_confirm_entry.configure(show = "*")

def copy_to_clipboard(app, password):
    """
    Copy given text to the system clipboard and clear it after 10 seconds.
    """
    app.clipboard_clear()
    app.clipboard_append(password)
    app.update()

    app.after(10000, lambda: app.clipboard_clear())