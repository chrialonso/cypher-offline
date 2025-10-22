import os
import shutil
import sqlcipher3.dbapi2 as sqlcipher
import sqlite3
import time
import bcrypt
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from encryption import encrypt_password, decrypt_password, generate_salt, derive_key

# File and database paths
THEME_FILE = "theme.txt"
APPEAR_FILE = "appear.txt"
REMEMBER_ME_FILE = "remember_me.txt"
DB_FILE = 'cypherdb.db'
DB_BACKUP_FILE = 'cypherdb_backup.db'
SERVICE_NAME = "Cypher"
FILE_KEY_ID  = "cypher_file_key"
META_DB = "cypherdb_meta.db"

# Preference functions
def load_theme_preference():
    """
    Read and return the user's saved color theme from THEME_FILE.
    Returns default 'dark-blue' if no file exists.
    """
    if os.path.exists(THEME_FILE):
        with open(THEME_FILE, "r") as file:
            return file.read().strip()
    return "dark-blue"

def save_theme_preference(theme):
    """
    Save the given color theme string to THEME_FILE.
    """
    with open(THEME_FILE, "w") as file:
        file.write(theme)

def load_appear_preference():
    """
    Read and return the user's saved appearance mode from APPEAR_FILE.
    Returns default 'dark' if no file exists.
    """
    if os.path.exists(APPEAR_FILE):
        with open(APPEAR_FILE, "r") as file:
            return file.read().strip()
    return "dark"

def save_appear_preference(appear):
    """
    Save the given appearance mode string ('light', 'dark', etc.) to APPEAR_FILE.
    """
    with open(APPEAR_FILE, "w") as file:
        file.write(appear)

def save_username(remember_var, username):
    """
    Store or remove the remembered username based on remember_var state.
    If remember_var is 'on', writes username to REMEMBER_ME_FILE.
    Otherwise, deletes any existing REMEMBER_ME_FILE.
    """
    if remember_var.get() == "on":
        with open(REMEMBER_ME_FILE, "w") as file:
            file.write(username)
    else:
        if os.path.exists(REMEMBER_ME_FILE):
            os.remove(REMEMBER_ME_FILE)

def load_username(remember_var, username_entry):
    """
    Preload username from REMEMBER_ME_FILE into the GUI entry and set remember_var to 'on'.
    Does nothing if no saved username exists.
    """
    if os.path.exists(REMEMBER_ME_FILE):
        with open(REMEMBER_ME_FILE, "r") as file:
            saved_username = file.read().strip()
            username_entry.insert(0, saved_username)
            remember_var.set("on")

def backup_database():
    """
    Create a backup copy of the main database file.
    Returns True on success, False on I/O failure or if DB_FILE doesn't exist.
    """
    if os.path.exists(DB_FILE):
        try:
            print('Backing up existing database...')
            shutil.copy(DB_FILE, DB_BACKUP_FILE)
            return True
        except IOError as e:
            print(f'Could not backup database: {e}')
            return False

def database_exists():
    """
    True if the encrypted vault file exists.
    """
    return os.path.exists(DB_FILE)

def init_database():
    """
    Initialize a new SQLCipher database with a random DEK.
    Configures cipher settings, creates user and password tables,
    and returns the raw DEK for wrapping.
    """
    if database_exists():
        return None

    dek = os.urandom(32)
    conn = sqlcipher.connect(DB_FILE)
    conn.execute(f"PRAGMA hexkey = '{dek.hex()}';")
    conn.execute("PRAGMA cipher_page_size = 4096;")
    conn.execute("PRAGMA kdf_iter = 100000;")

    cursor = conn.cursor()
    cursor.execute("""
        create table if not exists users_local(
        id integer primary key autoincrement,
        username text unique not null);
    """)

    cursor.execute("""
        create table if not exists passwords(
        id integer primary key autoincrement,
        user_id integer not null,
        website text not null,
        login_username text not null,
        encrypted_password blob not null,
        created_on timestamp default current_timestamp,
        last_modified timestamp default current_timestamp,
        category text not null,
        favorite integer default 0,
        foreign key (user_id) references users_local(id) on delete cascade);
    """)

    conn.commit()
    conn.close()

    return dek

def init_meta_db():
    """
    Create metadata SQLite DB for user wrap records,
    login attempts, and configuration.
    """
    with sqlite3.connect(META_DB) as meta_conn:
        meta_conn.execute("""
        create table if not exists users_meta(
        username text primary key not null,
        salt blob not null,
        dek_iv blob not null,
        encrypted_dek blob not null,
        password_hash blob not null);
        """)

        meta_conn.execute("""
            create table if not exists login_attempts(
            username text primary key not null,
            attempts integer not null,
            last_attempt timestamp not null);
        """)

        meta_conn.execute("""
            create table if not exists config(
            key text primary key not null,
            value text not null);
        """)

        default_configs = {
                "max_attempts": "5",
                "lockout_time": "60"
        }

        for key, value in default_configs.items():
            meta_conn.execute("insert or ignore into config (key, value) values(?, ?)", (key, value))

def get_config_value(key):
    """
    Retrieve an integer configuration value by key from the config table.
    Returns None if key is not found.
    """
    with sqlite3.connect(META_DB) as meta_conn:
        cursor = meta_conn.cursor()
        cursor.execute("select value from config where key = ?", (key,))
        result = cursor.fetchone()
    meta_conn.close()
    return int(result[0]) if result else None

def connect_with_dek(dek):
    """
    Open and return a SQLCipher connection to the vault using the provided DEK.
    Enables foreign keys and re-applies cipher PRAGMAs.
    """
    conn = sqlcipher.connect(DB_FILE, check_same_thread=False)
    conn.execute(f"PRAGMA hexkey = '{dek.hex()}';")
    conn.execute("PRAGMA cipher_page_size = 4096;")
    conn.execute("PRAGMA kdf_iter = 100000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def load_wrap_record(username):
    """
    Fetch salt, IV, wrapped DEK, and password hash for a user from metadata.
    Raises ValueError if the user does not exist.
    """
    with sqlite3.connect(META_DB) as meta_conn:
        row = meta_conn.execute("select salt, dek_iv, encrypted_dek, password_hash from users_meta where username = ?", (username,)).fetchone()
    meta_conn.close()
    if not row:
        raise ValueError("User not found")
    return row

def save_wrap_record(username, salt, iv, encrypted_dek, password_hash):
    """
    Insert a new wrap record into metadata for a user.
    """
    with sqlite3.connect(META_DB) as meta_conn:
        cursor = meta_conn.cursor()
        cursor.execute("insert into users_meta (username, salt, dek_iv, encrypted_dek, password_hash) values (?, ?, ?, ?, ?)", (username, salt, iv, encrypted_dek, password_hash))
    meta_conn.close()

def open_for_user(username, master_password):
    """
    Authenticate the user, unwrap the DEK, and open their vault.
    Returns the SQLCipher connection, DEK, and local user_id.
    """
    salt, iv, encrypted_dek, password_hash = load_wrap_record(username)

    if not bcrypt.checkpw(master_password.encode(), password_hash):
        raise ValueError("Invalid username or password")

    # unwrap DEK
    kek = derive_key(master_password, salt)
    aesgcm = AESGCM(kek)
    dek = aesgcm.decrypt(iv, encrypted_dek, None)

    # open with the unwrapped DEK
    conn = connect_with_dek(dek)

    cursor = conn.cursor()
    cursor.execute("select id from users_local where username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise ValueError("Invalid username or password")
    user_id = row[0]
    return conn, dek, user_id

def create_user(username, master_password, conn, dek):
    """
    Register a new user by wrapping the DEK with a KEK derived from the
    master password and storing both vault and metadata records.
    Returns False if username already exists.
    """
    cursor = conn.cursor()

    #check for existing wrap record
    try:
        load_wrap_record(username)
        # if fetched a record, username is taken
        return False
    except ValueError:
        pass #continue

    # salt + hash
    salt = generate_salt()
    password_hash = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())

    # generate a key encrypted key (KEK) and encrypt (wrap) it
    wrap_key = derive_key(master_password, salt)
    aesgcm = AESGCM(wrap_key)
    iv = os.urandom(12)
    encrypted_dek = aesgcm.encrypt(iv, dek, None)
    save_wrap_record(username, salt, iv, encrypted_dek, password_hash)

    cursor.execute("insert into users_local (username) values (?)", (username,))
    conn.commit()
    return True

def bootstrap_first_user(username, master_password):
    """
    Initialize a new vault and metadata for the very first user.
    Returns True on success, raises RuntimeError if vault exists.
    """
    dek = init_database()
    if dek is None:
        raise RuntimeError("Database already initialized.")
    conn = connect_with_dek(dek)
    try:
        return create_user(username, master_password, conn, dek)
    finally:
        conn.close()

def verify_user(username, password, vault):
    """
    Verify user credentials against metadata. Returns local user_id or None.
    """
    vault_cursor = vault.cursor()
    vault_cursor.execute("select id from users_local where username = ?", (username,))
    row = vault_cursor.fetchone()

    if not row:
        return None
    user_id = row[0]

    try:
        with sqlite3.connect(META_DB) as meta_conn:
            cursor = meta_conn.cursor()
            cursor.execute("select password_hash from users_meta where username = ?", (username,))
            result = cursor.fetchone()
        meta_conn.close()

        # bcrypt.checkpw will raise ValueError if the hash is invalid
        if result and bcrypt.checkpw(password.encode(), result[0]):
            return user_id
    except sqlite3.Error as e:
        print(f"Database Error in verify_user: {e}")
    except ValueError:
        print("Error: Stored password hash is corrupted or invalid.")
    return None

def user_exists(username):
    """
    Return True if a wrap record exists for the given username.
    """
    with sqlite3.connect(META_DB) as meta_conn:
        cursor = meta_conn.cursor()
        cursor.execute("select username from users_meta where username = ?", (username,))
    meta_conn.close()
    return cursor.fetchone() is not None

def get_user_salt(username):
    """
    Retrieve the salt used for wrapping a user's DEK.
    """
    with sqlite3.connect(META_DB) as meta_conn:
        cursor = meta_conn.cursor()
        cursor.execute("select salt from users_meta where username = ?", (username,))
        salt = cursor.fetchone()

    meta_conn.close()

    if salt[0]:
        return salt[0]
    else:
        return None

def store_password(user_id, website, login_username, plain_password, category, encryption_key, top_level_domain, conn):
    """
    Encrypt and store a new credential entry in the vault.
    """

    website = normalize_website(website, top_level_domain)
    cursor = conn.cursor()
    encrypted_password = encrypt_password(plain_password, encryption_key)

    try:
        cursor.execute('insert into passwords (user_id, website, login_username, encrypted_password, category) values(?, ?, ?, ?, ?)', (user_id, website, login_username, encrypted_password, category))
    except sqlite3.Error as e:
        print(f"Error: {e}")

def get_login_data(user_id, encryption_key, conn, category = None, favorite = None):
    """
    Fetch and decrypt credentials for display, with optional filtering.
    """
    cursor = conn.cursor()

    data = []
    query = 'SELECT website, login_username, encrypted_password, created_on, id, category, favorite, last_modified FROM passwords WHERE user_id = ?'
    params = [user_id]

    if category and category != "All" and category != "Favorites":
        query += ' AND category = ?'
        params.append(category)

    if category == "Favorites" or favorite == "True":
        query += ' AND favorite = 1'

    cursor.execute(query, params)

    rows = cursor.fetchall()
    for website, login_username, encrypted_password, creation_date, password_id, category, is_favorite, modified in rows:
        try:
            decrypted_password = decrypt_password(encrypted_password, encryption_key)
            data.append((website, login_username, decrypted_password, creation_date, password_id, category, is_favorite, modified))
        except Exception as e:
            print(f'Error decrypting password for {website}: {e}')
            data.append((website, login_username, 'Error: Cannot decrypt',creation_date, password_id, category, is_favorite, modified))
    return data

def get_category(user_id, encryption_key, conn):
    """
    Return a list of (category, website) for grouping in the UI.
    """
    if encryption_key is None:
        raise Exception('Authentication required.')

    cursor = conn.cursor()

    categories = []

    cursor.execute('select category, website from passwords where user_id = ?',  (user_id,))
    rows = cursor.fetchall()
    for category, website in rows:
        decrypted_website = decrypt_password(website, encryption_key)
        categories.append((category, decrypted_website))
    return categories

def delete_login(user_id, password_id, conn):
    """
    Remove a credential entry from the vault.
    """
    cursor = conn.cursor()
    cursor.execute("delete from passwords where user_id = ? and id = ?", (user_id, password_id,))

def edit_login(user_id, old_username, old_website, new_website, new_login_username, new_password, encryption_key, conn):
    """
    Update an existing credential's details.
    Returns (success, message).
    """
    cursor = conn.cursor()
    cursor.execute('select id from passwords where user_id = ? and website = ? and login_username = ?', (user_id, old_website, old_username))
    result = cursor.fetchone()

    if not result:
        return False, "Login not found"

    new_encrypted_password = encrypt_password(new_password, encryption_key)

    try:
        cursor.execute("update passwords set website = ?, login_username = ?, encrypted_password = ?, last_modified = current_timestamp where user_id = ? and id = ?", (new_website, new_login_username, new_encrypted_password, user_id, result[0]))
        conn.commit()
        return True, "Login updated successfully!"
    except sqlite3.Error as e:
        conn.rollback()
        print(f'Error Editing Login: {e}')
        return False

def change_master_password(user_id, old_password, new_password, vault):
    """
    Change the master password: unwrap and re-wrap the DEK,
    re-encrypt all stored credentials, and update metadata.
    """
    vault_cursor = vault.cursor()

    vault_cursor.execute('select username from users_local where id = ? ', (user_id,))
    row = vault_cursor.fetchone()

    if not row:
        return False, 'User not found'
    username = row[0]

    try:
        salt, old_iv, encrypted_dek, password_hash = load_wrap_record(username)
    except ValueError:
        return False, "User not found in metadata"

    if not bcrypt.checkpw(old_password.encode(), password_hash):
        return False, 'Wrong password'

    old_encryption_key = derive_key(old_password, salt)
    aesgcm = AESGCM(old_encryption_key)
    try:
        dek = aesgcm.decrypt(old_iv, encrypted_dek, None)
    except Exception:
        return False, "Failed to unwrap DEK, data may be corrupted"

    new_salt = generate_salt()
    new_wrap_key = derive_key(new_password, new_salt)
    aesgcm2 = AESGCM(new_wrap_key)
    new_iv = os.urandom(12)
    new_wrapped_key = aesgcm2.encrypt(new_iv, dek, None)
    new_password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())

    vault_cursor.execute("select id, encrypted_password from passwords where user_id = ?", (user_id,))
    for pwd_id, blob in vault_cursor.fetchall():
        # decrypt with old master‑derived key
        old_cipher = blob
        plain = decrypt_password(old_cipher, old_encryption_key)

        # re‑encrypt with new master‑derived key
        new_cipher = encrypt_password(plain, new_wrap_key)
        vault_cursor.execute(
            "update passwords set encrypted_password = ? where id = ?",
            (new_cipher, pwd_id))

    # commit the vault changes
    vault.commit()

    # 7) Update metadata DB
    with sqlite3.connect(META_DB) as meta_conn:
        meta_c = meta_conn.cursor()
        meta_c.execute("""
            update users_meta set salt = ?, dek_iv = ?, encrypted_dek = ?, password_hash = ? where username = ?""", (new_salt, new_iv, new_wrapped_key, new_password_hash, username))

    meta_conn.close()
    return True, "Master password updated successfully"

def delete_master_user(user_id, password, vault):
    """
    Delete a user's account: remove wrap record and all vault data.
    If last user, remove vault and metadata files as well.
    """
    vault_cursor = vault.cursor()
    vault_cursor.execute('select username from users_local where id = ?', (user_id,))
    username = vault_cursor.fetchone()[0]

    if not username:
        return False, f'User {username} not found.'

    with sqlite3.connect(META_DB) as meta_conn:
        meta_cursor = meta_conn.cursor()
        meta_cursor.execute("select password_hash from users_meta where username = ?",(username,))
        row = meta_cursor.fetchone()

        if not row:
            return False, "User not found"
        stored_hash = row[0]

        if not bcrypt.checkpw(password.encode(), stored_hash):
            return False, "Incorrect password"

        # delete wrap record
        meta_cursor.execute("delete from users_meta where username = ?",(username,))
        meta_cursor.execute("select count(*) from users_meta")
        remaining = meta_cursor.fetchone()[0]

    meta_conn.close()

    # 2) Delete from vault (SQLCipher)
    vault_cursor = vault.cursor()
    # find the vault‐internal user_id

    # remove all their credentials
    vault_cursor.execute("delete from passwords where user_id = ?", (user_id,))
    # remove the user record
    vault_cursor.execute("delete from users_local where id = ?", (user_id,))
    vault.commit()

    if remaining == 0:
        vault.close()
        for path in (DB_FILE, DB_BACKUP_FILE, META_DB):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    return True, "Account and all data deleted successfully"

def get_login_info(username):
    """
    Check if a username is currently allowed to attempt login.
    Uses config values 'max_attempts' and 'lockout_time'.
    Returns False if locked out, True otherwise.
    """
    now = int(time.time())
    with sqlite3.connect(META_DB) as meta_conn:
        cursor = meta_conn.cursor()
        cursor.execute("select attempts, last_attempt from login_attempts where username = ?", (username,))
        result = cursor.fetchone()

    meta_conn.close()
    if result:
        if result[0] >= int(get_config_value("max_attempts")) and (now - result[1]) < get_config_value("lockout_time"):
            return False
    return True

def reset_attempts(username):
    """
    Clear all recorded login attempts for a user, resetting lockout state.
    """
    with sqlite3.connect(META_DB) as meta_conn:
        cursor = meta_conn.cursor()
        cursor.execute("delete from login_attempts where username = ?", (username,))
    meta_conn.close()

def increment_attempts(username):
    """
    Increment failed login count and update timestamp.
    Inserts new record if none exists.
    """
    now = int(time.time())
    with sqlite3.connect(META_DB) as meta_conn:
        cursor = meta_conn.cursor()
        cursor.execute("select * from login_attempts where username = ?", (username,))
        result = cursor.fetchone()

    if result:
        cursor.execute("update login_attempts set attempts = attempts + 1, last_attempt = ? where username = ?", (now, username))
        meta_conn.close()
    else:
        cursor.execute("insert into login_attempts(username, attempts, last_attempt) values (?, ?, ?)", (username, 1, now))
        meta_conn.close()
    return False

def toggle_favorite(password_id, is_favorite, encryption_key, conn):
    """
    Mark or unmark a password entry as favorite.
    Requires valid encryption key for authentication.
    """
    if not encryption_key:
        raise Exception('Authentication required.')

    new_val = 1 if is_favorite.get() == "on" else 0

    cursor = conn.cursor()
    cursor.execute("update passwords set favorite = ? where id = ?", (new_val, password_id))

def normalize_website(website, top_level_domain = None):
    """
    Extract domain from URL or name, add a top-level domain if missing.
    """
    parsed_url = urlparse(website)
    domain = parsed_url.netloc if parsed_url.netloc else website
    domain = domain.replace("www.", "")

    if "." not in domain and top_level_domain is not None:
        return domain.lower() + top_level_domain
    else:
        return domain.lower()
