import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# === Persistent Config ===
KEY_FILE = "fernet.key"
DATA_FILE = "stored_data.json"
MAX_ATTEMPTS = 3
MASTER_PASSWORD = "admin123"

# === Load or generate encryption key ===
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(KEY)

cipher = Fernet(KEY)

# === Load or initialize stored data ===
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

failed_attempts = st.session_state.get("failed_attempts", 0)

# === Utility Functions ===
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey.strip())
    entry = stored_data.get(encrypted_text.strip())

    if entry and entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.strip().encode()).decode()
    else:
        st.session_state.failed_attempts = st.session_state.get("failed_attempts", 0) + 1
        return None

# === Streamlit UI ===
st.set_page_config(page_title="Secure Data App", page_icon="🔐")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("📂 Navigation", menu)

if choice == "Home":
    st.header("🏠 Welcome!")
    st.markdown("""
    This app lets you **securely store and retrieve** your data using a custom passkey.
    - 💾 All data is saved to a file
    - 🔐 Uses **Fernet encryption** and **SHA-256 hashing**
    - 🔁 Locks you out after 3 failed attempts
    """)

elif choice == "Store Data":
    st.header("🗄️ Store New Data")
    user_data = st.text_area("✍️ Enter your text:")
    passkey = st.text_input("🔑 Set your passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey.strip())
            encrypted_text = encrypt_data(user_data.strip())
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data()
            st.success("✅ Your data has been securely stored!")
            st.code(encrypted_text, language="text")
        else:
            st.warning("⚠️ Please fill in both fields!")

elif choice == "Retrieve Data":
    st.header("🔍 Retrieve Encrypted Data")
    encrypted_text = st.text_area("📄 Paste the encrypted text:").strip()
    passkey = st.text_input("🔑 Enter your passkey:", type="password").strip()

    if st.button("Decrypt Data"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Successfully decrypted!")
                st.write("📂 Your Data:")
                st.code(decrypted_text, language="text")
                st.balloons()
            else:
                remaining = MAX_ATTEMPTS - st.session_state.get("failed_attempts", 0)
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")

                if remaining <= 0:
                    st.warning("🔒 Too many failed attempts. Please reauthorize via login page.")
                    st.success("✅ Please go to 'Login' from the sidebar to reauthorize.")
                    st.stop()
        else:
            st.warning("⚠️ Please provide both inputs.")

    if st.checkbox("🛠 Show Stored Data (Debug)"):
        st.json(stored_data)

elif choice == "Login":
    st.header("🔐 Reauthorization")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in successfully! Please now select 'Retrieve Data' from the sidebar.")
            st.stop()
        else:
            st.error("❌ Incorrect master password!")