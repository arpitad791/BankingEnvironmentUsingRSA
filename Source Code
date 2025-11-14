"""
secure_bank_simulation.py

Refactored version of your original code: same logic and behavior,
organized into clear modules/functions and enriched with explanatory comments.

Features preserved (unchanged behavior):
 - Fermat primality test
 - Euler (Solovay–Strassen) primality test with Jacobi symbol
 - RSA key generation (returns same tuple shape)
 - RSA encrypt/decrypt (char-by-char as in original)
 - Transaction creation, OTP, file encryption demo, logging
 - ipywidgets interactive transaction UI

Dependencies:
 pip install sympy cryptography ipywidgets
"""

import random
import secrets
import logging
from datetime import datetime

from sympy import gcd, mod_inverse

# -----------------------
# Logging configuration
# -----------------------
logging.basicConfig(
    filename="crypto_log.txt",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def log_event(event: str) -> None:
    """Write an event message to log file and print a short console message."""
    logging.info(event)
    print("📝 LOG:", event)


# -----------------------
# Primality testing
# -----------------------
def is_prime_fermat(n: int, k: int = 5) -> bool:
    """
    Fermat primality test.
    Returns True if n is probably prime, False if composite.
    k: number of random bases to try (increases confidence).
    """
    if n <= 1:
        return False
    # small n quick pass
    if n <= 3:
        return True
    for _ in range(k):
        # choose random base a in [2, n-2]
        a = random.randint(2, n - 2)
        # Fermat's little theorem check
        if pow(a, n - 1, n) != 1:
            return False
    return True


def jacobi(a: int, n: int) -> int:
    """
    Compute Jacobi symbol (a/n).
    Returns -1, 0, or 1. Used by the Solovay–Strassen (Euler) test.
    """
    if n % 2 == 0:
        return 0
    a %= n
    result = 1
    while a:
        # factor out powers of two from a
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        # swap a and n (quadratic reciprocity trick)
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def is_prime_euler(n: int, k: int = 5) -> bool:
    """
    Solovay–Strassen (often referred to here as Euler) primality test.
    Returns True if n is probably prime, False if composite.
    """
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        j = jacobi(a, n)
        # j == 0 means composite (a is a quadratic residue indicator)
        if j == 0:
            return False
        # compute a^{(n-1)/2} mod n and compare with jacobi (mod n)
        if pow(a, (n - 1) // 2, n) != j % n:
            return False
    return True


# -----------------------
# Prime / key generation
# -----------------------
def generate_prime(method: str = "euler", start: int = 1000, end: int = 5000) -> int:
    """
    Generate a single prime in [start, end] using the chosen method.
    method: 'euler' (Solovay–Strassen) or 'fermat'
    (This loops until a prime candidate passes the chosen test.)
    """
    assert method in ("euler", "fermat"), "method must be 'euler' or 'fermat'"
    tester = is_prime_euler if method == "euler" else is_prime_fermat
    while True:
        p = random.randint(start, end)
        if tester(p):
            return p


def generate_rsa_keys(method: str = "euler"):
    """
    Generate RSA keypair using primes obtained via the selected primality test.
    Returns:
      (e, n), (d, n), (p, q, phi)
    (Matches the original output shape from your code.)
    """
    p = generate_prime(method)
    q = generate_prime(method)
    # ensure distinct primes
    while q == p:
        q = generate_prime(method)

    n = p * q
    phi = (p - 1) * (q - 1)

    # standard public exponent
    e = 65537
    # if e not coprime to phi, step to next odd until coprime
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)
    # mod_inverse from sympy returns the modular inverse (or raises if not possible)
    return (e, n), (d, n), (p, q, phi)


# -----------------------
# RSA encrypt / decrypt
# -----------------------
def rsa_encrypt(message: str, public_key: tuple) -> list:
    """
    Encrypt string message using public_key (e, n).
    Character-wise encoding using ord(), as in original code.
    Returns a list of integers (ciphertext blocks per character).
    """
    e, n = public_key
    return [pow(ord(c), e, n) for c in message]


def rsa_decrypt(cipher: list, private_key: tuple) -> str:
    """
    Decrypt list of integers cipher using private_key (d, n).
    Returns reconstructed string via chr().
    """
    d, n = private_key
    return ''.join(chr(pow(c, d, n)) for c in cipher)


# -----------------------
# Transaction and file demo utilities
# -----------------------
def create_transaction(from_account: str, to_account: str, amount: str) -> dict:
    """Build a transaction dictionary and include timestamp + secure OTP."""
    transaction = {
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "otp": str(secrets.randbelow(999999)).zfill(6)
    }
    return transaction


def demo_transaction_flow(method: str = "euler"):
    """
    Demonstration of generating keys, encrypting a transaction, sending it,
    decrypting it on the bank side, and checking integrity.
    """
    # Generate bank keys using the requested primality test
    public_bank, private_bank, _ = generate_rsa_keys(method)
    log_event(f"Bank RSA keys generated using {method} test (n bit-length: {public_bank[1].bit_length()})")

    # Prepare a sample transaction
    transaction = create_transaction("1234567890", "0987654321", "₹25,000")
    transaction_str = str(transaction)
    print("\n💳 Transaction Data (before encryption):")
    print(transaction_str)

    # Encrypt using bank's public key
    cipher = rsa_encrypt(transaction_str, public_bank)
    print("\n🔒 Encrypted (sent over network):", cipher[:10], "...")

    # Simulate bank decrypting with private key
    decrypted = rsa_decrypt(cipher, private_bank)
    print("\n✅ Bank received and decrypted message:")
    print(decrypted)

    # Integrity check
    print("\nIntegrity check:", "✅ Passed" if decrypted == transaction_str else "❌ Failed")


def file_encrypt_demo():
    """
    Demonstrate file encryption: write a sample text file, generate a new keypair,
    encrypt the file text, write cipher to file, and decrypt back to verify.
    """
    text = "Your account balance update request has been received securely."
    open("bank_msg.txt", "w").write(text)

    public_key, private_key, _ = generate_rsa_keys("euler")

    # Read plaintext, encrypt and save ciphertext as space-separated ints
    msg = open("bank_msg.txt").read()
    cipher = rsa_encrypt(msg, public_key)
    open("bank_cipher.txt", "w").write(' '.join(map(str, cipher)))

    # Read back ciphertext and decrypt
    cipher_data = list(map(int, open("bank_cipher.txt").read().split()))
    decrypted = rsa_decrypt(cipher_data, private_key)
    print("Decrypted text:\n", decrypted)


# -----------------------
# OTP and AES key demo
# -----------------------
def demo_otp_and_aes():
    """Show OTP generation and AES key-length demo (informational)."""
    secure_otp = str(secrets.randbelow(1_000_000)).zfill(6)
    print("Secure OTP:", secure_otp)

    aes_key = secrets.token_bytes(32)
    print("AES key length:", len(aes_key), "bytes")
    # Note: actual AES encryption not implemented here; this matches the original script.


# -----------------------
# IPython interactive UI (keeps original behavior)
# -----------------------
def launch_ipywidgets_ui():
    """
    Launch a simple ipywidgets-based interactive interface.
    This is optional and runs in Jupyter / IPython environments.
    """
    try:
        from ipywidgets import interact, widgets
        from IPython.display import display
    except Exception:
        print("ipywidgets not available in this environment. Skipping UI launch.")
        return

    @interact(
        from_account=widgets.Text(value='1234567890', description='From:'),
        to_account=widgets.Text(value='0987654321', description='To:'),
        amount=widgets.Text(value='₹5000', description='Amount:')
    )
    def make_transaction(from_account, to_account, amount):
        txn = {
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "otp": str(secrets.randbelow(999999)).zfill(6),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        print("📤 Transaction ready:")
        print(txn)
        log_event(f"Transaction created: {txn}")


# -----------------------
# Enhanced demo with interactive button (original notebook UI)
# -----------------------
def launch_notebook_simulator():
    """
    Recreates the original interactive notebook flow with a submit button
    (uses ipywidgets). Safe to call in Jupyter only.
    """
    try:
        from ipywidgets import widgets
        from IPython.display import display, clear_output
    except Exception:
        print("ipywidgets not available. Notebook simulator not launched.")
        return

    public_bank, private_bank = generate_rsa_keys()
    log_event(f"Generated RSA keys using Euler test (n={public_bank[1].bit_length()} bits)")

    def submit_transaction(from_acc, to_acc, amount):
        clear_output()
        display(title)
        log_event("New transaction initiated.")

        txn = {
            "from_account": from_acc,
            "to_account": to_acc,
            "amount": amount,
            "otp": str(secrets.randbelow(999999)).zfill(6),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        txn_str = str(txn)
        print("💳 Transaction Data:")
        print(txn)
        log_event("Transaction data prepared.")

        cipher = rsa_encrypt(txn_str, public_bank)
        print("\n🔒 Encrypted data (sent over network):")
        print(cipher[:10], "...")
        log_event("Transaction encrypted with bank's public key.")

        decrypted = rsa_decrypt(cipher, private_bank)
        print("\n🏦 Bank decrypted transaction:")
        print(decrypted)
        log_event("Bank successfully decrypted transaction.")

        print("\nIntegrity check:", "✅ Passed" if decrypted == txn_str else "❌ Failed")

    title = widgets.HTML(value="<h3>🏦 Secure Banking Transaction Simulator (RSA + Euler Keygen)</h3>")
    from_acc = widgets.Text(value='1234567890', description='From:')
    to_acc = widgets.Text(value='0987654321', description='To:')
    amount = widgets.Text(value='₹5000', description='Amount:')
    submit_btn = widgets.Button(description="Submit Transaction", button_style='success')

    submit_btn.on_click(lambda b: submit_transaction(from_acc.value, to_acc.value, amount.value))
    display(title, from_acc, to_acc, amount, submit_btn)


# -----------------------
# Main guard - preserves original runtime behavior
# -----------------------
if __name__ == "__main__":
    # Keep behavior equivalent to your original script:
    # - generate keys via Euler test and print them
    public_bank, private_bank, _ = generate_rsa_keys("euler")
    print("🏦 Bank Public Key:", public_bank)
    print("🔐 Bank Private Key:", private_bank)

    # Demonstration of a transaction being encrypted, sent, and decrypted
    transaction = create_transaction("1234567890", "0987654321", "₹25,000")
    transaction_str = str(transaction)
    print("\n💳 Transaction Data (before encryption):")
    print(transaction_str)

    cipher = rsa_encrypt(transaction_str, public_bank)
    print("\n🔒 Encrypted (sent over network):", cipher[:10], "...")

    decrypted = rsa_decrypt(cipher, private_bank)
    print("\n✅ Bank received and decrypted message:")
    print(decrypted)

    print("\nIntegrity check:", "✅ Passed" if decrypted == transaction_str else "❌ Failed")

    # File-based encryption demo (exactly as in your original code)
    text = "Your account balance update request has been received securely."
    open("bank_msg.txt", "w").write(text)

    public_key, private_key, _ = generate_rsa_keys("euler")

    msg = open("bank_msg.txt").read()
    cipher = rsa_encrypt(msg, public_key)
    open("bank_cipher.txt", "w").write(' '.join(map(str, cipher)))

    cipher_data = list(map(int, open("bank_cipher.txt").read().split()))
    decrypted = rsa_decrypt(cipher_data, private_key)
    print("Decrypted text:\n", decrypted)

    # Logging demo
    log_event("Session started")
    log_event("RSA keypair generated using Euler test")

    # OTP & AES demo
    demo_otp_and_aes()

    # If running in a Jupyter notebook, user can call:
    # launch_ipywidgets_ui() or launch_notebook_simulator()
