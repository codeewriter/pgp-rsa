from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


# ====== Membuat RSA key pair ======
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key_pem = key.export_key().decode()
    public_key_pem = key.publickey().export_key().decode()
    return key, key.publickey(), private_key_pem, public_key_pem


# ====== AES Encryption ======
def encrypt_message_with_aes(message: bytes, aes_key: bytes):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))
    return ct_bytes, cipher.iv


# ====== AES Key Encryption with RSA ======
def encrypt_key_with_rsa(aes_key: bytes, rsa_public_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key


# ====== RSA Key Decryption ======
def decrypt_key_with_rsa(encrypted_key: bytes, rsa_private_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key


# ====== AES Message Decryption ======
def decrypt_message_with_aes(ciphertext: bytes, aes_key: bytes, iv: bytes):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt


# ====== MAIN PROGRAM ======
if __name__ == "__main__":
    print("===== PGP Simulation: Pertukaran Kunci Menggunakan RSA + AES =====\n")

    # 1. Input dari Pengguna
    user_input = input("Masukkan pesan yang ingin dienkripsi: ")
    message = user_input.encode()

    # 2. Penerima Membuat RSA Key Pair
    print("\n🔐 Penerima membuat RSA Key Pair...")
    private_key_obj, public_key_obj, private_key_str, public_key_str = generate_rsa_keys()

    print("\n📌 === SIMULASI ===")
    print("📤 Kirim public key ini ke pengirim:\n")
    print(public_key_str)

    input("\n🔁 Tekan Enter setelah public key dikirim dan siap digunakan oleh pengirim...")

    # 3. Pengirim Memasukkan Public Key Penerima
    print("\n📥 Pengirim memasukkan public key penerima (paste dari atas):")
    input_pub_key_str = ""
    print("Tempelkan public key di bawah ini (akhiri dengan garis kosong):")
    while True:
        line = input()
        if line.strip() == "":
            break
        input_pub_key_str += line + "\n"

    try:
        input_public_key = RSA.import_key(input_pub_key_str)
    except Exception as e:
        print("❌ Gagal memproses public key! Error:", e)
        exit()

    # 4. Pengirim membuat AES key dan mengenkripsi pesan
    print("\n✉️ Mengenkripsi pesan dengan AES...")
    aes_key = get_random_bytes(16)  # 128-bit
    ciphertext, iv = encrypt_message_with_aes(message, aes_key)

    print("✅ Pesan terenkripsi (AES):", base64.b64encode(ciphertext).decode())

    # 5. Pengirim mengenkripsi AES key menggunakan RSA public key penerima
    print("\n🔒 Mengenkripsi AES key dengan RSA Public Key penerima...")
    encrypted_aes_key = encrypt_key_with_rsa(aes_key, input_public_key)
    print("✅ AES key terenkripsi (RSA):", base64.b64encode(encrypted_aes_key).decode())

    # 6. Penerima mendekripsi AES key menggunakan RSA Private Key
    print("\n🔓 Mendekripsi AES key menggunakan RSA Private Key penerima...")
    decrypted_aes_key = decrypt_key_with_rsa(encrypted_aes_key, private_key_obj)

    # 7. Penerima mendekripsi pesan menggunakan AES key
    print("📩 Mendekripsi pesan dengan AES...")
    decrypted_message = decrypt_message_with_aes(ciphertext, decrypted_aes_key, iv)

    # 8. Output
    print("\n===== HASIL =====")
    print("📨 Pesan asli     :", user_input)
    print("📬 Pesan diterima :", decrypted_message.decode())
