import os
import struct
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- 1. GÜVENLİ ANAHTAR TÜRETME (KDF) ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Paroladan PBKDF2-HMAC-SHA256 kullanarak 256-bit anahtar türetir."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 için 32 bayt
        salt=salt,
        iterations=480000, # NIST 2024 önerilerine uygun iterasyon sayısı
    )
    return kdf.derive(password.encode())

# --- 2. ÜRETİM ORTAMI İÇİN AES-GCM SINIFI ---
class SecureAEADChannel:
    def __init__(self, password: str, device_id: int):
        # Gerçek senaryoda bu 'salt' veritabanında parolaya/kullanıcıya özel saklanır.
        self.salt = os.urandom(16) 
        self.key = derive_key(password, self.salt)
        self.aesgcm = AESGCM(self.key)
        
        # Nonce için Cihaz/Oturum ID'si (4 bayt)
        self.device_id = device_id
        # Nonce için artan sayaç (8 bayt)
        self.message_counter = 0

    def get_next_nonce(self) -> bytes:
        """
        12 Bayt Nonce Üretimi: [4 Bayt Device ID] + [8 Bayt Sayaç]
        Aynı anahtar ile asla aynı Nonce üretilmemesini garanti altına alır.
        """
        # >I: 4-byte unsigned int (Big Endian)
        # Q: 8-byte unsigned long long
        nonce = struct.pack(">I Q", self.device_id, self.message_counter)
        self.message_counter += 1
        return nonce

    def encrypt_message(self, plaintext: bytes, aad: bytes) -> tuple:
        nonce = self.get_next_nonce()
        # AESGCM şifreler ve Auth Tag'i ciphertext'in sonuna otomatik ekler
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    def decrypt_message(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        # Auth Tag uyuşmazsa veya veri bozulmuşsa InvalidTag fırlatır
        return self.aesgcm.decrypt(nonce, ciphertext, aad)


# --- 3. TEST VE SİMÜLASYON ---
def production_ready_demo():
    print("--- Güvenli Yazılım Geliştirme: Üretim Standartlarında AES-GCM ---\n")
    
    # İletişim kanalını başlatan cihaz (Örn: Cihaz ID 101)
    channel = SecureAEADChannel(password="CokGuvenliParola!2026", device_id=101)
    
    plaintext = b"Lisans Kriptografi Dersi: Deterministik Nonce ve KDF Uygulamasi."
    header_aad = b"Network-Header-v2.0"

    # 1. Mesajın Şifrelenmesi
    nonce1, ciphertext1 = channel.encrypt_message(plaintext, header_aad)
    print(f"[+] Mesaj 1 Sifrelendi.")
    print(f"    Nonce (Hex) : {nonce1.hex()} (Sayac: 0)")
    print(f"    Ciphertext  : {ciphertext1.hex()[:32]}... (kisaltildi)\n")

    # 2. Mesajın Şifrelenmesi (Sayacın arttığını göstermek için)
    nonce2, ciphertext2 = channel.encrypt_message(b"Ikinci Paket", header_aad)
    print(f"[+] Mesaj 2 Sifrelendi.")
    print(f"    Nonce (Hex) : {nonce2.hex()} (Sayac: 1)\n")

    # 3. Başarılı Deşifreleme İşlemi
    try:
        decrypted = channel.decrypt_message(nonce1, ciphertext1, header_aad)
        print(f"[+] Basarili Desifreleme (Mesaj 1): {decrypted.decode()}")
    except InvalidTag:
        print("[-] Hata: Orijinal mesaj 1 dogrulanamadi.")

    # 4. Bütünlük Bozulma (Man-in-the-Middle) Testi
    print("\n--- Saldiri Simülasyonu ---")
    tampered_aad = b"Network-Header-v2.1" # AAD manipüle edildi
    try:
        channel.decrypt_message(nonce1, ciphertext1, tampered_aad)
    except InvalidTag:
        print("[OK] AAD manipülasyonu yakalandi. PyCA 'InvalidTag' firlatti. Paket çöpe atildi!")

if __name__ == "__main__":
    production_ready_demo()