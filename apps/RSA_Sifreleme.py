# RSA Şifreleme
p = 1001234569  # 10 haneli bir asal sayı
q = 1987654421  # 10 haneli bir diğer asal sayı
n = p * q
# Euler Totient (phi) = (p - 1) * (q - 1)
phi = (p - 1) * (q - 1)


e = 65537  # 1 < e < phi ve gcd(e, phi) = 1 olmalıdır.

# Euler Totint ile e'nin aralarında asal olması gerekir. 
# Bu nedenle e genellikle 65537 olarak seçilir. phi ile e arakarında asal olduğu sürece
# Başka bir sayı da seçilebilir. 

d = pow(e, -1, phi) # Modüler ters pow(taban, üs, mod)
# e x d ≡ 1 (mod phi) olacak şekilde d hesaplanır.
# 65537 x d ≡ 1 (mod phi) olacak şekilde d hesaplanır.
# e ile d sayılarını çarptığımızda ve 
# sonucu phi sayısına böldüğümüzde kalan 1 olmalıdır.
# 65537 (e) * 319512942087840833 (d) / 1990108314541990560 (phi) -> Kalan 1

# Şifrelenecek sayısal metin (n değerinden küçük olmalıdır)
sifrelenmek_istenen_metin = "YILMAZ"
# ASCII -> Y = 89, I = 73, L = 76, M = 77, A = 65, Z = 90
"""
Sayıya Dönüştürme (Big-Endian): Her bayt 256'nın kuvvetleriyle çarpılarak toplanır
• (89×256⁵ + 73×256⁴ + 76×256³ + 77×256² + 65×256¹ + 90×256⁰).
• Ortaya Çıkan Sayısal Mesaj (M): 98.174.160.159.066
# ASCII değerini üç haneye tamamlamak için yapılır.
"""

# Metni sayıya dönüştürme (Big-Endian)
sayisal_metin = int.from_bytes(sifrelenmek_istenen_metin.encode('utf-8'), byteorder='big')
print("Sayısal Metin:", sayisal_metin)  # Çıktı: 98171347616090

# Mesaj n'den küçük olmalıdır
assert sayisal_metin < n

# Şifreleme: C = (sayisal_metin^e) mod n
sifreli_metin = pow(sayisal_metin, e, n)
print("Şifreli Veri:", sifreli_metin)

# Şifre Çözme: M = (sifreli_metin^d) mod n
cozulen_sayi = pow(sifreli_metin, d, n)
print("Çözülen Veri:", cozulen_sayi)

#Sayıyı tekrar metne çevirme (Şifre çözüldükten sonra)
cozulen_metin = sayisal_metin.to_bytes((sayisal_metin.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
print("Çözülen Metin:", cozulen_metin)  # Çıktı: YILMAZ

