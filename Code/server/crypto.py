from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import hashlib
import os


## @defgroup group1_crypto Cryptography methods
## Cryptography-related methods used throughout the whole project
##
## client, ttp and server applications use identical functions. Cryptographic operations (ex. encryption) are done using cryptography and hashlib libraries


## @ingroup group1_crypto
## @brief Generating a RSA key pair
## @details Generates a new 4096-bit RSA private key and derives the corresponding public key
## @return (RSAPublicKey, RSAPrivateKey) - generated keys
def generate_RSA_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    return public_key, private_key


## @ingroup group1_crypto
## @brief Serializing a public key
## @details Converts a RSA public key into PEM-encoded bytes
## @param public_key (RSAPublicKey) - public key to serialize.
## @return bytes - PEM-encoded public key
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


## @ingroup group1_crypto
## @brief Serializing a private key
## @details Converts an RSA private key into PEM-encoded bytes without encryption.
## @param private_key (RSAPrivateKey) - RSA private key to serialize
## @return bytes - PEM-encoded private key
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


## @ingroup group1_crypto
## @brief Deserializing a public key
## @details Loads an RSA public key from PEM-encoded bytes.
## @param serialized_public_key (bytes) - PEM-encoded public key
## @return RSAPublicKey - deserialized RSA public key
def deserialize_public_key(serialized_public_key):
    return serialization.load_pem_public_key(serialized_public_key)


## @ingroup group1_crypto
## @brief Deserializing a private key
## @details Loads an RSA private key from PEM-encoded bytes.
## @param serialized_private_key (bytes) - PEM-encoded private key
## @return RSAPrivateKey - deserialized RSA private key
def deserialize_private_key(serialized_private_key):
    return serialization.load_pem_private_key(serialized_private_key, password=None)


## @ingroup group1_crypto
## @brief Generating a random ID
## @details Generates a cryptographically secure random identifier using SHA-256.
## @return str - 64-character hexadecimal identifier
def generate_random_id():
    return hashlib.sha256(os.urandom(32)).hexdigest()


## @ingroup group1_crypto
## @brief Generating a certificate
## @details Creates and signs an X.509 certificate for a subject using the issuer's private key.
## @param subject_id (str) - identifier of the certificate subject
## @param subject_public_key (RSAPublicKey) - public key of the certificate subject
## @param issuer_id (str) - identifier of the certificate issuer
## @param issuer_private_key (RSAPrivateKey) - private key used to sign the certificate
## @return Certificate - signed X.509 certificate
def generate_certificate(subject_id, subject_public_key, issuer_id, issuer_private_key):
    builder = x509.CertificateBuilder()
    
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_id)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_id)]))
    builder = builder.public_key(subject_public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.now())
    builder = builder.not_valid_after(datetime.datetime.now() + datetime.timedelta(weeks=4))

    return builder.sign(issuer_private_key, hashes.SHA256())
    

## @ingroup group1_crypto
## @brief Serializing a certificate
## @details Converts an X.509 certificate into PEM-encoded bytes.
## @param cert (Certificate) - X.509 certificate to serialize
## @return bytes - PEM-encoded certificate
def serialize_certificate(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


## @ingroup group1_crypto
## @brief Deserializing a certificate
## @details Loads an X.509 certificate from PEM-encoded bytes.
## @param serialized_cert (bytes) - PEM-encoded certificate
## @return Certificate - deserialized X.509 certificate
def deserialize_certificate(serialized_cert):
    return x509.load_pem_x509_certificate(serialized_cert)


## @ingroup group1_crypto
## @brief Encrypting data
## @details Encrypts data using RSA-OAEP with SHA-256.
## @param public_key (RSAPublicKey) - RSA public key used for encryption
## @param data (bytes) - plaintext data for encryption
## @return bytes - RSA-encrypted ciphertext
def encrypt_data(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


## @ingroup group1_crypto
## @brief Decrypting data
## @details Decrypts RSA-OAEP encrypted data using SHA-256.
## @param private_key (RSAPrivateKey) - RSA private key used for decryption
## @param encrypted_data (bytes) - ciphertext to decrypt
## @return bytes - decrypted plaintext data
def decrypt_data(private_key, encrypted_data):
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


## @ingroup group1_crypto
## @brief Generating a AES key
## @details Generates a random 256-bit AES key.
## @return bytes - 32-byte AES key
def generate_aes_key():
    return os.urandom(32)


## @ingroup group1_crypto
## @brief Encrypting data with AES
## @details Encrypts plaintext using AES-256 in CFB mode. The generated IV is prepended to the ciphertext.
## @param key (bytes) - 32-byte AES key
## @param plaintext (bytes) - data for encryption
## @return bytes - IV concatenated with the encrypted ciphertext
def encrypt_aes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


## @ingroup group1_crypto
## @brief Decrypting data with AES
## @details Decrypts data encrypted with AES-256 in CFB mode. Expects the IV to be prepended to the ciphertext.
## @param key (bytes) - 32-byte AES key
## @param ciphertext (bytes) - IV and encrypted data
## @return bytes - decrypted plaintext
def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext


## @ingroup group1_crypto
## @brief Verifying validity of a certificate
## @details Verifies the authenticity of a certificate.
## @param cert (Certificate) - certificate to verify
## @param issuer_public_key (RSAPublicKey) - public RSA key of the certificate's issuer
## @return Boolean
## - True if certificate successfully verified
## - False if verification fails
## @exception Exception - caught internally when signature verification fails or when an invalid certificate and/or public key is provided.
def verify_certificate(cert, issuer_public_key):
    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception as e:
        return False