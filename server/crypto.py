
def generate_RSA_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    return public_key, private_key

