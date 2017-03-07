# Create Keypair for use in RSA Encryption
require 'openssl'

# Key size is 4096 bit (RSA-4096)
key_pair = OpenSSL::PKey::RSA.generate(4096)

pub_key = key_pair.public_key
# Export Private Key and Public Key to PEM format
File.open("private_key", "w") { |f| f.write(key_pair.to_pem) }
File.open("pubkey.pub", "w") { |f| f.write(pub_key.to_pem) }
