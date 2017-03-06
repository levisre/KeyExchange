require 'openssl'

key_pair = OpenSSL::PKey::RSA.generate(4096)

pub_key = key_pair.public_key
File.open("private_key", "w") { |f| f.write(key_pair.to_pem) }
File.open("pubkey.pub", "w") { |f| f.write(pub_key.to_pem) }
