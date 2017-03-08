require 'openssl'

# For Example, key size is 1024 bits length
keysize = 1024
dhInstance = OpenSSL::PKey::DH.new(keysize)
# Save to file
File.open('dhparam.pem','w') { |f| f.write(dhInstance.public_key.to_pem) }