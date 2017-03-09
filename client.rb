require 'net/http'
require 'uri'
require 'json'
require 'base64'
require 'openssl'
require 'securerandom'

# Global AES Key used for Encryption/Decryption
$gKey = nil
# Global AES IV used for Encryption/Decryption
$gIV = nil
$host = 'http://localhost:4567'
def encryptAES(data)
	cipher = OpenSSL::Cipher::AES128.new(:GCM)
	cipher.encrypt
	cipher.key = $gKey
	cipher.iv = $gIV
	# In this case, auth_data is unused, but required by GCM Mode
	cipher.auth_data = ""
	encrypted = cipher.update(data) + cipher.final
	# Data being sent contains encrypted data and auth Tag
	return cipher.auth_tag + encrypted
end

def decryptAES(msg)
	# Get Encrypted data
	data = msg[16..msg.length]
	# Get Auth tag
	tag = msg[0..15]
	cipher = OpenSSL::Cipher::AES128.new(:GCM)
	cipher.decrypt
	cipher.key = $gKey
	cipher.iv = $gIV
	# In this case, auth_data is unused, but required by GCM Mode
	cipher.auth_data = ""
	cipher.auth_tag = tag
	return cipher.update(data) + cipher.final
end

def craftBody(data)
	dataChunk = {
		"data" => Base64.encode64(data)
	}
	JSON.dump(dataChunk).chomp
end

def httpConn(link,body,reqType='text/json')
	uri = URI.parse(link)
	#header = {'Content-Type': 'text/json'}
	http = Net::HTTP.new(uri.host, uri.port)
	request = Net::HTTP::Post.new(uri.request_uri)
	request.body = body
	request['Content-Type'] = reqType
	return http.request(request)
end

def parseResponse(response)
	msg = JSON.parse(response.body)
	Base64.decode64(msg['msg']).chomp
end

# Call yahoo api from server
def yahoo(msg)
	body = encryptAES(msg)
	response = httpConn($host + '/yahoo',body, 'application/binary')
	puts decryptAES(response.body)
end

def runYahoo
	fellas = ["Alice","Bob","Colin","Dave","Eve","Ford","Gwen","Hipp","Iris"]
	for gz in fellas
		yahoo(gz)
	end
end

##########################
# Key Exchange using RSA #
##########################
def sendRSA
	# Create Random AES Key and Random Init Vector
	$gKey = SecureRandom.random_bytes(16)
	#UPDATE: To be honest, AES128-GCM mode requires 12 bytes of IV, so this must be changed
	#$gIV = SecureRandom.random_bytes(16)
	$gIV = SecureRandom.random_bytes(12)
	aesIV = Base64.encode64($gIV).chomp
	aesKey = Base64.encode64($gKey).chomp
	data = "This is the super Secret Message"
	msg = Base64.encode64(encryptAES(data)).chomp
	# AES Info will be send to Server. Type: JSON. Data in Base64 Format
	# key: AES Encryption Key 
	# iv : AES Init Vector 
	# msg: Test Message send to Server
	aesInfo = {
		"key" => aesKey,
		"iv" => aesIV,
		"msg"=> msg
	}
	# Encrypt Request Data using RSA Public Key
	rsaPub = OpenSSL::PKey::RSA.new File.read('pubkey.pub')
	dataChunk = rsaPub.public_encrypt(JSON.dump(aesInfo).chomp)
	#Create Request Body and send to server
	body= craftBody(dataChunk)
	response = httpConn($host + '/rsa',body)
	data = parseResponse(response)
	# Try to decrypt the encrypted Message sent from Server
	puts decryptAES(data)
	# Run the test
	runYahoo
end

###############################################
# Key Exchange using Diffie Hellman Epheemral #
###############################################
def sendDHE
	# Using Diffie Hellman with 256 bits size. According to security standards, the key size must be
	# at least 1024 bits. In this case i only use 256 bits to optimize performance.
	# Key size should not be smaller than 256 bits due to the use of shared secret (32 bytes) in this case
	clientDH = OpenSSL::PKey::DH.new(256)
	# DH Info to send to Server for Key Exchange. Type: JSON, data is in hex format
	# G: Base G 
	# p: Modulus p
	# A: CLient Public Key
	dhStruct = {
		"G" => clientDH.g.to_s(16),
		"p" => clientDH.p.to_s(16),
		"A" => clientDH.pub_key.to_s(16),
	}
	#Create Request Body and send to server
	body = craftBody(JSON.dump(dhStruct).chomp)
	response = httpConn($host + '/dhe',body)
	data = parseResponse(response)
	key = JSON.parse(data)
	# Get Server Public B and compute Shared Secret
	serverPub = key['B']
	shared = clientDH.compute_key(serverPub.to_i(16))
	# First 16 bytes of shared Secret will be used as Encryption Key. See server.rb
	$gKey = shared[0..15]
	# Next 16 bytes of shared secret will be used as Initial Vector. See server.rb
	#$gIV = shared[16..31]
	#UPDATE: To be honest, AES128-GCM mode requires 12 bytes of IV, so this must be changed
	$gIV = shared[16..27]
	# Try to decrypt the encrypted Message sent from Server
	puts decryptAES(Base64.decode64(key['text']))
	# Run the test
	runYahoo
end

##########################################3####################
# Key Exchange using Ellkiptic Curve Diffie Hellman Ephemeral #
###############################################################
def sendECDHE
	groupName = 'prime256v1'
	clientEC = OpenSSL::PKey::EC.generate(groupName)
	cPub = clientEC.public_key.to_bn
	# Client Public Send to Server. Type: JSON
	# cpub: CLient Public in hexadecimal Format
	ecStruct = {
		"cpub" => cPub.to_s(16)
	}
	# Encrypt Request Data using RSA Public Key
	rsaPub = OpenSSL::PKey::RSA.new File.read('pubkey.pub')
	dataChunk = rsaPub.public_encrypt(JSON.dump(ecStruct).chomp)
	#Create Request Body and send to server
	body= craftBody(dataChunk)
	#body = craftBody(JSON.dump(ecStruct).chomp)
	response = httpConn($host + '/ecdhe',body)
	data = parseResponse(response)
	key = JSON.parse(data)
	# Get Server Public and compute 
	serverPub = key['spub']
	# Convert Server Public to BigNumber, Server public current ly in Hex Format
	sPubBN = OpenSSL::BN.new(serverPub,16)
	# Create EC Point from Server BigNumber
	sPubGrp = OpenSSL::PKey::EC::Group.new(groupName)
	sPubPoint = OpenSSL::PKey::EC::Point.new(sPubGrp,sPubBN)
	# Compute shared Secret with provided Server Public
	shared = clientEC.dh_compute_key(sPubPoint)
	#First 16 bytes of shared Secret will be used as Encryption Key
	$gKey = shared[0..15]
	#Next 16 bytes of shared secret will be used as Initial Vector	
	#$gIV = shared[16..31]
	#UPDATE: To be honest, AES128-GCM mode requires 12 bytes of IV, so this must be changed
	$gIV = shared[16..27]
	puts decryptAES(Base64.decode64(key['text']))
	runYahoo
end

sendRSA
sendDHE
sendECDHE