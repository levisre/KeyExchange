require 'sinatra'
require 'json'
require 'openssl'
require 'base64'
require 'securerandom'

set :show_exceptions, false
# Global AES Key used for Encryption/Decryption
$gKey = nil


error 500 do
	'0mG, Th15 15 $h!t! W@tCh 0uT, dUd3...'	
end

def decryptRSA(data)
	privateKey = OpenSSL::PKey::RSA.new File.read("private_key")
	return privateKey.private_decrypt(data)
end

def encryptAES(msg)
	cipher = OpenSSL::Cipher::AES128.new(:GCM)
	cipher.encrypt
	cipher.key = $gKey
	# randomize ID, will be sent alongside with encrypted data
	iv = cipher.random_iv
	# In this case, auth_data is unused, but required by GCM Mode
	cipher.auth_data = ''
	encrypted = cipher.update(msg) + cipher.final
	# Data being sent = auth_tag(16 bytes) + iv(12 bytes) + encrypteddata
	return cipher.auth_tag + iv + encrypted
end

def decryptAES(msg)
	# Get Auth tag = First 16 bytes
	tag = msg[0..15]
	# Get init vector = Next 12 bytes
	iv = msg[16..27]
	# Get Encrypted data = the rest
	data = msg[28..msg.length]
	cipher = OpenSSL::Cipher::AES128.new(:GCM)
	cipher.decrypt
	cipher.key = $gKey
	cipher.iv = iv
	cipher.auth_tag = tag
	# In this case, auth_data is unused, but required by GCM Mode
	cipher.auth_data = ''
	return cipher.update(data) + cipher.final
end

def parseRequest(request)
	# Request type: JSON
	# {"data": <BASE64_DATA>}
	request.body.rewind
	begin
		reqData = JSON.parse(request.body.read)
		Base64.decode64(reqData['data'])
	rescue
		error 500
	end
end

def craftResponse(data)
	# Response Type: JSON
	# {"msg": <BASE64_DATA>}
	response = {
		"msg" => Base64.encode64(data).chomp
	}
	JSON.dump(response).chomp
end

get '/' do
	'Yay, i\'m up and running'
end

##########################
# Key Exchange using RSA #
##########################
post '/rsa' do
	content_type:json
	reqData = parseRequest(request)
	#The AES Key and IV are encrypted by Public key at Client Side, So we need to decrypt it first
	begin
		msgStruct = JSON.parse(decryptRSA(reqData))
		$gKey = Base64.decode64(msgStruct['key'])
		#$gIV = Base64.decode64(msgStruct['iv'])
		# Try to decrypt an encrypted Message sent by Client to see the AES Key works or not
		secmsg = Base64.decode64(msgStruct['msg'])
		msg = decryptAES(secmsg)
		# Encrypt and send it back to Client to test thaat the encryption Routine work on both sides
		retmsg = 'You sent : ' + msg
		data = encryptAES(retmsg)
		craftResponse(data)
	rescue
		error 500
	end
end

###############################################
# Key Exchange using Diffie Hellman Ephemeral #
###############################################
post '/dhe' do
	content_type:json
	reqData = parseRequest(request)
	begin
		data = JSON.parse(reqData)
		serverDH = OpenSSL::PKey::DH.new
		#Get the base number (G) and modulus (p) sent by Client
		serverDH.g = data['G'].to_i(16)
		serverDH.p = data['p'].to_i(16)
		serverDH.generate_key!
		#Server compute shared Secret from Public A sent by client
		sharedSecret = serverDH.compute_key(data['A'].to_i(16))
		#First 16 bytes of shared Secret will be used as Encryption Key
		$gKey = sharedSecret[0..15]
		#Server return Public B and a test message encrypted by AES with key and IV created by shared Secret
		new_msg = encryptAES("DHE Key Exchange Success!")
		data = {
			"B" => serverDH.pub_key.to_s(16), 
			"text" => Base64.encode64(new_msg).chomp
		}
		craftResponse(JSON.dump(data).chomp)
	rescue
		error 500
	end
end

##########################################3####################
# Key Exchange using Ellkiptic Curve Diffie Hellman Ephemeral #
###############################################################

post '/ecdhe' do
	content_type:json
	reqData = parseRequest(request)
	begin
		groupName = "prime256v1"
		# The Client Public is encrypted by RSA at client side, so we need to use RSA Private to decrypt it
		data = JSON.parse!(decryptRSA(reqData))
		# Convert Client Public to BigNumber, Client public current ly in Hex Format
		cPubBN = OpenSSL::BN.new(data['cpub'],16)
		# Create EC Point from client BigNumber
		cPubGrp = OpenSSL::PKey::EC::Group.new(groupName)
		cPubPoint = OpenSSL::PKey::EC::Point.new(cPubGrp,cPubBN)
		# Create Server side EC Instance
		serverEC = OpenSSL::PKey::EC.generate(groupName)
		# Compute shared Secret with provided Client Public
		shared = serverEC.dh_compute_key(cPubPoint)
		#First 16 bytes of shared Secret will be used as Encryption Key
		$gKey = shared[0..15]
		# Server Return Server Public and a test message encrypted by AES with key and IV created by shared Secret
		new_msg = encryptAES("ECDHE Key Exchange Success!")
		data = {
			'spub' => serverEC.public_key.to_bn.to_s(16),
			"text" => Base64.encode64(new_msg)
		}
		craftResponse(JSON.dump(data).chomp)
	rescue
		error 500
	end
end

#This APi is for testing Message Exchange with pre-shared AES Key
# Data sent and received in raw format
post '/yahoo' do 
	content_type:'application/binary'
	begin
		request.body.rewind
		reqData = decryptAES(request.body.read)
		response = 'Okay, i know your name, ' + reqData
		encryptAES(response)
	rescue
		error 500
	end
end
