import traceback
from flask import Flask, render_template, jsonify, request

from umbral import pre, keys, config, params
from umbral import config as uconfig
from umbral.curve import SECP256K1
from umbral.signing import Signer

from nucypher import MockNetwork
import uuid
import msgpack
import base64
import json
import sys
import redis

app = Flask(__name__)


def setup():
	# Setup pyUmbral
	global config
	config = uconfig.set_default_curve()

	global mock_kms
	mock_kms = MockNetwork()

	global r
	r = redis.Redis(host='localhost', port=6379, db=0)


# This app is BOB
config = ""
mock_kms = ""


# our encoding

def bytes_to_string(b):
	encoded = base64.b64encode(b)
	return encoded.decode('utf-8')


def string_to_bytes(s):
	sd = s.encode('utf-8')
	return base64.b64decode(sd)

def dict_to_string(d):
	return json.dumps(d)

def string_to_dict(s):
	return json.loads(s)


@app.route('/gen_keys', methods=["GET"])
def gen_keys():
	# Generate Keys and setup mock network
	alice_privkey = keys.UmbralPrivateKey.gen_key()
	alice_pubkey = alice_privkey.get_pubkey()

	response = {
		"pubkey": bytes_to_string(alice_pubkey.to_bytes()),
		"privkey": bytes_to_string(alice_privkey.to_bytes())
	}

	return jsonify(response)


@app.route('/encrypt', methods=["POST"])
def encrypt():
	# Get data from request
	json_data = json.loads(request.data.decode('utf-8'))
	data, alice_pubkey, alice_privkey = json_data["hash"].encode(
		'utf-8'), json_data['alice_pubkey'], json_data['alice_privkey']

	alice_pubkey = string_to_bytes(alice_pubkey)
	alice_pubkey = keys.UmbralPublicKey.from_bytes(alice_pubkey)

	alice_privkey = string_to_bytes(alice_privkey)
	alice_privkey = keys.UmbralPrivateKey.from_bytes(alice_privkey)

	# Encrypt some data
	plaintext = data
	ciphertext, capsule = pre.encrypt(alice_pubkey, plaintext)

	# convert capsule to str
	capsule_id = str(uuid.uuid4())
	string_capsule = bytes_to_string(capsule.to_bytes())
	r.set(capsule_id, string_capsule)

	# capsule_id = mock_kms.putcapsule(capsule)

	response = {
		"ciphertext": bytes_to_string(ciphertext),
		"capsule_id": capsule_id,
	}

	return jsonify(response)


@app.route('/grant', methods=["POST"])
def grant():
	json_data = json.loads(request.data.decode('utf-8'))
	capsule_id, alice_pubkey, alice_privkey, bob_pubkey = json_data['capsule_id'], json_data[
		'alice_pubkey'], json_data['alice_privkey'], json_data['bob_pubkey']

	alice_pubkey = string_to_bytes(alice_pubkey)
	alice_pubkey = keys.UmbralPublicKey.from_bytes(alice_pubkey)

	alice_privkey = string_to_bytes(alice_privkey)
	alice_privkey = keys.UmbralPrivateKey.from_bytes(alice_privkey)

	bob_pubkey = string_to_bytes(bob_pubkey)
	bob_pubkey = keys.UmbralPublicKey.from_bytes(bob_pubkey)

	alice_signing_privkey = keys.UmbralPrivateKey.gen_key()
	alice_signing_pubkey = alice_signing_privkey.get_pubkey()
	alice_signer = Signer(alice_signing_privkey)

	# Perform split-rekey and grant re-encryption policy
	alice_kfrags = pre.generate_kfrags(
		alice_privkey, bob_pubkey, 10, 20, alice_signer)

	policy_id = mock_kms.grant(alice_kfrags)

	alice_pubkey.from_bytes

	response = {
		"policy_id": policy_id,
		"capsule_id": capsule_id,
		"alice_pubkey": bytes_to_string(alice_pubkey.to_bytes()),
		"alice_signing_pubkey": bytes_to_string(alice_signing_pubkey.to_bytes())
	}

	return jsonify(response)


@app.route('/decrypt', methods=["POST"])
def decrypt():
	# Get data from request
	json_data = json.loads(request.data.decode('utf-8'))
	ciphertext, policy_id, capsule_id, alice_pubkey, bob_pubkey, bob_privkey, alice_signing_pubkey = json_data['ciphertext'], json_data[
		'policy_id'], json_data['capsule_id'], json_data['alice_pubkey'], json_data['bob_pubkey'], json_data['bob_privkey'], json_data['alice_signing_pubkey']

	
	# convert to bytes
	ciphertext = string_to_bytes(ciphertext)
	
	try:

		capsule_byte = r.get(capsule_id).decode("utf-8")
		capsule = pre.Capsule.from_bytes(string_to_bytes(capsule_byte), params.UmbralParameters(SECP256K1))

		alice_pubkey = string_to_bytes(alice_pubkey)
		alice_pubkey = keys.UmbralPublicKey.from_bytes(alice_pubkey)

		bob_pubkey = string_to_bytes(bob_pubkey)
		bob_pubkey = keys.UmbralPublicKey.from_bytes(bob_pubkey)

		bob_privkey = string_to_bytes(bob_privkey)
		bob_privkey = keys.UmbralPrivateKey.from_bytes(bob_privkey)

		alice_signing_pubkey = string_to_bytes(alice_signing_pubkey)
		alice_signing_pubkey = keys.UmbralPublicKey.from_bytes(
			alice_signing_pubkey)

		try:
			capsule.set_correctness_keys(
				alice_pubkey, bob_pubkey, alice_signing_pubkey)
		except:
			print("Unexpected error:", sys.exc_info()[0])
			traceback.print_exception(*sys.exc_info()[0])

		# Perform re-encryption request
		bob_cfrags = mock_kms.reencrypt(policy_id, capsule, 10)
		# Simulate capsule handoff, and set the correctness keys.
		# Correctness keys are used to prove that a cfrag is correct and not modified
		# by a proxy node in the network. They must be set to use the `decrypt` and
		# `attach_cfrag` funtions.
		bob_capsule = capsule

		try:
			bob_capsule.set_correctness_keys(
				alice_pubkey, bob_pubkey, alice_signing_pubkey)
		except:
			print("Unexpected error:", sys.exc_info()[0])
			traceback.print_exception(*sys.exc_info()[0])

		for cfrag in bob_cfrags:
			bob_capsule.attach_cfrag(cfrag)
		
		decrypted_data = pre.decrypt(
			ciphertext, bob_capsule, bob_privkey, alice_signing_pubkey)

		return jsonify({
			"decrypted_data": decrypted_data.decode('utf-8'),
		})
	except Exception as e:
		print("except", str(e), sys.exc_info()[0])
		traceback.print_exception(*sys.exc_info()[0])
		return jsonify({
			"decrypted_data": None,
		})


if __name__ == '__main__':
	setup()
	app.run(host='0.0.0.0', port=8543, debug=True)
	# alice = gen_alice()
	# print(alice["pubkey"].point_key)
	# encrypt_result = encrypt(b"Hello World", alice["pubkey"], alice["privkey"])
	# print(encrypt_result)
	# decrypt_result = decrypt(encrypt_result["ciphertext"], encrypt_result["policy_id"], encrypt_result["capsule"], encrypt_result["alice_pubkey"],encrypt_result["alice_signing_pubkey"])
	# print(decrypt_result)

	# print(string_to_bytes(bytes_to_string(b'hello')))
	# print(string_to_bytes("aGVsbG8gd29ybGQ="))
