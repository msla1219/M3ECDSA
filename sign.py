from fastecdsa.curve import secp256k1
from fastecdsa.keys import export_key, gen_keypair

from fastecdsa import curve, ecdsa, keys, point
from hashlib import sha256


def sign(m):

	#generating the private key over secp224k1 curve
	private_key = keys.gen_private_key(curve=secp256k1)

	#get the public key from the corresponding private key
	public_key = keys.get_public_key(private_key, curve=secp256k1)

	#generate signature
	r, s = ecdsa.sign(m, private_key, curve.secp256k1)

	assert isinstance( public_key, point.Point )
	assert isinstance( r, int )
	assert isinstance( s, int )

	return(public_key, [r,s])

