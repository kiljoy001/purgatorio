Form1: module
{
	PATH:	con "/dis/lib/form1.dis";

	AuthPass:	con 3;
	AuthTs:	con 64;
	AuthTc:	con 65;
	AuthAs:	con 66;
	AuthAc:	con 67;
	AuthTp:	con 68;
	AuthHr:	con 69;

	# form1 frame: num/sig + ChaCha20-Poly1305
	encrypt:	fn(num: int, key: array of byte,
			   plain: array of byte): array of byte;
	decrypt:	fn(key: array of byte, frame: array of byte):
				(int, array of byte);

	# raw ChaCha20-Poly1305, ciphertext and tag concatenated
	ccencrypt:	fn(key: array of byte, nonce: array of byte,
			   aad: array of byte, plain: array of byte):
				array of byte;
	ccdecrypt:	fn(key: array of byte, nonce: array of byte,
			   aad: array of byte, cipher: array of byte):
				array of byte;
};
