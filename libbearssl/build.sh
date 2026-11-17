#!/bin/sh
# build.sh -- compile the BearSSL subset for the Inferno kernel.
#
#   ./build.sh [clean]
#
# BearSSL uses #if, which 8c's built-in preprocessor does not support,
# so each source is preprocessed with the host gcc (with -undef so the
# generic non-GCC paths are selected) and then compiled by 8c.  The
# compat headers map stdint/stddef/string to Plan 9's u.h/kern.h.
#
# Output: $ROOT/Inferno/$OBJTYPE/lib/libbearssl.a
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=${ROOT:-$(cd "$here/.." && pwd)}
objtype=${OBJTYPE:-386}
cc=${CC:-$root/Linux/386/bin/8c}
gcc=${GCC:-gcc}
out=$root/Inferno/$objtype/lib/libbearssl.a
obj=$here/obj-$objtype

if [ "${1:-}" = clean ]; then
	rm -rf "$obj" "$out"
	exit 0
fi

mkdir -p "$obj" "$(dirname "$out")"
srcs="settings.c
int/i32_div32.c
int/i15_add.c
int/i15_bitlen.c
int/i15_decmod.c
int/i15_decode.c
int/i15_decred.c
int/i15_encode.c
int/i15_fmont.c
int/i15_iszero.c
int/i15_moddiv.c
int/i15_modpow.c
int/i15_modpow2.c
int/i15_montmul.c
int/i15_mulacc.c
int/i15_muladd.c
int/i15_ninv15.c
int/i15_reduce.c
int/i15_rshift.c
int/i15_sub.c
int/i15_tmont.c
ec/ecdsa_atr.c
ec/ecdsa_rta.c
ec/ec_secp384r1.c
ec/ec_secp521r1.c
hash/multihash.c
ssl/ssl_hashes.c
codec/enc16be.c
codec/dec16be.c
codec/enc32be.c
codec/dec32be.c
codec/enc64be.c
codec/dec64be.c
codec/ccopy.c
hash/sha2small.c
hash/dig_size.c
hash/dig_oid.c
hash/ghash_ctmul.c
hash/ghash_ctmul32.c
mac/hmac.c
mac/hmac_ct.c
symcipher/aes_common.c
symcipher/aes_ct.c
symcipher/aes_ct_enc.c
symcipher/aes_ct_dec.c
symcipher/aes_ct_ctr.c
symcipher/aes_ct_ctrcbc.c
aead/gcm.c
ec/ec_p256_m15.c
ec/ec_keygen.c
ec/ec_pubkey.c
ec/ec_secp256r1.c
ec/ecdsa_i15_bits.c
ec/ecdsa_i15_sign_raw.c
ec/ecdsa_i15_sign_asn1.c
rand/hmac_drbg.c
ssl/ssl_engine.c
ssl/ssl_hs_server.c
ssl/ssl_server.c
ssl/ssl_io.c
ssl/ssl_rec_gcm.c
ssl/ssl_scert_single_ec.c
ssl/ssl_engine_default_aesgcm.c
ssl/prf.c
ssl/prf_sha256.c"

objs=
for s in $srcs; do
	b=$(echo "$s" | tr / _)
	$gcc -E -undef -Dinline= -Dmemcpy=br_memcpy \
		-I"$here/compat" \
		-I"$root/Inferno/$objtype/include" \
		-I"$root/include" \
		-I"$here/inc" -I"$here/src" \
		-o "$obj/$b.i" "$here/src/$s"
	$cc -o "$obj/$b.8" "$obj/$b.i"
	objs="$objs $obj/$b.8"
done

rm -f "$out"
ar rcs "$out" $objs
echo "wrote $out"
