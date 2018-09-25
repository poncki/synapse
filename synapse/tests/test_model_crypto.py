import hashlib

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.tests.utils as s_t_utils


BITS = 2048
HEXSTR_MODULUS = 'abbd407f417fe8d6632aae1c6d09b271416bef9244e61f7c7c2856ddfde3ecf93cd50b3eaea5c9b8cb9bfb5a317bf50925a' \
                 'b500a06247ec2f3294891a8e62c317ee648f933ec1bf760a9d7e9a5ea4706b2a2c3f6376079114ddcc7a15d3fecf001458f' \
                 '22f0551802a25ef95cf464aabeb0514ea3849583bc09022730c44a2ff5f893fc6885add69c103d75114dd2f11436f617fbf' \
                 'b0af2978802aabf35483bbfcc470d50d6afb4283c1d06d2bf27efe9d7c09f226895633a46c3d77173bf0db8634299462b5f' \
                 '29629ad3b0470c76ddfd331ed0207d4dbd5fd44a2f66ca5f802ac0130e4a4bb2c149b5baa7a373188823ee21fe2950a76c8' \
                 '18586919f7914453d'
HEXSTR_PUBLIC_EXPONENT = 0x10001
HEXSTR_PRIVATE_EXPONENT = '9db58a80120f3b2b7d1f998a231b8f916fa985f4456f2a24f0033f5a56a7b35b61e0a695e65dfab3c7ceb2f0ad' \
                          '968e7bdaeac9f29a97730ce5add8a5627c14c3532c7880d88c8f56099f8ed65275a4c9e2cb93b70c3d7c904677' \
                          '639fac7962c537f5bfaf2f12859d0dacb7c403ee59da0922715bba0a6f5202d7c653833e39715f04664c2396c4' \
                          '7bdf3f09f5486d8f6aea767ba011f1a5a10c8b57f079aea58abfd5e50ef20aa5e09b1082f6af98e806c9aeeb89' \
                          '4148a7d82cd6e1443c6115eb567fba0eacf5b7178518b8ba312da6ace22238d1ed19f3e703652576a6152ba60d' \
                          '4d4c6bc75b3ee7c8efeadee0c5ed7c14bf2930a6c4f13137becf38912f49c5'
HEXSTR_PRIVATE_PRIME_P = 'dee90ee63c12729a3fe7d38c581abf7e1c784ec0bd4bfdd1282286ea9996673942a24c7c98b31c6cd12db8ba96d' \
                         'a785c4392569d7bfc2be9d9907c3b7fbf40d31891642952a0e5a23dfbe721a746588df9a246ea4936a1958f66fd' \
                         '3a32c08008a0f6ed9b516fa869fb08a57ef31c0ec217f173e489a2f8f111e25c25c961c2b7'
HEXSTR_PRIVATE_PRIME_Q = 'c53b9c8dfb3dda04d16c7f779a02b3b8c7b44bf876dc88ad562778eafaded9ade882ccfb887761515a251c22476' \
                         '1bef7207fa489e398041787cfbd155f1034a207d517f06bc76a044262484f82f0c6a887f776b1dce837408999d8' \
                         '8dd33a96c7f80e23719e77a11075d337bf9cc47d7dbf98e341b81c23f165dd15ccfd2973ab'

TEST_MD5 = hashlib.md5(b'test').hexdigest()
TEST_SHA1 = hashlib.sha1(b'test').hexdigest()
TEST_SHA256 = hashlib.sha256(b'test').hexdigest()
TEST_SHA384 = hashlib.sha384(b'test').hexdigest()
TEST_SHA512 = hashlib.sha512(b'test').hexdigest()

class CryptoModelTest(s_t_utils.SynTest):

    def test_norm_lm_ntlm(self):
        with self.getTestCore() as core:  # type: s_cortex.Cortex
            lm = core.model.type('hash:lm')
            valu, subs = lm.norm(TEST_MD5.upper())
            self.eq(valu, TEST_MD5)
            self.eq(subs, {})
            self.raises(s_exc.BadTypeValu, lm.norm, TEST_SHA256)

            ntlm = core.model.type('hash:ntlm')
            valu, subs = lm.norm(TEST_MD5.upper())
            self.eq(valu, TEST_MD5)
            self.eq(subs, {})
            self.raises(s_exc.BadTypeValu, ntlm.norm, TEST_SHA256)

    def test_forms_crypto_simple(self):
        with self.getTestCore() as core:  # type: s_cortex.Cortex
            with core.snap() as snap:
                # md5
                node = snap.addNode('hash:md5', TEST_MD5.upper())
                self.eq(node.ndef, ('hash:md5', TEST_MD5))
                self.raises(s_exc.BadPropValu, snap.addNode, 'hash:md5', TEST_SHA1)
                # sha1
                node = snap.addNode('hash:sha1', TEST_SHA1.upper())
                self.eq(node.ndef, ('hash:sha1', TEST_SHA1))
                self.raises(s_exc.BadPropValu, snap.addNode, 'hash:sha1', TEST_SHA256)
                # sha256
                node = snap.addNode('hash:sha256', TEST_SHA256.upper())
                self.eq(node.ndef, ('hash:sha256', TEST_SHA256))
                self.raises(s_exc.BadPropValu, snap.addNode, 'hash:sha256', TEST_SHA384)
                # sha384
                node = snap.addNode('hash:sha384', TEST_SHA384.upper())
                self.eq(node.ndef, ('hash:sha384', TEST_SHA384))
                self.raises(s_exc.BadPropValu, snap.addNode, 'hash:sha384', TEST_SHA512)
                # sha512
                node = snap.addNode('hash:sha512', TEST_SHA512.upper())
                self.eq(node.ndef, ('hash:sha512', TEST_SHA512))
                self.raises(s_exc.BadPropValu, snap.addNode, 'hash:sha512', TEST_MD5)

    def test_form_rsakey(self):
        prop = 'rsa:key'
        props = {
            'bits': BITS,
            'priv:exp': HEXSTR_PRIVATE_EXPONENT,
            'priv:p': HEXSTR_PRIVATE_PRIME_P,
            'priv:q': HEXSTR_PRIVATE_PRIME_Q,
        }
        valu = (HEXSTR_MODULUS, HEXSTR_PUBLIC_EXPONENT)

        with self.getTestCore() as core:  # type: s_cortex.Cortex

            with core.snap() as snap:

                node = snap.addNode(prop, valu, props)

                self.eq(node.ndef[1], (HEXSTR_MODULUS, HEXSTR_PUBLIC_EXPONENT))

                self.eq(node.get('mod'), HEXSTR_MODULUS)
                self.eq(node.get('bits'), BITS)
                self.eq(node.get('pub:exp'), HEXSTR_PUBLIC_EXPONENT)
                self.eq(node.get('priv:exp'), HEXSTR_PRIVATE_EXPONENT)
                self.eq(node.get('priv:p'), HEXSTR_PRIVATE_PRIME_P)
                self.eq(node.get('priv:q'), HEXSTR_PRIVATE_PRIME_Q)
