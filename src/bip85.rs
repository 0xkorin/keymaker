use crate::bip32::ExtKey;
use crate::bip32::HARDENED_OFFSET as H;
use crate::bip39::Mnemonic;
use hmac::{Hmac, Mac};
use k256::SecretKey;
use sha2::Sha512;

pub trait Bip85 {
	fn child_mnemonic(&self, i: u32) -> Option<Mnemonic>;
}

impl Bip85 for ExtKey<SecretKey> {
	fn child_mnemonic(&self, i: u32) -> Option<Mnemonic> {
		if self.depth() > 0 {
			return None;
		}
		let key = self.derive_path(&[H + 83696968, H + 39, H + 0, H + 24, H + i])?;
		let entropy = key.entropy();
		Some(Mnemonic::from_entropy(&entropy[..32]))
	}
}

pub trait Entropy {
	fn entropy(&self) -> [u8; 64];
}

impl Entropy for ExtKey<SecretKey> {
	fn entropy(&self) -> [u8; 64] {
		let mut hmac = Hmac::<Sha512>::new_from_slice(b"bip-entropy-from-k").unwrap();
		hmac.update(&self.key().to_bytes());
		let res = hmac.finalize().into_bytes();
		let mut out = [0; 64];
		out.copy_from_slice(&res);
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn key() -> ExtKey<SecretKey> {
		ExtKey::<SecretKey>::root_from_key(
			hex::decode("1b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c")
				.unwrap(),
			SecretKey::from_slice(
				&hex::decode("3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed9")
					.unwrap(),
			)
			.unwrap(),
		)
	}

	#[test]
	fn entropy() {
		let key = key().derive_path(&[H + 83696968, H, H]).unwrap();
		assert_eq!(hex::encode(key.entropy()), "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7");
	}

	#[test]
	fn mnemonic() {
		let mnemonic = key().child_mnemonic(0).unwrap();
		assert_eq!(mnemonic.to_string(), "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano");
	}
}
