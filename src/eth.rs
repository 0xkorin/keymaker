use crate::bip32::ExtKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::fmt::Write;

pub struct Address([u8; 20]);

impl AsRef<[u8]> for Address {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let buf = hex::encode(&self.0);
		let mut hasher = Keccak256::new();
		hasher.update(&buf);
		let hash = hex::encode(hasher.finalize());
		f.write_str("0x")?;
		for (mut c, h) in buf.chars().zip(hash.chars()) {
			if h as u8 > 55 {
				c = c.to_ascii_uppercase();
			}
			f.write_char(c)?;
		}
		Ok(())
	}
}

pub trait ToAddress {
	fn address(&self) -> Address;
}

impl ToAddress for ExtKey<SecretKey> {
	fn address(&self) -> Address {
		self.key().address()
	}
}

impl ToAddress for SecretKey {
	fn address(&self) -> Address {
		self.public_key().address()
	}
}

impl ToAddress for PublicKey {
	fn address(&self) -> Address {
		let point = self.to_encoded_point(false);
		let mut hasher = Keccak256::new();
		hasher.update(&point.as_bytes()[1..]);
		let hash = hasher.finalize();
		let mut address = [0; 20];
		address.copy_from_slice(&hash[12..]);
		Address(address)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn address() {
		let addr = SecretKey::from_slice(
			&hex::decode("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315")
				.unwrap(),
		)
		.unwrap()
		.address();
		assert_eq!(
			hex::encode(&addr),
			"001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
		);
		assert_eq!(
			format!("{addr}"),
			"0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9"
		);
	}

	#[test]
	fn checksum() {
		let data = [
			"0x52908400098527886E0F7030069857D2E4169EE7",
			"0x8617E340B3D01FA5F11F306F4090FD50E238070D",
			"0xde709f2102306220921060314715629080e2fb77",
			"0x27b1fdb04752bbc536007a920d24acb045561c26",
			"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
			"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
			"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
			"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
		];

		for exp in data {
			let mut address = Address([0; 20]);
			hex::decode_to_slice(&exp[2..], &mut address.0).unwrap();
			assert_eq!(address.to_string(), exp);
		}
	}
}
