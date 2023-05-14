use crate::base58;
use hmac::{Hmac, Mac};
use k256::{PublicKey, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::ops::AddAssign;

type ScalarPrimitive = k256::elliptic_curve::ScalarPrimitive<k256::Secp256k1>;
pub const HARDENED_OFFSET: u32 = 1 << 31;

#[derive(Clone)]
pub struct ExtKey<K> {
	depth: u8,
	number: u32,
	fingerprint: [u8; 4],
	chain_code: [u8; 32],
	key: K,
}

impl<K: Key> ExtKey<K> {
	pub fn depth(&self) -> u8 {
		self.depth
	}

	pub fn key(&self) -> &K {
		&self.key
	}

	pub fn derive(&self, i: u32) -> Option<Self> {
		let mut hmac = Hmac::<Sha512>::new_from_slice(&self.chain_code).unwrap();
		hmac.update(&self.key.serialize_for_child(i)?);
		hmac.update(&i.to_be_bytes());
		let res = hmac.finalize().into_bytes();

		let key = self
			.key
			.add_scalar(ScalarPrimitive::from_slice(&res[..32]).ok()?)?;
		let mut chain_code = [0; 32];
		chain_code.copy_from_slice(&res[32..]);

		Some(Self {
			depth: self.depth + 1,
			fingerprint: self.key.fingerprint(),
			number: i,
			chain_code,
			key,
		})
	}

	pub fn derive_path(&self, path: &[u32]) -> Option<Self> {
		let mut key = self.clone();
		for &i in path {
			key = key.derive(i)?;
		}
		Some(key)
	}

	pub fn serialize(&self) -> [u8; 78] {
		let mut out = [0; 78];
		out[..4].copy_from_slice(K::version());
		out[4] = self.depth;
		out[5..9].copy_from_slice(&self.fingerprint);
		out[9..13].copy_from_slice(&self.number.to_be_bytes());
		out[13..45].copy_from_slice(&self.chain_code);
		out[45..].copy_from_slice(&self.key.serialize());
		out
	}
}

impl ExtKey<SecretKey> {
	pub fn from_seed<T: AsRef<[u8]>>(seed: T) -> Option<Self> {
		let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
		hmac.update(seed.as_ref());
		let res = hmac.finalize().into_bytes();
		let key = SecretKey::from_slice(&res[..32]).ok()?;
		let mut chain_code = [0; 32];
		chain_code.copy_from_slice(&res[32..]);
		Some(Self {
			depth: 0,
			number: 0,
			fingerprint: [0; 4],
			chain_code,
			key,
		})
	}

	#[cfg(test)]
	pub fn public_key(&self) -> ExtKey<PublicKey> {
		ExtKey {
			depth: self.depth,
			number: self.number,
			fingerprint: self.fingerprint,
			chain_code: self.chain_code,
			key: self.key.public_key(),
		}
	}

	#[cfg(test)]
	pub fn root_from_key<T: AsRef<[u8]>>(code: T, key: SecretKey) -> Self {
		let mut chain_code = [0; 32];
		chain_code.copy_from_slice(code.as_ref());
		Self {
			depth: 0,
			number: 0,
			fingerprint: [0; 4],
			chain_code,
			key,
		}
	}
}

impl<K: Key> fmt::Display for ExtKey<K> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", base58::encode_check(self.serialize()))
	}
}

pub trait Key: Clone + Sized {
	fn version() -> &'static [u8];
	fn serialize(&self) -> [u8; 33];
	fn serialize_for_child(&self, i: u32) -> Option<[u8; 33]>;
	fn fingerprint(&self) -> [u8; 4];
	fn add_scalar(&self, key: ScalarPrimitive) -> Option<Self>;
}

impl Key for SecretKey {
	// 0x0488ADE4 - xprv
	fn version() -> &'static [u8] {
		&[4, 136, 173, 228]
	}

	fn serialize(&self) -> [u8; 33] {
		let mut out = [0; 33];
		out[1..].copy_from_slice(&self.to_bytes()[..]);
		out
	}

	fn serialize_for_child(&self, i: u32) -> Option<[u8; 33]> {
		if i < HARDENED_OFFSET {
			Some(self.public_key().serialize())
		} else {
			Some(self.serialize())
		}
	}

	fn fingerprint(&self) -> [u8; 4] {
		self.public_key().fingerprint()
	}

	fn add_scalar(&self, mut key: ScalarPrimitive) -> Option<Self> {
		key.add_assign(self.as_scalar_primitive());
		if key.is_zero().unwrap_u8() == 1 {
			None
		} else {
			Some(SecretKey::new(key))
		}
	}
}

impl Key for PublicKey {
	// 0x0488B21E - xpub
	fn version() -> &'static [u8] {
		&[4, 136, 178, 30]
	}

	fn serialize(&self) -> [u8; 33] {
		let mut out = [0; 33];
		let ser = self.to_sec1_bytes();
		out.copy_from_slice(&ser);
		out
	}

	fn serialize_for_child(&self, i: u32) -> Option<[u8; 33]> {
		if i < HARDENED_OFFSET {
			Some(self.serialize())
		} else {
			None
		}
	}

	fn fingerprint(&self) -> [u8; 4] {
		let mut hasher = Sha256::new();
		hasher.update(&self.to_sec1_bytes());
		let hash = hasher.finalize();
		let mut hasher = Ripemd160::new();
		hasher.update(&hash);
		let hash = hasher.finalize();
		let mut out = [0; 4];
		out.copy_from_slice(&hash[..4]);
		out
	}

	fn add_scalar(&self, key: ScalarPrimitive) -> Option<Self> {
		let mut point = SecretKey::new(key).public_key().to_projective();
		point.add_assign(self.to_projective());
		PublicKey::from_affine(point.to_affine()).ok()
	}
}

#[cfg(test)]
mod tests {
	use super::HARDENED_OFFSET as H;
	use super::*;

	fn cmp(key: &ExtKey<SecretKey>, pk: &str, sk: &str) {
		assert_eq!(format!("{key}"), sk);
		assert_eq!(format!("{}", key.public_key()), pk);
	}

	#[test]
	fn encode() {
		let data = [
			("000102030405060708090a0b0c0d0e0f", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", vec![
				 (H, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
				 (1, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
				 (H+2, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
				 (2, "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
				 (1000000000, "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
			]),
			("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB", "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U", vec![
				(0, "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH", "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"),
				(H+2147483647, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a", "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"),
				(1, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon", "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"),
				(H+2147483646, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL", "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"),
				(2, "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt", "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
			]),
			("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13", "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6", vec![
				(H, "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
			]),
			("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678", "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa", "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv", vec![
				(H, "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m", "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"),
				(H+1, "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt", "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1")
			])
		];

		for (seed, pk, sk, path) in data {
			let mut key = ExtKey::<SecretKey>::from_seed(&hex::decode(seed).unwrap()).unwrap();
			cmp(&key, pk, sk);
			for (i, pk, sk) in path {
				if let Some(p) = key.public_key().derive(i) {
					assert_eq!(format!("{p}"), pk);
				}

				key = key.derive(i).unwrap();
				cmp(&key, pk, sk);
			}
		}
	}
}
