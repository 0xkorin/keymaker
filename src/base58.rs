use crate::util::IterExt;
use sha2::{Digest, Sha256};

const ALPHABET: &'static [u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
	let l = input.as_ref().len() * 138 / 100;
	input
		.as_ref()
		.into_iter()
		.map(|v| *v as u32)
		.fold_mut((vec![0; l + 1], l), |(a, h), mut x| {
			let mut j = a.len() - 1;
			while j > *h || x != 0 {
				x += 256 * (a[j] as u32);
				a[j] = (x % 58) as u8;
				x /= 58;
				j = j.saturating_sub(1);
			}
			*h = j;
		})
		.0
		.into_iter()
		.skip_while(|v| *v == 0)
		.map(|v| ALPHABET[v as usize] as char)
		.collect()
}

pub fn encode_check<T: AsRef<[u8]>>(input: T) -> String {
	let mut input = input.as_ref().to_vec();
	let mut hasher = Sha256::new();
	hasher.update(&input);
	let mut hash = hasher.finalize_reset();
	hasher.update(&hash);
	hash = hasher.finalize();
	input.extend_from_slice(&hash[..4]);
	encode(input)
}

#[cfg(test)]
mod tests {
	#[test]
	fn encode() {
		let data = [
			(b"".as_ref(), ""),
			(&[32], "Z"),
			(&[45], "n"),
			(&[48], "q"),
			(&[49], "r"),
			(&[57], "z"),
			(&[45, 49], "4SU"),
			(&[49, 49], "4k8"),
			(b"abc", "ZiCa"),
			(b"1234598760", "3mJr7AoUXx2Wqd"),
			(
				b"abcdefghijklmnopqrstuvwxyz",
				"3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
			),
		];

		for (input, output) in data {
			assert_eq!(super::encode(input), output);
		}
	}
}
