use crate::bip39::Mnemonic;
use crate::bip85::Bip85;
use sha2::{Digest, Sha256};
use std::io::{stdin, stdout, Write};

mod base58;
mod bip32;
mod bip39;
mod bip85;
mod util;

fn main() {
	println!("Generate seed from dice rolls");
	println!("Throw at least 154 dice to ensure 256 bit security");
	print!("Enter dice rolls: ");
	stdout().flush().unwrap();

	let mut input = String::new();
	stdin().read_line(&mut input).unwrap();

	let mut hasher = Sha256::new();
	let mut warn = false;
	for mut c in input.trim_end().chars().map(|v| v as u8) {
		if c < 49 || c > 54 {
			warn = true;
			continue;
		}
		if c == 54 {
			c = 48; // map 6 to 0
		}
		hasher.update(&[c]);
	}
	let res = hasher.finalize();
	let mnemonic = Mnemonic::from_entropy(res);
	let seed = mnemonic.seed("");
	let root_key = seed.root_key().unwrap();

	if warn {
		println!();
		println!("!!!! WARNING: invalid characters, they will be discarded !!!!");
		println!("Press ENTER to continue anyway");
		input.clear();
		stdin().read_line(&mut input).unwrap();
	}

	if input.trim_end().len() < 128 {
		println!();
		println!("!!!! WARNING: insufficient entropy !!!!");
		println!("Press ENTER to continue anyway");
		input.clear();
		stdin().read_line(&mut input).unwrap();
	}

	println!();
	println!("Mnemonic: {mnemonic}");
	println!("Seed:     {seed}");
	println!("Root key: {root_key}");
	println!();

	println!("Keep pressing ENTER to generate child mnemonics");

	let mut i = 0;
	loop {
		input.clear();
		stdin().read_line(&mut input).unwrap();
		println!("{i}: {}", root_key.child_mnemonic(i).unwrap());
		i += 1;
	}
}
