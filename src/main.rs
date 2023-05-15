use crate::bip32::HARDENED_OFFSET;
use crate::bip39::Mnemonic;
use crate::bip85::Bip85;
use crate::eth::ToAddress;
use sha2::{Digest, Sha256};
use std::io::{stdin, stdout, Write};

mod base58;
mod bip32;
mod bip39;
mod bip85;
mod eth;
mod util;

fn main() {
	println!("Keymaker {}", env!("CARGO_PKG_VERSION"));
	println!();
	println!("Choose option:");
	println!(" 1) Generate mnemonic from dice rolls");
	println!(" 2) Derive child mnemonics from mnemonic");
	println!(" 3) Derive ETH addresses from mnemonic");

	print!("Choice: ");
	stdout().flush().unwrap();

	let mut input = String::new();
	stdin().read_line(&mut input).unwrap();

	println!();
	println!();

	match input.trim_end() {
		"1" => {
			let mnemonic = dice();
			print_mnemonic(&mnemonic);
			print_child_mnemonics(&mnemonic);
		}
		"2" => {
			println!("Derive child mnemonics from mnemonic");
			let mnemonic = prompt_mnemonic();
			print_mnemonic(&mnemonic);
			print_child_mnemonics(&mnemonic);
		}
		"3" => {
			println!("Derive ETH addresses from mnemonic");
			let mnemonic = prompt_mnemonic();
			print_mnemonic(&mnemonic);
			print_eth_addresses(&mnemonic);
		}
		_ => {
			println!("Unknown option");
		}
	}
}

fn prompt_mnemonic() -> Mnemonic {
	print!("Enter 24 word mnemonic: ");
	stdout().flush().unwrap();

	let mut input = String::new();
	stdin().read_line(&mut input).unwrap();

	Mnemonic::from_phrase(&input).expect("Invalid mnemonic")
}

fn dice() -> Mnemonic {
	println!("Generate mnemonic from dice rolls");
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

	let res = hasher.finalize();
	Mnemonic::from_entropy(res)
}

fn print_mnemonic(mnemonic: &Mnemonic) {
	let seed = mnemonic.seed("");
	let root_key = seed.root_key().unwrap();
	println!();
	println!("Mnemonic: {mnemonic}");
	println!("Seed:     {seed}");
	println!("Root key: {root_key}");
	println!();
}

fn print_child_mnemonics(mnemonic: &Mnemonic) {
	println!("Keep pressing ENTER to generate child mnemonics");

	let seed = mnemonic.seed("");
	let root_key = seed.root_key().unwrap();
	let mut input = String::new();

	let mut i = 0;
	loop {
		input.clear();
		stdin().read_line(&mut input).unwrap();
		println!("{i}: {}", root_key.child_mnemonic(i).unwrap());
		i += 1;
	}
}

fn print_eth_addresses(mnemonic: &Mnemonic) {
	println!("Derivation path: 44'/60'/X'/0/0 (Ledger Live)");
	println!("Keep pressing ENTER to generate addresses");

	let seed = mnemonic.seed("");
	let base = seed
		.root_key()
		.unwrap()
		.derive_path(&[44 + HARDENED_OFFSET, 60 + HARDENED_OFFSET])
		.unwrap();

	let mut i = 0;
	let mut input = String::new();
	loop {
		input.clear();
		stdin().read_line(&mut input).unwrap();
		for _ in 0..4 {
			let address = base
				.derive_path(&[i + HARDENED_OFFSET, 0, 0])
				.unwrap()
				.address();
			println!("{address}");
			i += 1;
		}
	}
}
