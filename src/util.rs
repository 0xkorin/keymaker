use std::iter::Peekable;

pub trait Bits {
	const SIZE: usize;
	fn bits(self) -> usize;
}

impl Bits for &u8 {
	const SIZE: usize = 8;

	fn bits(self) -> usize {
		*self as usize
	}
}

pub struct BitsN<const N: usize>(usize);

impl<const N: usize> Bits for BitsN<N> {
	const SIZE: usize = N;

	fn bits(self) -> usize {
		self.0
	}
}

impl<const N: usize> TryFrom<usize> for BitsN<N> {
	type Error = ();

	fn try_from(v: usize) -> Result<Self, Self::Error> {
		if v < 1 << N {
			Ok(Self(v))
		} else {
			Err(())
		}
	}
}

pub struct BitIter<I, const N: usize> {
	iter: I,
	read: usize,
	buffer: usize,
}

impl<I, const N: usize> Iterator for BitIter<I, N>
where
	I: Iterator,
	I::Item: Bits,
{
	type Item = usize;

	fn next(&mut self) -> Option<Self::Item> {
		while self.read < N {
			self.read += I::Item::SIZE;
			self.buffer |= self.iter.next()?.bits() << (64 - self.read);
		}
		let out = self.buffer >> (64 - N);
		self.buffer <<= N;
		self.read -= N;
		Some(out)
	}
}

pub struct Implode<I: Iterator> {
	iter: Peekable<I>,
	separator: I::Item,
	toggle: bool,
}

impl<I> Iterator for Implode<I>
where
	I: Iterator,
	I::Item: Clone,
{
	type Item = I::Item;

	fn next(&mut self) -> Option<Self::Item> {
		if self.iter.peek().is_none() {
			return None;
		}
		self.toggle = !self.toggle;
		if self.toggle {
			Some(self.separator.clone())
		} else {
			self.iter.next()
		}
	}
}

pub trait IterExt: Iterator + Sized {
	fn bits<const N: usize>(self) -> BitIter<Self, N>
	where
		Self::Item: Bits,
	{
		BitIter {
			iter: self,
			read: 0,
			buffer: 0,
		}
	}

	fn bytes(self) -> BitIter<Self, 8>
	where
		Self::Item: Bits,
	{
		self.bits()
	}

	fn fold_mut<A, F>(self, mut init: A, mut f: F) -> A
	where
		F: FnMut(&mut A, Self::Item),
	{
		for item in self {
			f(&mut init, item);
		}
		init
	}

	fn implode(self, separator: Self::Item) -> Implode<Self>
	where
		Self::Item: Clone,
	{
		Implode {
			iter: self.peekable(),
			separator,
			toggle: true,
		}
	}
}

impl<T> IterExt for T where T: Iterator {}
