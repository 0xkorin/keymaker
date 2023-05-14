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

	fn fold_mut<A, F>(self, mut init: A, mut f: F) -> A
	where
		F: FnMut(&mut A, Self::Item),
	{
		for item in self {
			f(&mut init, item);
		}
		init
	}
}

impl<T> IterExt for T where T: Iterator {}
