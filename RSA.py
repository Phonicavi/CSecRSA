import random

class RSA():

	def __init__(self):
		(p, q) = self.__generate_random_primes()
		self.__p = p
		self.__q = q
		self.__n = p * q
		self.__phi = (p - 1) * (q - 1)
		exg = 0
		while True:
			self.__e = random.randint(0, self.__phi - 4) + 3
			if not (self.__phi % self.__e):
				continue
			(gcd, self.__d, exg) = self.__exgcd(self.__e, self.__phi)
			if (gcd == 1) and (self.__d > 0) and (self.__d < self.__n):
				break

	def get_public_key(self):
		return (self.__e, self.__n)

	def get_private_key(self):
		return (self.__d, self.__p, self.__q)

	def __generate_random_primes(self):
		a = (int)(1e8 + random.randint(0, 9e8))
		a += 0 if (a % 2) else 1
		b = (int)(1e8 + random.randint(0, 9e8))
		b += 0 if (b % 2) else 1
		primes_less_than_1e4 = (int)(1e4 + 1) * [0]
		count = self.__generate_prime_within((int)(1e4), primes_less_than_1e4)
		while True:
			f = False
			for i in xrange(3, count):
				if a > primes_less_than_1e4[i]:
					if not (a % primes_less_than_1e4[i]):
						f = True
						break
				else:
					break
			if f:
				a += 2
				continue
			if not self.__is_prime(a, 10):
				a += 2
			else:
				break
		while True:
			if (a == b):
				b += 2
				continue
			f = False
			for i in xrange(3, count):
				if b > primes_less_than_1e4[i]:
					if not (b % primes_less_than_1e4[i]):
						f = True
						break
				else:
					break
			if f:
				b += 2
				continue
			if not self.__is_prime(a, 10):
				b += 2
			else:
				break
		print "[generate_random_primes] a = %u, b = %u" % (a, b)
		return (a, b)

	def __generate_prime_within(self, n, p): # upper_bound: n, uint_list: p
		count = 0
		if n <= 2:
			return count
		isComposite = (n + 1) * [False]
		p[0] = 1
		for i in xrange(2, n):
			if not isComposite[i]:
				count += 1
				p[count] = i
			for j in xrange(1, count + 1):
				k = p[j] * i
				if k >= n:
					break
				isComposite[k] = True
				if not (i % p[j]):
					break
		return count

	def __is_prime(self, n, t):
		if n < 2:
			return False
		elif n == 2:
			return True
		elif not (n % 2):
			return False
		k = 0
		m = n - 1
		while not (m & 1):
			m >>= 1
			k += 1
		while t:
			t -= 1
			a = self.__mod(random.randint(0, n - 3) + 2, m, n)
			if (a != 1):
				for i in xrange(0, k):
					if (a != n - 1):
						a = self.__mod_pro(a, a, n)
				if i >= k:
					return False
		return True

	def __mod(self, a, b, c):
		result = 1
		while b:
			if (b & 0x1):
				result = self.__mod_pro(result, a, c)
			a = self.__mod_pro(a, a, c)
			b >>= 1
		return result

	def __mod_pro(self, x, y, n):
		result = 0
		tmp = x % n
		while y:
			if (y & 0x1):
				result += tmp
				if result > n:
					result -= n
			tmp <<= 1
			if tmp > n:
				tmp -= n
			y >>= 1
		return result

	def __exgcd(self, a, b):
		if (b == 0):
			return (a, 1, 0)
		(gcd, x, y) = self.__exgcd(b, a%b)
		t = y
		y = x - (a / b) * y
		x = t
		return (gcd, x, y)

	def cipher(self, plain_text):
		cipher_text = []
		for word in plain_text:
			assert (word < self.__n) # assertion
			cipher_text.append(self.__mod(word, self.__e, self.__n))
		return cipher_text

	def decipher(self, cipher_text):
		decipher_text = []
		for word in cipher_text:
			decipher_text.append(self.__mod(word, self.__d, self.__n))
		return decipher_text


if __name__ == '__main__':
	rsa = RSA()
	print "Public Key: {e = %u, n = %u}" % rsa.get_public_key()
	print "Private Key: {d = %u, p = %u, q = %u}" % rsa.get_private_key()

	length = 4
	word_limit = (rsa.get_public_key()[1] - 1)/2 # rsa.__n
	plain_text = []
	for i in xrange(length):
		plain_text.append(random.randint(0, word_limit))
	cipher_text = rsa.cipher(plain_text)
	decipher_text = rsa.decipher(cipher_text)

	print "origin message:"
	for word in plain_text:
		print ("%x" % word),
	print "\ncipher text:"
	for word in cipher_text:
		print ("%x" % word),
	print "\ndecipher text:"
	for word in decipher_text:
		print ("%x" % word),

