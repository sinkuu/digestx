/**
 * FNV(Fowler-Noll-Vo) hash implementation.
 */
module digestx.fnv;


public import std.digest.digest;


/**
 * Template API FNV-1(a) hash implementation.
 */
struct FNV(ulong bitLength, bool fnv1a = false)
{
	void start() @safe pure nothrow @nogc
	{
		this = this.init;
	}

	void put(scope const(ubyte)[] data...) @trusted pure nothrow @nogc
	{
		foreach (immutable ubyte i; data)
		{
			static if (fnv1a)
			{
				_hash ^= i;
				_hash *= fnvPrime;
			}
			else
			{
				_hash *= fnvPrime;
				_hash ^= i;
			}
		}
	}

	ubyte[bitLength / 8] finish() const @trusted pure nothrow @nogc
	{
		import std.bitmanip : nativeToBigEndian;

		static if (__VERSION__ < 2067)
		{
			// Phobos bug: std.bitmanip.nativeToBigEndian is not annotated with @nogc
			return (cast(ubyte[bitLength / 8] function(IntType) @safe pure nothrow @nogc)
					&nativeToBigEndian!IntType)(_hash);
		}
		else
		{
			return nativeToBigEndian(_hash);
		}
	}

private:

	// FNV-1 hash parameters
	static if (bitLength == 32)
	{
		enum uint fnvPrime  = 0x1000193U;
	}
	else static if (bitLength == 64)
	{
		enum ulong fnvPrime = 0x100000001B3UL;
	}
	else static assert(false, "Unsupported hash length");

	static if (bitLength == 32)
	{
		enum uint fnvOffsetBasis  = 0x811C9DC5U;
	}
	else static if (bitLength == 64)
	{
		enum ulong fnvOffsetBasis = 0xCBF29CE484222325UL;
	}
	else static assert(false, "Unsupported hash length");

	import std.traits : Unqual;
	alias IntType = Unqual!(typeof(fnvPrime));

	IntType _hash = fnvOffsetBasis;
}

alias FNV32 = FNV!32; /// 32bit FNV-1, hash size is ubyte[4]
alias FNV64 = FNV!64; /// 64bit FNV-1, hash size is ubyte[8]
alias FNV32A = FNV!(32, true); /// 32bit FNV-1a, hash size is ubyte[4]
alias FNV64A = FNV!(64, true); /// 64bit FNV-1a, hash size is ubyte[8]

alias FNV32Digest = WrapperDigest!FNV32; /// OOP API for 32bit FNV-1
alias FNV64Digest = WrapperDigest!FNV64; /// OOP API for 64bit FNV-1
alias FNV32ADigest = WrapperDigest!FNV32A; /// OOP API for 32bit FNV-1a
alias FNV64ADigest = WrapperDigest!FNV64A; /// OOP API for 64bit FNV-1a

///
unittest
{
	import digestx.fnv;

	FNV64 fnv64;
	fnv64.put(cast(ubyte[])"hello");
	assert(toHexString(fnv64.finish()) == "7B495389BDBDD4C7");

	// Template API
	assert(digest!FNV32("abc") == x"439C2F4B");
	assert(digest!FNV64("abc") == x"D8DCCA186BAFADCB");
	assert(digest!FNV32A("abc") == x"1A47E90B");
	assert(digest!FNV64A("abc") == x"E71FA2190541574B");
	
	assert(digest!FNV64("hello") == fnv64.finish());

	// OOP API
	Digest fnv = new FNV32ADigest;
	ubyte[] d = fnv.digest("1234");
	assert(d == x"FDC422FD");
}

@safe pure nothrow @nogc
unittest
{
	assert(digest!FNV32("") == x"811C9DC5");
	assert(digest!FNV64("") == x"CBF29CE484222325");
	assert(digest!FNV32A("") == x"811C9DC5");
	assert(digest!FNV64A("") == x"CBF29CE484222325");
}
