/**
Adler-32 implementation. This module conforms to the APIs defined in std.digest.digest.
*/
module digestx.adler;


public import std.digest.digest;


struct Adler32
{
	void start() @safe pure nothrow @nogc
	{
		this = this.init;
	}

	void put(scope const(ubyte)[] data...) @trusted pure nothrow @nogc
	{
		foreach (immutable ubyte i; data)
		{
			_a += i;
			_b += _a;

			--_tlen;
			if (_tlen == 0)
			{
				_a %= 65521;
				_b %= 65521;
				_tlen = moduloInterval;
			}
		}

		if (_tlen != moduloInterval)
		{
			_a %= 65521;
			_b %= 65521;
		}
	}

	ubyte[4] finish() const @trusted pure nothrow @nogc
	{
		import std.bitmanip : nativeToBigEndian;

		static if (__VERSION__ < 2067)
		{
			// Phobos bug: std.bitmanip.nativeToBigEndian is not annotated with @nogc
			auto r = (cast(ubyte[4] function(uint) @safe pure nothrow @nogc)&nativeToBigEndian!uint)
				((_b << 16) | _a);
		}
		else
		{
			auto r = nativeToBigEndian((_b << 16) | _a);
		}
		return r;
	}

private:

	uint _a = 1, _b;
	uint _tlen = moduloInterval;

	enum moduloInterval = 5552;
}

//Convenience alias for $(D digest) function in std.digest.digest using the Adler32 implementation.
auto adler32Of(T...)(T data)
{
	return digest!(Adler32, T)(data);
}

/// OOP API for Adler32.
alias Adler32Digest = WrapperDigest!Adler32;

///
unittest
{
	Adler32 adler;
	adler.put(cast(ubyte[])"abc");
	assert(adler.finish() == x"024d0127");
	adler.start();
	adler.put(cast(ubyte[])"def");
	assert(adler.finish() == x"025F0130");

	assert(adler32Of("abc") == x"024d0127");
}

@safe pure nothrow @nogc
unittest
{
	static assert(isDigest!Adler32);

	assert(adler32Of("abc") == x"024d0127");
	assert(adler32Of("abcdefghijklmnopqrstuvwxyz") == x"90860B20");
}

pure nothrow @nogc
unittest
{
	import std.range : repeat;
	assert(adler32Of(repeat('a', 1000000)) == x"15D870F9");
}

///
unittest
{
	auto adler = new Adler32Digest;
	assert(adler.digest("abc") == x"024d0127");
}
