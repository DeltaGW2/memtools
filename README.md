# memtools
x64 single header C++ memory tools for pattern scanning, verification and navigation.

# Usage
`#define MAX_PATTERN_LENGTH 128` is the default. Change this define as necessary.

## Patterns
Patterns are constexpr-compatible to parse at compile-time.

### Format
- Hexadecimals must be uppercase.
- Wildcards can be single `?` or double `??` question mark.
- Only hexadecimal pairs are interpreted.
- Spaces are skipped.

### Examples
Valid:
- `1A 2B ?? 4D` - Third byte is a wildcard and won't be matched.
- `1A 2B ?  4D` - Third byte is a wildcard and won't be matched.
- `1A 2B 3C 4D` - All bytes will be matched.

Invalid:
- `1a 2b 3c 4d` - Lowercase is not permitted.
- `1A2B3C4D` - Will be interpreted in pairs as `1A 2B 3C 4D`.
- `1A2B3C4` - Will be interpreted in pairs as `1A 2B 3C 04`.
- `1A 2B ??? 5E` - Will be interpreted as `1A 2B ?? ? 5E`. Third and fourth byte won't be matched.

## Instructions
In addition to matching against memory patterns, you can navigate and validate around this pattern. For example, you can match against a string to confirm the address is correct.

If any instructions fail, the scanner will continue to scan to the next byte sequence that matches and perform the instructions again.
Only if the pattern matches and all instructions are successful the address will be returned.

### Operations
- `Offset` - Adds an offset to the current address.
- `Follow` - Follows a relative address.
- `Strcmp` - Compares against an UTF8 string.
- `Wcscmp` - Compares against an UTF16 string.
- `CmpI8` - Compares against an 8 bit integer.
- `CmpI16` - Compares against a 16 bit integer.
- `CmpI32` - Compares against a 32 bit integer.
- `CmpI64` - Compares against a 64 bit integer.
- `PushAddr` - Stores the current address, to return to it. E.g. to check a string in a sub function and then continue navigating the callsite.
- `PopAddr` - Restores the last pushed address and continues from there.
- `AdvWcard` - Goes to the next *set* of wildcards. Important: Only works at top level of the pattern. Not when following. Does respect Offset operations.
- `FuncEntry` - Goes to the beginning of the current function.

## Examples

```cpp
/* Byte pattern to search for with wildcards. */
constexpr memtools::Pattern PatternExample(
	"41 B8 ? ? ? ? "    /* Wildcards contain an irrelevant integer value, that changes often. */
	"48 8D 15 ? ? ? ? " /* Wildcards reference string "CEventHandler" */
	"48 8D 0D ? ? ? ? " /* Wildcards reference string "pHandler == null" */
	"E8 ? ? ? ?"        /* Function call to a sub function, we actually want a pointer to. */
);
const memtools::DataScan ExampleScan(
	PatternExample,

	/* Advance 9 bytes, to the second set of wildcards. */
	memtools::Offset(9),

	/* Compare against the expected string. */
	memtools::Strcmp("CEventHandler"),

	/* Advance another 7 bytes, to the third set of wildcards. */
	memtools::Offset(7),

	/* Compare against the expected string. */
	memtools::Strcmp("pHandler == null)",

	/* Advances 5 bytes to the third set of wildcards. */
	memtools::Offset(5),

	/* Follows the relative address into the function. */
	memtools::Follow()
);

void main()
{
	void* subfunc = ExampleScan.Scan();

	/* If the bytes matched and all actions are successful the returned pointer should be in the function called at E8 ? ? ? ?. */

	if (!subfunc)
	{
		/* Unsuccessful scan. No address returned. */
	}

	/* You can also create a "FallbackScan", which combines multiple DataScans. */
	memtools::FallbackScan fallback(
		ExampleScan,
		AnotherScan
	);

	subfunc = fallback.Scan();
}
```

## Patch
A patch utility also exists. Its purpose is to create a runtime patch at a given address, which can later be deleted.

### Usage
`Patch(void* aTarget, uint8_t* aBytes);`
```cpp
memtools::Patch* someBytePatch = new Patch(targetAddr, "\xC8");

...

/* Removes the patched bytes and restores them to the original. */
delete someBytePatch;
```