///----------------------------------------------------------------------------------------------------
/// Copyright (c) Kevin Bieniek - Licensed under the MIT license.
///
/// Name         :  memtools.h
/// Description  :  x64 memory tools for pattern scanning, verification and navigation.
/// Authors      :  K. Bieniek
///----------------------------------------------------------------------------------------------------

#ifndef MEMTOOLS_H
#define MEMTOOLS_H

#include <windows.h>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <psapi.h>
#include <vector>

/// You can define ENABLE_PATTERN_CACHING which will store the first result matching a given pattern.
/// This potentially speeds up multiple searches starting with the same pattern.
//#define ENABLE_PATTERN_CACHING
#ifdef ENABLE_PATTERN_CACHING
#include <mutex>
#endif

#ifndef MAX_PATTERN_LENGTH
#define MAX_PATTERN_LENGTH     128
#endif

#ifndef MAX_INSTRUCTION_LENGTH
#define MAX_INSTRUCTION_LENGTH 16
#endif
#define CHAR_0                 0x30 /* ascii value for '0' */
#define CHAR_9                 0x39 /* ascii value for '9' */
#define CHAR_A                 0x41 /* ascii value for 'A' */
#define CHAR_F                 0x46 /* ascii value for 'F' */
#define HEXVAL_A               10   /* value of hex A */
#define HEXPOW_1               0x01 /* power of the first digit */
#define HEXPOW_2               0x10 /* power of the second digit */

///----------------------------------------------------------------------------------------------------
/// memtools Namespace
///----------------------------------------------------------------------------------------------------
namespace memtools
{
	///----------------------------------------------------------------------------------------------------
	/// FollowRelativeAddress:
	/// 	Follows a relative address.
	///----------------------------------------------------------------------------------------------------
	inline void* FollowRelativeAddress(void* aAddress)
	{
		int32_t jmpOffset = *(__unaligned int32_t*)aAddress;

		return (PBYTE)aAddress + jmpOffset + 4;
	}

	inline void* FollowJmpChain(PBYTE aPointer)
	{
		while (true)
		{
			if (aPointer[0] == 0xEB)
			{
				/* short jmp */
				/* address is relative to after jmp */
				aPointer += 2 + *(__unaligned int8_t*) & aPointer[1]; // jmp +imm8
			}
			else if (aPointer[0] == 0xE9)
			{
				/* near jmp */
				/* address is relative to after jmp */
				aPointer += 5 + *(__unaligned int32_t*) &aPointer[1]; // jmp +imm32
			}
			else if (aPointer[0] == 0xFF && aPointer[1] == 0x25)
			{
				/* far jmp */
				/* x64: address is relative to after jmp */
				/* x86: absolute address can be read directly */
#ifdef _WIN64
				aPointer += 6 + *(__unaligned int32_t*) &aPointer[2]; // jmp [+imm32]
#else
				aPointer = *(__unaligned int32_t*) &aPointer[2]; // jmp [imm32]
#endif
				/* dereference to get the actual target address */
				aPointer = *(__unaligned PBYTE*)aPointer;
			}
			else
			{
				break;
			}
		}

		return aPointer;
	}

	///----------------------------------------------------------------------------------------------------
	/// Byte Struct
	///----------------------------------------------------------------------------------------------------
	struct Byte
	{
		bool    IsWildcard = false;
		uint8_t Value      = 0;
	};

	///----------------------------------------------------------------------------------------------------
	/// Pattern Struct
	///----------------------------------------------------------------------------------------------------
	struct Pattern
	{
		Byte     Bytes[MAX_PATTERN_LENGTH];
		uint64_t Size;

		constexpr Pattern() : Bytes(), Size(0) {}
		inline constexpr Pattern(const char* aPattern) : Bytes(), Size(0)
		{
			uint64_t len = 0; /* length of the pattern string */

			while (aPattern[len])
			{
				len++;
			}

			uint64_t j = 0;

			for (uint64_t i = 0; i < len; i++)
			{
				/* Pattern string not done, but already filled max byte length. */
				if (this->Size >= MAX_PATTERN_LENGTH)
				{
					break;
				}

				/* Skip spaces. */
				if (aPattern[i] == ' ') { continue; }

				/* Skip angle brackets. (For marking significant bytes.)*/
				if (aPattern[i] == '<') { continue; }
				if (aPattern[i] == '>') { continue; }

				/* Match wildcard. */
				if (aPattern[i] == '?')
				{
					this->Bytes[j] = Byte{ true };
					this->Size++;
					j++;

					/* Match if double wildcard '??' instead of single wildcard '?'. */
					if (i + 1 < len && aPattern[i + 1] == '?')
					{
						i++;
					}

					continue;
				}

				/* Match hex. */
				if ((aPattern[i] >= CHAR_0 && aPattern[i] <= CHAR_9) || (aPattern[i] >= CHAR_A && aPattern[i] <= CHAR_F))
				{
					uint8_t val = 0;

					/* Match if double hex 'FF' instead of single hex 'F' */
					if (i + 1 < len && (aPattern[i + 1] >= CHAR_0 && aPattern[i + 1] <= CHAR_9) || (aPattern[i + 1] >= CHAR_A && aPattern[i + 1] <= CHAR_F))
					{
						/* Calculate byte value using position.*/
						if (aPattern[i] <= CHAR_9)
						{
							val += (aPattern[i] - CHAR_0) * HEXPOW_2;
						}
						else
						{
							val += ((aPattern[i] - CHAR_A) + HEXVAL_A) * HEXPOW_2;
						}

						/* Calculate second hex value part of byte. */
						if (aPattern[i + 1] <= CHAR_9)
						{
							val += (aPattern[i + 1] - CHAR_0) * HEXPOW_1;
						}
						else
						{
							val += ((aPattern[i + 1] - CHAR_A) + HEXVAL_A) * HEXPOW_1;
						}

						i++;
					}
					else
					{
						/* Single hex value. */
						if (aPattern[i] <= CHAR_9)
						{
							val += (aPattern[i] - CHAR_0) * HEXPOW_1;
						}
						else
						{
							val += ((aPattern[i] - CHAR_A) + HEXVAL_A) * HEXPOW_1;
						}
					}

					this->Bytes[j] = Byte{ false, val };
					this->Size++;
					j++;

					continue;
				}
				else
				{
					throw "Invalid hexadecimal.";
				}
			}
		}
	};

	inline bool operator==(const Pattern& lhs, const PBYTE rhs)
	{
		for (uint64_t i = 0; i < lhs.Size; i++)
		{
			if (!lhs.Bytes[i].IsWildcard && lhs.Bytes[i].Value != rhs[i])
			{
				return false;
			}
		}

		return true;
	}

	inline bool operator==(const Pattern& lhs, const Pattern& rhs)
	{
		return memcmp(&lhs, &rhs, sizeof(Pattern)) == 0;
	}

	inline bool operator!=(const Pattern& lhs, const Pattern& rhs)
	{
		return !(lhs == rhs);
	}

	///----------------------------------------------------------------------------------------------------
	/// EOperation Enumeration
	///----------------------------------------------------------------------------------------------------
	enum class EOperation
	{
		NONE,
		offset,
		follow,
		strcmp,
		wcscmp,
		cmpi8,
		cmpi16,
		cmpi32,
		cmpi64,
		pushaddr,
		popaddr,
		advwcard,
		funcentry
	};

	///----------------------------------------------------------------------------------------------------
	/// Instruction Struct
	///----------------------------------------------------------------------------------------------------
	struct Instruction
	{
		EOperation     Operation;
		int64_t        Value;
		const char*    String;
		const wchar_t* WString;

		constexpr Instruction()                                      : Operation(EOperation::NONE), Value(0),      String(nullptr), WString(nullptr) {}
		constexpr Instruction(EOperation aOp)                        : Operation(aOp),              Value(0),      String(nullptr), WString(nullptr) {}
		constexpr Instruction(EOperation aOp, int64_t        aValue) : Operation(aOp),              Value(aValue), String(nullptr), WString(nullptr) {}
		constexpr Instruction(EOperation aOp, const char*    aStr)   : Operation(aOp),              Value(0),      String(aStr),    WString(nullptr) {}
		constexpr Instruction(EOperation aOp, const wchar_t* aWStr)  : Operation(aOp),              Value(0),      String(nullptr), WString(aWStr) {}

		inline constexpr Instruction(const Instruction& aOther) 
			: Operation(aOther.Operation)
			, Value(aOther.Value)
			, String(aOther.String)
			, WString(aOther.WString)
		{}

		inline Instruction& operator=(const Instruction& aOther)
		{
			if (this == &aOther) { return *this; }

			this->Operation = aOther.Operation;
			this->Value = 0;
			this->String = nullptr;
			this->WString = nullptr;

			switch (this->Operation)
			{
				case EOperation::strcmp:
				{
					this->String = aOther.String;
					break;
				}
				case EOperation::wcscmp:
				{
					this->WString = aOther.WString;
					break;
				}
				default:
				{
					this->Value = aOther.Value;
					break;
				}
			}

			return *this;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// Offset:
	/// 	Adds an offset (in bytes) to the current memory address.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Offset(int64_t aValue) { return Instruction(EOperation::offset, aValue); }
	
	///----------------------------------------------------------------------------------------------------
	/// Follow:
	/// 	Interprets the current address as a relative address and follows it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Follow() { return Instruction(EOperation::follow); }

	///----------------------------------------------------------------------------------------------------
	/// Strcmp:
	/// 	Interprets the current address as a relative address to a string, follows and compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Strcmp(const char* aStr) { return Instruction(EOperation::strcmp, aStr); }

	///----------------------------------------------------------------------------------------------------
	/// Wcscmp:
	/// 	Interprets the current address as a relative address to a wstring, follows and compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction Wcscmp(const wchar_t* aWStr) { return Instruction(EOperation::wcscmp, aWStr); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI8:
	/// 	Interprets the current address as an i8 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI8(int64_t aValue) { return Instruction(EOperation::cmpi8, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI16:
	/// 	Interprets the current address as an i16 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI16(int64_t aValue) { return Instruction(EOperation::cmpi16, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI32:
	/// 	Interprets the current address as an i32 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI32(int64_t aValue) { return Instruction(EOperation::cmpi32, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// CmpI64:
	/// 	Interprets the current address as an i64 compares it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction CmpI64(int64_t aValue) { return Instruction(EOperation::cmpi64, aValue); }

	///----------------------------------------------------------------------------------------------------
	/// PushAddr:
	/// 	Stores the current address on the address stack.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction PushAddr() { return Instruction(EOperation::pushaddr); }

	///----------------------------------------------------------------------------------------------------
	/// PopAddr:
	/// 	Restores the last address on the address stack and removes it.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction PopAddr() { return Instruction(EOperation::popaddr); }

	///----------------------------------------------------------------------------------------------------
	/// AdvWcard:
	/// 	Adds an offset to the current offset, so that the address will be at the next set of wildcards.
	/// 	Pass aSets for how many amount of sets should be skipped.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction AdvWcard(int64_t aSets = 1) { return Instruction(EOperation::advwcard, aSets > 1 ? aSets : 1); }

	///----------------------------------------------------------------------------------------------------
	/// FuncEntry:
	/// 	Moves to the beginning of the current function.
	///----------------------------------------------------------------------------------------------------
	constexpr Instruction FuncEntry() { return Instruction(EOperation::funcentry); }

	///----------------------------------------------------------------------------------------------------
	/// PatternScan Struct
	///----------------------------------------------------------------------------------------------------
	struct PatternScan
	{
		Pattern                                         Assembly;
		std::array<Instruction, MAX_INSTRUCTION_LENGTH> Instructions = {};
		std::size_t                                     Count        = 0;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		template<typename... Instrs>
		constexpr PatternScan(Pattern aASM, Instrs... instrs)
			: Assembly(aASM)
			, Instructions{ instrs... }
			, Count(sizeof...(Instrs))
		{
			static_assert(sizeof...(Instrs) <= MAX_INSTRUCTION_LENGTH, "Too many instructions for DataScan.");
		}

		///----------------------------------------------------------------------------------------------------
		/// Scan:
		/// 	Scans for the memory pattern and returns its pointer if found.
		///----------------------------------------------------------------------------------------------------
		template <typename T = void*>
		inline T Scan() const
		{
			if (this->Assembly.Size == 0) { return nullptr; }

			void* resultAddr = nullptr;

			PBYTE addr = 0;

#ifdef ENABLE_PATTERN_CACHING
			struct PatternMatch
			{
				memtools::Pattern Pattern;
				void*             Address;
			};

			static std::mutex                s_PatternMatchMutex;
			static std::vector<PatternMatch> s_PatternMatchStore;

			{
				const std::lock_guard<std::mutex> lock(s_PatternMatchMutex);
				auto it = std::find_if(s_PatternMatchStore.begin(), s_PatternMatchStore.end(), [this](const PatternMatch& match)
				{
					return match.Pattern == this->Assembly;
				});

				/* If stored, start from stored address. */
				if (it != s_PatternMatchStore.end())
				{
					addr = (PBYTE)it->Address;
				}
			}
#endif

			MEMORY_BASIC_INFORMATION mbi{};

			while (resultAddr == nullptr)
			{
				/* If virtual query fails, stop scanning. */
				if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
				{
					break;
				}

				/* Advance query address into the next page. */
				addr += mbi.RegionSize;

				/* Sanity check: Page is smaller than bytes to match against. */
				if (this->Assembly.Size > mbi.RegionSize)
				{
					continue;
				}

				/* Skip uncommitted pages. */
				if (mbi.State != MEM_COMMIT)
				{
					continue;
				}

				/* Skip pages without read permission. */
				if (!(mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE))
				{
					continue;
				}

				PBYTE base = (PBYTE)mbi.BaseAddress;
				uint64_t end = mbi.RegionSize - this->Assembly.Size; // ensure not going out of bounds

				bool isMatch = false;

				for (uint64_t i = 0; i < end; i++)
				{
					isMatch = this->Assembly == &base[i];

					if (isMatch)
					{
#ifdef ENABLE_PATTERN_CACHING
						{
							const std::lock_guard<std::mutex> lock(s_PatternMatchMutex);
							auto it = std::find_if(s_PatternMatchStore.begin(), s_PatternMatchStore.end(), [this](const PatternMatch& match)
							{
								return match.Pattern == this->Assembly;
							});

							/* If stored, start from stort address. */
							if (it == s_PatternMatchStore.end())
							{
								s_PatternMatchStore.push_back(PatternMatch{ this->Assembly, base + i });
							}
						}
#endif

						resultAddr = base + i;

						uint32_t instructionsFailed = 0;

						std::vector<void*> addrStore{};

						/* Track offsets for wildcard advancing. */
						int64_t offsetFromMatch = 0;

						for (const Instruction& inst : this->Instructions)
						{
							EOperation op = inst.Operation;

							switch (op)
							{
								case EOperation::offset:
								{
									offsetFromMatch += inst.Value;
									resultAddr = (PBYTE)resultAddr + inst.Value;
									break;
								}
								case EOperation::follow:
								{
									resultAddr = FollowRelativeAddress((PBYTE)resultAddr);
									break;
								}
								case EOperation::strcmp:
								{
									instructionsFailed += strcmp((const char*)FollowRelativeAddress(resultAddr), inst.String) == 0 ? 0 : 1;
									break;
								}
								case EOperation::wcscmp:
								{
									instructionsFailed += wcscmp((const wchar_t*)FollowRelativeAddress(resultAddr), inst.WString) == 0 ? 0 : 1;
									break;
								}
								case EOperation::cmpi8:
								{
									instructionsFailed += *((int8_t*)resultAddr) == (int8_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::cmpi16:
								{
									instructionsFailed += *((int16_t*)resultAddr) == (int16_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::cmpi32:
								{
									instructionsFailed += *((int32_t*)resultAddr) == (int32_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::cmpi64:
								{
									instructionsFailed += *((int64_t*)resultAddr) == (int64_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::pushaddr:
								{
									addrStore.push_back(resultAddr);
									break;
								}
								case EOperation::popaddr:
								{
									resultAddr = addrStore.back();
									addrStore.pop_back();
									break;
								}
								case EOperation::advwcard:
								{
									/* Advance as many sets as in the parameter. */
									for (int64_t i = 0; i < inst.Value; i++)
									{
										bool wasAtWildcard = this->Assembly.Bytes[offsetFromMatch].IsWildcard;
										bool foundWildcard = false;

										while (offsetFromMatch < (int64_t)this->Assembly.Size)
										{
											if (wasAtWildcard && this->Assembly.Bytes[offsetFromMatch].IsWildcard)
											{
												offsetFromMatch++;
											}
											else if (!wasAtWildcard && this->Assembly.Bytes[offsetFromMatch].IsWildcard)
											{
												break;
											}
											else
											{
												offsetFromMatch++;
												wasAtWildcard = false;
											}
										}
									}

									resultAddr = base + i + offsetFromMatch;

									break;
								}
								case EOperation::funcentry:
								{
									DWORD64 imageBase = 0;
									PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(resultAddr), &imageBase, nullptr);

									if (!function)
									{
										instructionsFailed++;
										break;
									}

									resultAddr = reinterpret_cast<void*>(imageBase + function->BeginAddress);
									break;
								}
								default:
									break;
							}

							if (instructionsFailed)
							{
								/* interrupt if any failed */
								resultAddr = nullptr;
								break;
							}
						}

						if (!instructionsFailed)
						{
							/* the instructions were all executed, we interrupt the byte iteration */
							break;
						}
					}
				}
			}

			return (T)resultAddr;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// FallbackScan Struct
	///----------------------------------------------------------------------------------------------------
	struct FallbackScan
	{
		std::vector<PatternScan> Scans;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		inline FallbackScan(std::initializer_list<PatternScan> aScans)
		{
			for (const PatternScan& scan : aScans)
			{
				this->Scans.push_back(scan);
			}
		}

		///----------------------------------------------------------------------------------------------------
		/// Scan:
		/// 	Performs the datascans sequentially, returning if one succeeds. Otherwise returns nullptr.
		///----------------------------------------------------------------------------------------------------
		template <typename T = void*>
		inline T Scan() const
		{
			for (const PatternScan& scan : this->Scans)
			{
				void* result = scan.Scan();

				if (result)
				{
					return (T)result;
				}
			}

			return (T)nullptr;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// Patch Struct
	///----------------------------------------------------------------------------------------------------
	struct Patch
	{
		void*                Target = nullptr;
		std::vector<uint8_t> OriginalBytes;
		uint16_t             Size          = 0;

		Patch(const Patch&) = delete;
		Patch& operator=(const Patch&) = delete;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		inline Patch(void* aTarget, const uint8_t* aBytes, uint16_t aSize)
		{
			if (aTarget == nullptr) { throw "Target is nullptr."; }
			if (aBytes == nullptr)  { throw "Patch Bytes are nullptr."; }
			if (aSize == 0)         { throw "Patch Bytes are size 0."; }

			this->Target = aTarget;
			this->Size = aSize;
			this->OriginalBytes.resize(this->Size);

			DWORD oldProtect;
			if (VirtualProtect(this->Target, this->Size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				throw "Failed to change page protection.";
			}
			
			/* Copy the original bytes. */
			memcpy(this->OriginalBytes.data(), this->Target, this->Size);

			/* Write the new bytes. */
			memcpy(this->Target, aBytes, this->Size);

			/* Flush the instruction cache. */
			FlushInstructionCache(GetCurrentProcess(), this->Target, this->Size);

			/* Restore page protection. */
			VirtualProtect(this->Target, this->Size, oldProtect, &oldProtect);
		}

		///----------------------------------------------------------------------------------------------------
		/// dtor
		///----------------------------------------------------------------------------------------------------
		inline ~Patch()
		{
			if (this->Target == nullptr || this->OriginalBytes.empty())
			{
				return;
			}

			DWORD oldProtect;
			if (VirtualProtect(this->Target, this->Size, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				/* Restore original bytes. */
				memcpy(this->Target, this->OriginalBytes.data(), this->Size);

				/* Flush the instruction cache. */
				FlushInstructionCache(GetCurrentProcess(), this->Target, this->Size);

				/* Restore page protection. */
				VirtualProtect(this->Target, this->Size, oldProtect, &oldProtect);
			}
		}
	};
}

#endif
