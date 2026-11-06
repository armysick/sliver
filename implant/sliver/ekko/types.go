package ekko

// M128A is a 128-bit register save slot (one XMM register).
type M128A struct {
	Low  uint64
	High int64
}

// CONTEXT is the full amd64 CONTEXT: 1232 bytes, Rsp at offset 152, Rip at
// 248, the XMM save area at 256. The chain hands these structs to
// NtContinue, which reads the integer, segment and XMM areas at exactly
// these offsets, so init() asserts the layout. FltSave is the winnt.h
// union (Header[2] + Legacy[8] + Xmm0-Xmm15) kept as a raw 512-byte block
// — the chain never sets XMM state, it only has to leave the offsets of
// the later fields correct.
//
// (goEkko, which this package supersedes, omitted the 512-byte XMM area:
// its VectorRegister landed at offset 256 and every later field was
// shifted. It happened to work because the chain only sets fields below
// offset 256 and the garbage XMM values went into registers the chain
// never relies on — but GetThreadContext would have overflowed it.)
type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

// ustring mirrors UNICODE_STRING as SystemFunction032 expects it: two
// 32-bit lengths followed by the buffer pointer, 16 bytes total.
type ustring struct {
	Length        uint32
	MaximumLength uint32
	Buffer        uintptr
}

// imageNTHeaders64Prefix reads just enough of IMAGE_NT_HEADERS64 to reach
// SizeOfImage in the optional header.
type imageNTHeaders64Prefix struct {
	Signature uint32
	// IMAGE_FILE_HEADER (20 bytes)
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
	// IMAGE_OPTIONAL_HEADER64 (partial, up to SizeOfImage)
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
}
