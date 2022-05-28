#pragma once

#include <windows.h>
#include <vector>
#include <map>
#include <inttypes.h>
#include <stdio.h>
#include <sstream>
#include <cstring>
#include <stdexcept>
#include <stdlib.h>
#include "utils.hpp"
#include "cryptlib.h"
#include <iostream>

extern HANDLE stdoutHandle;

struct importData
{
	std::string dllName;
	std::vector <IMAGE_IMPORT_BY_NAME *> thunks;
	std::map <uint32_t *, uint64_t> funcInfo; // hash + rva 
};

class parser 
{
	private:
		std::map <DWORD, std::string> importOffsetToName;
		std::vector<importData> iData;
		bool hasIAT;
		architecture arch;
		uint16_t ntHeadersOff;
		IMAGE_NT_HEADERS32 * ntHeaders;
		IMAGE_DOS_HEADER * dosHeader;
		std::vector <char> & peData;
		std::vector <IMAGE_SECTION_HEADER> sections;
		uint32_t getFirstFreeVirtualSectionOffset ();
		uint32_t getFirstFreeFileSectionOffset ();
		DWORD convertRVAToFile(DWORD RVA);
		IMAGE_DATA_DIRECTORY * getDataDirectories ();
		void parseIAT ();
		void parse ();
		void fixGuardCF(uint32_t oep, uint32_t newEP);
	public:

		parser (std::vector <char> & peData);
		parser (const parser& rhs);
		std::vector <IMAGE_SECTION_HEADER> parseSections ();
		std::vector <dataBlob> getExcludedSections ();
		void addStubSection (const char * unpackCode, const uint32_t size);
		void savePackedPE (std::string name);
};

class parserException : public std::runtime_error 
{
	private:

		std::string msg;
		const char* file;
    	int line;
    	const char* func;

    public:

    	parserException(const std::string & arg, const char* file_, int line_, const char* func_);
    	~parserException() throw() {}
    	const char * what() const throw();

        const char* get_file() const { return file; }
        int get_line() const { return line; }   
        const char* get_func() const { return func; }
};

#ifdef __MINGW32__

namespace mingw_specific
{
	struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
		WORD Flags;
		WORD Catalog;
		DWORD CatalogOffset;
		DWORD Reserved;
	};

	typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32 {
		DWORD                            Size;
		DWORD                            TimeDateStamp;
		WORD                             MajorVersion;
		WORD                             MinorVersion;
		DWORD                            GlobalFlagsClear;
		DWORD                            GlobalFlagsSet;
		DWORD                            CriticalSectionDefaultTimeout;
		DWORD                            DeCommitFreeBlockThreshold;
		DWORD                            DeCommitTotalFreeThreshold;
		DWORD                            LockPrefixTable;
		DWORD                            MaximumAllocationSize;
		DWORD                            VirtualMemoryThreshold;
		DWORD                            ProcessHeapFlags;
		DWORD                            ProcessAffinityMask;
		WORD                             CSDVersion;
		WORD                             DependentLoadFlags;
		DWORD                            EditList;
		DWORD                            SecurityCookie;
		DWORD                            SEHandlerTable;
		DWORD                            SEHandlerCount;
		DWORD                            GuardCFCheckFunctionPointer;
		DWORD                            GuardCFDispatchFunctionPointer;
		DWORD                            GuardCFFunctionTable;
		DWORD                            GuardCFFunctionCount;
		DWORD                            GuardFlags;
		IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
		DWORD                            GuardAddressTakenIatEntryTable;
		DWORD                            GuardAddressTakenIatEntryCount;
		DWORD                            GuardLongJumpTargetTable;
		DWORD                            GuardLongJumpTargetCount;
		DWORD                            DynamicValueRelocTable;
		DWORD                            CHPEMetadataPointer;
		DWORD                            GuardRFFailureRoutine;
		DWORD                            GuardRFFailureRoutineFunctionPointer;
		DWORD                            DynamicValueRelocTableOffset;
		WORD                             DynamicValueRelocTableSection;
		WORD                             Reserved2;
		DWORD                            GuardRFVerifyStackPointerFunctionPointer;
		DWORD                            HotPatchTableOffset;
		DWORD                            Reserved3;
		DWORD                            EnclaveConfigurationPointer;
		DWORD                            VolatileMetadataPointer;
		DWORD                            GuardEHContinuationTable;
		DWORD                            GuardEHContinuationCount;
		DWORD                            GuardXFGCheckFunctionPointer;
		DWORD                            GuardXFGDispatchFunctionPointer;
		DWORD                            GuardXFGTableDispatchFunctionPointer;
		DWORD                            CastGuardOsDeterminedFailureMode;
		DWORD                            GuardMemcpyFunctionPointer;
	} IMAGE_LOAD_CONFIG_DIRECTORY32, * PIMAGE_LOAD_CONFIG_DIRECTORY32;


	typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64 {
		DWORD                            Size;
		DWORD                            TimeDateStamp;
		WORD                             MajorVersion;
		WORD                             MinorVersion;
		DWORD                            GlobalFlagsClear;
		DWORD                            GlobalFlagsSet;
		DWORD                            CriticalSectionDefaultTimeout;
		ULONGLONG                        DeCommitFreeBlockThreshold;
		ULONGLONG                        DeCommitTotalFreeThreshold;
		ULONGLONG                        LockPrefixTable;
		ULONGLONG                        MaximumAllocationSize;
		ULONGLONG                        VirtualMemoryThreshold;
		ULONGLONG                        ProcessAffinityMask;
		DWORD                            ProcessHeapFlags;
		WORD                             CSDVersion;
		WORD                             DependentLoadFlags;
		ULONGLONG                        EditList;
		ULONGLONG                        SecurityCookie;
		ULONGLONG                        SEHandlerTable;
		ULONGLONG                        SEHandlerCount;
		ULONGLONG                        GuardCFCheckFunctionPointer;
		ULONGLONG                        GuardCFDispatchFunctionPointer;
		ULONGLONG                        GuardCFFunctionTable;
		ULONGLONG                        GuardCFFunctionCount;
		DWORD                            GuardFlags;
		IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
		ULONGLONG                        GuardAddressTakenIatEntryTable;
		ULONGLONG                        GuardAddressTakenIatEntryCount;
		ULONGLONG                        GuardLongJumpTargetTable;
		ULONGLONG                        GuardLongJumpTargetCount;
		ULONGLONG                        DynamicValueRelocTable;
		ULONGLONG                        CHPEMetadataPointer;
		ULONGLONG                        GuardRFFailureRoutine;
		ULONGLONG                        GuardRFFailureRoutineFunctionPointer;
		DWORD                            DynamicValueRelocTableOffset;
		WORD                             DynamicValueRelocTableSection;
		WORD                             Reserved2;
		ULONGLONG                        GuardRFVerifyStackPointerFunctionPointer;
		DWORD                            HotPatchTableOffset;
		DWORD                            Reserved3;
		ULONGLONG                        EnclaveConfigurationPointer;
		ULONGLONG                        VolatileMetadataPointer;
		ULONGLONG                        GuardEHContinuationTable;
		ULONGLONG                        GuardEHContinuationCount;
		ULONGLONG                        GuardXFGCheckFunctionPointer;
		ULONGLONG                        GuardXFGDispatchFunctionPointer;
		ULONGLONG                        GuardXFGTableDispatchFunctionPointer;
		ULONGLONG                        CastGuardOsDeterminedFailureMode;
		ULONGLONG                        GuardMemcpyFunctionPointer;
	} IMAGE_LOAD_CONFIG_DIRECTORY64, * PIMAGE_LOAD_CONFIG_DIRECTORY64;

}
#endif