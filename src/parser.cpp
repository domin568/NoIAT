#include "parser.hpp"

#define throw_line(arg) throw parserException(arg, __FILE__, __LINE__, __func__);

parserException::parserException(const std::string & arg, const char* file_, int line_, const char* func_) : std::runtime_error(arg),
	file (file_),
	line (line_),
	func (func_)
{
	std::ostringstream o;
    o << file << ":" << line << ": " << func << ": " << arg;
    msg = o.str();
}
const char * parserException::what() const throw() 
{
	return msg.c_str();
}
void parser::parseIAT ()
{
	iData.reserve(20);

	IMAGE_DATA_DIRECTORY * dataDirectories = getDataDirectories ();

	IMAGE_DATA_DIRECTORY import = dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!import.VirtualAddress)
	{
		return;
	}

	IMAGE_IMPORT_DESCRIPTOR * importDescriptor = (IMAGE_IMPORT_DESCRIPTOR *) (peData.data() + convertRVAToFile(import.VirtualAddress));

	for (; importDescriptor->FirstThunk != 0; importDescriptor++)
	{
		importData libImportData;

		uint32_t currThunkOffset = convertRVAToFile(importDescriptor->FirstThunk);
		uint32_t currLibNameOffset = convertRVAToFile(importDescriptor->Name);

		libImportData.dllName = std::string(peData.data() + currLibNameOffset);

		//log ("currThunkOffset %.08x \n", logType::INFO, stdoutHandle, currThunkOffset);
		//log ("import dll name %s \n", logType::INFO, stdoutHandle, peData.data() + currLibNameOffset);

		if (arch == x64)
		{
		/*
			PIMAGE_THUNK_DATA64 thunks = (PIMAGE_THUNK_DATA64) (peData.data() + currThunkOffset); 

			for (; thunks->u1.AddressOfData != 0; thunks++)
			{
				if (thunks->u1.AddressOfData > 0x80000000) 
				{} // TODO
				else
				{
					IMAGE_IMPORT_BY_NAME * thunk = (IMAGE_IMPORT_BY_NAME *) (peData.data() + convertVAToFile(thunks->u1.AddressOfData));

					libImportData.thunks.push_back(thunk);
					std::string importName (thunk->Name);

					std::cout << thunk->Name << std::endl;
					std::cout << importName.size() << std::endl;
					CryptoPP::byte * shaDigest = ::SHA256(importName);

					libImportData.funcInfo.insert ({shaDigest, (uint64_t)() })
					//libImportData.hashes.push_back (shaDigest);		
				}
			}
			iData.push_back (libImportData);
		*/
		}
		else if (arch == x86)
		{
			uint32_t importOffset = 0;
			PIMAGE_THUNK_DATA32 thunks = (PIMAGE_THUNK_DATA32) (peData.data() + currThunkOffset); 
			for (; thunks->u1.AddressOfData != 0; thunks++)
			{
				if (thunks->u1.AddressOfData > 0x80000000) 
				{} // TODO
				else
				{
					IMAGE_IMPORT_BY_NAME * thunk = (IMAGE_IMPORT_BY_NAME *) (peData.data() + convertRVAToFile(thunks->u1.AddressOfData));

					libImportData.thunks.push_back(thunk);
					std::string importName ((const char *)thunk->Name);

					importOffsetToName.insert(std::make_pair(importDescriptor->FirstThunk + importOffset, importName));

					log (" %s ----> %s [%.08x] \n", logType::INFO, stdoutHandle, libImportData.dllName.c_str(), thunk->Name, importDescriptor->FirstThunk + importOffset);
		
					CryptoPP::byte * shaDigest = ::SHA1(importName);

					uint32_t *sha1DwordLe = (uint32_t *) shaDigest;
					sha1DwordLe[0] = be2le(sha1DwordLe[0]);
					sha1DwordLe[1] = be2le(sha1DwordLe[1]);
					sha1DwordLe[2] = be2le(sha1DwordLe[2]);
					sha1DwordLe[3] = be2le(sha1DwordLe[3]);
					sha1DwordLe[4] = be2le(sha1DwordLe[4]);

					libImportData.funcInfo.insert ({sha1DwordLe, (uint64_t)(importDescriptor->FirstThunk + importOffset)});

					//libImportData.hashes.push_back (shaDigest);		 
				}
				importOffset += 4;
			}
			iData.push_back (libImportData);
		}
	}
	for (const importData & libData : iData)
	{
		log ("import dll name %s \n", logType::INFO, stdoutHandle, libData.dllName.c_str());
		for (IMAGE_IMPORT_BY_NAME * thunk : libData.thunks)
		{
			//log ("----> %s \n", logType::INFO, stdoutHandle, thunk->Name);
		}
		for (const auto & func : libData.funcInfo)
		{
			log (" %s ----> %.08x%.08x%.08x%.08x%.08x [%.08x] \n", logType::INFO, stdoutHandle, libData.dllName.c_str(), func.first[0],func.first[1],func.first[2],func.first[3],func.first[4], func.second);	
		}
	}
}
DWORD parser::convertRVAToFile (DWORD RVA) // if possible, when section is not present in file then return 0
{
	for (const IMAGE_SECTION_HEADER & section : sections)
	{
		if (RVA >= section.VirtualAddress && RVA < section.VirtualAddress + section.Misc.VirtualSize)
		{
			return (section.PointerToRawData + (RVA - section.VirtualAddress));
		}
	}
	return 0;
}
std::vector <IMAGE_SECTION_HEADER> parser::parseSections ()
{
	sections.reserve (20);
	if (ntHeaders->FileHeader.NumberOfSections > 0)
	{
		WORD nSections = ntHeaders->FileHeader.NumberOfSections;

		IMAGE_SECTION_HEADER * sectionsPtr = (IMAGE_SECTION_HEADER *)( (uint8_t * ) ntHeaders + sizeof(ntHeaders->Signature) + sizeof (IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);

		sections.assign (sectionsPtr, sectionsPtr + nSections);
	}
	else
	{
		throw_line ("File has no sections (probably malformed PE file)");

	}

	parseIAT ();

	return sections;
}
IMAGE_DATA_DIRECTORY * parser::getDataDirectories ()
{
	DWORD dataDirectoryCount = ntHeaders->OptionalHeader.NumberOfRvaAndSizes;
	DWORD dataDirectoryOffset;
	if (arch == x86)
	{
		dataDirectoryOffset = 96;
	}
	else if (arch == x64)
	{
		dataDirectoryOffset = 112;
	}

	return (IMAGE_DATA_DIRECTORY *) (peData.data() + dosHeader->e_lfanew + 4 + sizeof (IMAGE_FILE_HEADER) + dataDirectoryOffset);
}
void parser::fixGuardCF(uint32_t oep, uint32_t newEP)
{
	IMAGE_DATA_DIRECTORY* directories = getDataDirectories();
	// ImageGuardCfFunctionTablePresent = 0x00000400 | ImageGuardCfInstrumented = 0x00000100 | ImageGuardProtectDelayloadIAT = 0x00001000 | ImageGuardDelayloadIATInItsOwnSection = 0x00002000 | ImageGuardCfExportSuppressionInfoPresent = 0x00004000 | ImageGuardCfLongjumpTablePresent = 0x00010000
	IMAGE_DATA_DIRECTORY loadConfigDir = directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	uint32_t loadConfigFileOffset = convertRVAToFile(loadConfigDir.VirtualAddress);
	uint32_t loadConfigSize = loadConfigDir.Size;

	if (loadConfigFileOffset == 0 || loadConfigSize == 0)
	{
		return;
	}



	if (arch == x86)
	{
		#if defined(__MINGW32__)
			mingw_specific::IMAGE_LOAD_CONFIG_DIRECTORY32* loadConfig = (mingw_specific::IMAGE_LOAD_CONFIG_DIRECTORY32 *)(peData.data() + loadConfigFileOffset);
		#else
			IMAGE_LOAD_CONFIG_DIRECTORY32* loadConfig = (IMAGE_LOAD_CONFIG_DIRECTORY32*)(peData.data() + loadConfigFileOffset);
		#endif

		uint32_t CFFuncCount = loadConfig->GuardCFFunctionCount;
		uint32_t imageBaseAntiMask = ntHeaders->OptionalHeader.ImageBase;
		if (CFFuncCount == 0 || imageBaseAntiMask == 0 || loadConfigSize <= 0x48)
		{
			return;
		}
		uint32_t CFFuncTableRVAOffset = loadConfig->GuardCFFunctionTable - imageBaseAntiMask;
		uint32_t CFFuncTableFileOffset = convertRVAToFile(CFFuncTableRVAOffset);

		loadConfig->GuardCFFunctionCount++;
		*(uint32_t*)(peData.data() + CFFuncTableFileOffset + (CFFuncCount * sizeof(uint32_t))) = newEP;
	}
	else if (arch == x64)
	{
		#if defined(__MINGW32__)
			mingw_specific::IMAGE_LOAD_CONFIG_DIRECTORY64* loadConfig = (mingw_specific::IMAGE_LOAD_CONFIG_DIRECTORY64*)(peData.data() + loadConfigFileOffset);
		#else
			IMAGE_LOAD_CONFIG_DIRECTORY64* loadConfig = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(peData.data() + loadConfigFileOffset);
		#endif
		uint32_t CFFuncCount = loadConfig->GuardCFFunctionCount;
		uint32_t imageBaseAntiMask = ntHeaders->OptionalHeader.ImageBase;
		if (CFFuncCount == 0 || imageBaseAntiMask == 0) // TODO loadConfigSize < ?
		{
			return;
		}
		uint32_t CFFuncTableRVAOffset = loadConfig->GuardCFFunctionTable - imageBaseAntiMask;
		uint32_t CFFuncTableFileOffset = convertRVAToFile(CFFuncTableRVAOffset);

		loadConfig->GuardCFFunctionCount++;
		*(uint64_t*)(peData.data() + CFFuncTableFileOffset + (CFFuncCount * sizeof(uint64_t))) = newEP;
	}
}
void parser::addStubSection (const char * unpackCode, const uint32_t size)
{
	uint32_t importDataSize = 0;
	for (const importData & libData : iData)
	{
		importDataSize += 4;
		uint32_t dllNameSize = libData.dllName.length();
		importDataSize += dllNameSize + 1;
		for (const auto & func : libData.funcInfo)
		{
			importDataSize += 28;	
		}
	}

	DWORD oepSize = 4;
	if (arch == x64)
	{
		oepSize = 8;
	}

	log("Import data size: %08x\n", logType::ERR, stdoutHandle, importDataSize);
	
	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
	DWORD freeFileSectionOffset = getFirstFreeFileSectionOffset ();
	DWORD freeVirtualSectionOffset = getFirstFreeVirtualSectionOffset ();
	DWORD currentHeadersSize = ntHeadersOff + sizeof(ntHeaders->Signature) + sizeof (IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader + sizeof (IMAGE_SECTION_HEADER) * ntHeaders->FileHeader.NumberOfSections;	
	DWORD dpackSectionSize = oepSize + size + importDataSize;
	DWORD dpackPaddingSize = roundUpTo(dpackSectionSize, ntHeaders->OptionalHeader.FileAlignment) -  dpackSectionSize;

	std::vector<uint8_t> dpackPadding (dpackPaddingSize, 0);

	uint32_t oep = ntHeaders->OptionalHeader.AddressOfEntryPoint;
	char * oepBytes = (char*) &oep;

	fixGuardCF(oep, freeVirtualSectionOffset + oepSize);

	log(".noiat section VirtualSectionOffset: %.16llx \n", logType::ERR, stdoutHandle, freeVirtualSectionOffset);
	log(".noiat section FileSectionOffset: %.16llx \n", logType::ERR, stdoutHandle, freeFileSectionOffset);

	IMAGE_SECTION_HEADER newSectionHeader;
	memset (&newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy (&newSectionHeader.Name, ".noiat\x00" , IMAGE_SIZEOF_SHORT_NAME);
	newSectionHeader.Misc.VirtualSize = dpackSectionSize;
	newSectionHeader.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE;
	newSectionHeader.PointerToRawData = freeFileSectionOffset;
	newSectionHeader.VirtualAddress = freeVirtualSectionOffset;

	newSectionHeader.SizeOfRawData = fileAlignment + fileAlignment * (dpackSectionSize / fileAlignment); // multiply of file alignment value
	
	ntHeaders->FileHeader.NumberOfSections += 1;

	ntHeaders->OptionalHeader.AddressOfEntryPoint = freeVirtualSectionOffset + oepSize;
	ntHeaders->OptionalHeader.SizeOfImage += roundUpTo(dpackSectionSize, ntHeaders->OptionalHeader.SectionAlignment);
	ntHeaders->OptionalHeader.SizeOfCode += roundUpTo(dpackSectionSize, ntHeaders->OptionalHeader.FileAlignment);
	ntHeaders->OptionalHeader.BaseOfCode = freeVirtualSectionOffset;
	ntHeaders->OptionalHeader.CheckSum = 0;

	IMAGE_DATA_DIRECTORY * dataDirectories = getDataDirectories ();

	// delete import info, resolve APIs dynamically

	dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	dataDirectories[ IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	dataDirectories[ IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;

	dataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
	dataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;

	if (currentHeadersSize + sizeof (IMAGE_SECTION_HEADER) > ntHeaders->OptionalHeader.SizeOfHeaders) // new header is not able to fit in current space, "allocate" new data (file alignment value) and change HeadersSize
	{
		// NOT TESTED
		log ("Header section has not enough size (%.8x + %.8x > %.8x), adding space for new section header .dpack \n", logType::INFO, stdoutHandle, currentHeadersSize, sizeof (IMAGE_SECTION_HEADER), ntHeaders->OptionalHeader.SizeOfHeaders);
		std::vector<uint8_t> padding (fileAlignment - sizeof (IMAGE_SECTION_HEADER), 0);
		peData.insert (peData.begin() + currentHeadersSize + sizeof (IMAGE_SECTION_HEADER), padding.begin(), padding.end());
		ntHeaders->OptionalHeader.SizeOfHeaders += fileAlignment;
		
		IMAGE_SECTION_HEADER * sectionsPtr = (IMAGE_SECTION_HEADER *)( (uint8_t * ) ntHeaders + sizeof(ntHeaders->Signature) + sizeof (IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);
		for (int i = 0 ; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			sectionsPtr[i].PointerToRawData += fileAlignment;
		}
	}

	// custom header filling with info

	memcpy (peData.data() + currentHeadersSize, &newSectionHeader, sizeof(IMAGE_SECTION_HEADER));

	// inserting new section
	// insert can reallocate memory so I have to write all at the end, ntHeaders is pointer to old memory

	peData.insert (peData.begin() + freeFileSectionOffset, oepBytes, oepBytes + oepSize);
	peData.insert (peData.begin() + freeFileSectionOffset + oepSize, unpackCode, unpackCode + size); // works also with overlay

	uint32_t stubEndAddr = freeFileSectionOffset + oepSize + size;

	uint32_t currentOffset = 0;
	for (const importData & libData : iData)  // [IMPORT FUNC SIZE | 4 BYTES] [DLL NAME XORED WITH 0xBE] [ADDR | 20 BYTES HASH] * IMPORT FUNC SIZE 
	{
		char * xoredDllName = new char [libData.dllName.length() + 1];
		memcpy (xoredDllName,libData.dllName.c_str(),libData.dllName.length());
		xoredDllName[libData.dllName.length()] = 0x00; // add null byte 
		for (int i = 0 ; i < libData.dllName.length() + 1; i++)
		{
			xoredDllName[i] ^= 0xbe;
		}

		uint32_t importCount = libData.funcInfo.size();
		char * importCountPtr = (char *) &importCount;

		log ("Import count %.08x \n", logType::INFO, stdoutHandle, importCount);

		peData.insert (peData.begin() + stubEndAddr + currentOffset, importCountPtr, importCountPtr + 4);
		currentOffset += 4;
		peData.insert (peData.begin() + stubEndAddr + currentOffset, xoredDllName, xoredDllName + libData.dllName.length() + 1);
		currentOffset += libData.dllName.length() + 1;

		for (const auto & func : libData.funcInfo)
		{
			DWORD savedOffsetFuncIAT = func.second;
			char * offsetFuncIAT = (char *) &func.second;
			for (int i = 0 ; i < 8; i++)
			{
				offsetFuncIAT[i] ^= 0xab;
			}
			peData.insert (peData.begin() + stubEndAddr + currentOffset, offsetFuncIAT, offsetFuncIAT + 8);
			currentOffset += 8;

			char * hash = (char *) func.first;
			peData.insert (peData.begin() + stubEndAddr + currentOffset, hash, hash + 20);
			currentOffset += 20;

			char* api_info_str = new char[importOffsetToName[savedOffsetFuncIAT].length() + libData.dllName.length() + 20];

			if (sprintf(api_info_str, "%s!%s", libData.dllName.c_str(), importOffsetToName[savedOffsetFuncIAT].c_str()))
			{
				log("%-50s %.08x%.08x%.08x%.08x%.08x [%.08x] \n", logType::INFO, stdoutHandle, api_info_str, func.first[0], func.first[1], func.first[2], func.first[3], func.first[4], savedOffsetFuncIAT);
			}
			else
			{
				log("Error with formatting output \n", logType::ERR, stdoutHandle, importCount);
			}
		}
	}

	// inserting dpack section padding
	peData.insert (peData.begin() + freeFileSectionOffset + dpackSectionSize, dpackPadding.begin(), dpackPadding.end());
}
uint32_t parser::getFirstFreeFileSectionOffset ()
{
	if (sections.size() == 0)
	{
		parseSections();
	}
	uint16_t maxSectionAddrIdx = 0;
	uint32_t maxAddr = 0; 
	for (uint32_t i = 0; i < sections.size(); i++)
	{
		if (sections[i].PointerToRawData > maxAddr)
		{
			maxAddr = sections[i].PointerToRawData;
			maxSectionAddrIdx = i;
		}
	}
	return sections[maxSectionAddrIdx].PointerToRawData + sections[maxSectionAddrIdx].SizeOfRawData;
}
uint32_t parser::getFirstFreeVirtualSectionOffset ()
{
	if (sections.size() == 0)
	{
		parseSections();
	}
	uint16_t maxSectionAddrIdx = 0;
	uint32_t maxAddr = 0; 
	for (uint32_t i = 0; i < sections.size(); i++)
	{
		if (sections[i].VirtualAddress > maxAddr)
		{
			maxAddr = sections[i].VirtualAddress;
			maxSectionAddrIdx = i;
		}
	}
	// align to section 
	uint32_t toRet = sections[maxSectionAddrIdx].VirtualAddress + sections[maxSectionAddrIdx].Misc.VirtualSize;
	DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	if (toRet % sectionAlignment == 0)
	{
		return toRet;
	}
	toRet = sectionAlignment + sectionAlignment * (toRet / sectionAlignment);
	return toRet;
}
void parser::parse ()
{
	dosHeader =  (IMAGE_DOS_HEADER *) peData.data();
	if (dosHeader->e_magic != 0x5A4D)
	{
		throw_line ("File is not PE (missing MZ)");
	}
	ntHeadersOff = dosHeader->e_lfanew;
	ntHeaders = (IMAGE_NT_HEADERS32 *) (peData.data() + ntHeadersOff);
	if (ntHeaders->Signature != 0x00004550)
	{
		throw_line ("File is not PE (missing PE)");
	}

	WORD machine = ntHeaders->FileHeader.Machine;

	if (machine != IMAGE_FILE_MACHINE_I386) // && machine != IMAGE_FILE_MACHINE_AMD64)
	{
		throw_line ("File is not supported (unsupported architecture)");
		return;
	}
	if (machine == IMAGE_FILE_MACHINE_I386)
	{
		arch = x86;
	}
	else if (machine == IMAGE_FILE_MACHINE_AMD64)
	{
		arch = x64;
	}
}
parser::parser (const parser& rhs) : peData(rhs.peData) // must initialize reference also in copy constructor
{
	hasIAT = 0;
	parse();
}
parser::parser (std::vector<char> & peData_) : peData(peData_)
{
	hasIAT = 0;
	parse();
}