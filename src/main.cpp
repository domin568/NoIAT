#include "utils.hpp"
#include "parser.hpp"
#include <fstream>
#include <iostream>

HANDLE stdoutHandle;

const char * packerCode = "\xc3";

extern "C" void stub32();
extern "C" void end_stub32();

void showBanner (HANDLE stdoutHandle)
{
	log ("NoIAT v. 0.0.1\n", logType::INFO, stdoutHandle);
}

int main (int argc, char ** argv)
{
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	showBanner(stdoutHandle);

	if (argc < 3)
	{
		log ("Usage: NoIAT.exe <in.exe> <out.exe>", logType::ERR, stdoutHandle);
		return 1;
	}

	std::ifstream inPeFile (argv[1], std::ifstream::binary);

	inPeFile.seekg (0, std::ios::end);
	std::streamsize peSize = inPeFile.tellg();
	std::vector<char> peData (peSize);
	inPeFile.seekg(0, std::ios::beg);
	inPeFile.read (peData.data(), peSize);

	try
	{
		parser p (peData);
		std::vector <IMAGE_SECTION_HEADER> sections = p.parseSections ();

		uint32_t stub_size = (uint32_t)((char*)end_stub32 - (char*)stub32) + 1;

		log (".noiat stub size %d\n", logType::ERR, stdoutHandle, stub_size);

		p.addStubSection ((char*)stub32,stub_size);

		std::ofstream outPeFile (argv[2], std::ofstream::binary);
		outPeFile.write (reinterpret_cast<const char*>(&peData[0]), peData.size());
		outPeFile.close();
	}
	catch (const std::runtime_error & ex)
	{
		std::cout << ex.what() << std::endl;
        return 1;
	}
	catch (const std::exception & e)
	{
		std::cout << e.what() << std::endl;
		return 2;
	}
	return 0;
}