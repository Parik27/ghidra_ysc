/**
 * 
 */
package yscFormat;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * @author parik
 *
 */
public class YscHeader implements StructConverter {
	
	static final int PAGE_SIZE = 0x4000;

	public long PageBase;// 0x00
	public long pageMapPointer;// 0x08
	public long CodeBlocksBasePointer;// 0x10 Points to an array of code block offsets
	public int GlobalsSignature;// 0x18
	public int CodeSize;// 0x1C - The size of all the code tables
	public int ParameterCount;// 0x20 - These are for starting a script with args. The args appear at the start of the script static variables
	public int StaticCount;// 0x24 - The number of static variables in the script
	public int GlobalCount;// 0x28 - This is used for scripts that seem to initialise global variable tables
	public int NativesCount;// 0x2C - The total amount of natives in the native table
	public long StaticsPointer;// 0x30 - The Offset in file where static variables are initialised
	public long GlobalsPointer;// 0x38 - The Offset in file where global variales are initilaised(only used for registration scripts)
	public long NativesPointer;// 0x40 - The Offset in file where the natives table is stored
	public long Null1;//0x48
	public long Null2;//0x50;
	public int ScriptNameHash;//0x58 - A Jenkins hash of the scripts name
	public int UnkUsually1;//0x5C
	public long ScriptNamePointer;//0x60 - Points to an offset in the file that has the name of the script
	public long StringBlocksBasePointer;//0x68 - Points to an array of string block offsets
	public int StringSize;//0x70 - The Size of all the string tables
	public int Null3;//0x74
	public int Null4;//0x78
	public int Null5;//0x7C
	
	public boolean VerifyPointer (long ptr)
	{
		return (ptr & 0x50000000) != 0x5000000;
	}
	
	public long CorrectPointer (long ptr) throws IOException 
	{
		if (!VerifyPointer (ptr))
			throw new IOException ();
		
		return ptr & 0xFFFFFF;
	}
	
	public int GetSize () 
	{
		return 0x80;
	}
	
	public void CorrectPointers () throws IOException
	{
		pageMapPointer = CorrectPointer(pageMapPointer);
		CodeBlocksBasePointer = CorrectPointer(CodeBlocksBasePointer);
		StaticsPointer = CorrectPointer(StaticsPointer);
		GlobalsPointer = CorrectPointer(GlobalsPointer);
		NativesPointer = CorrectPointer(NativesPointer);
		ScriptNamePointer = CorrectPointer(ScriptNamePointer);
		StringBlocksBasePointer = CorrectPointer(StringBlocksBasePointer);
	}
	
	public long GetPagesCount (long totalSize)
	{
		return (totalSize / PAGE_SIZE) + 1;
	}
	
	public long GetPageSize (long pageIndex, long totalSize)
	{
		long MaxPageIndex = GetPagesCount (totalSize) - 1;
		
		if (pageIndex > MaxPageIndex || pageIndex < 0)
			return 0;
		
		if (pageIndex == MaxPageIndex)
			return totalSize % PAGE_SIZE;
		
		return PAGE_SIZE;
	}
	
	public YscHeader (BinaryReader r) throws IOException
	{
		PageBase = r.readNextLong();
		pageMapPointer = r.readNextLong();
		CodeBlocksBasePointer = r.readNextLong();
		GlobalsSignature = r.readNextInt();
		CodeSize = r.readNextInt();
		ParameterCount = r.readNextInt();
		StaticCount = r.readNextInt();
		GlobalCount = r.readNextInt();
		NativesCount = r.readNextInt();
		StaticsPointer = r.readNextLong();
		GlobalsPointer = r.readNextLong();
		NativesPointer = r.readNextLong();
		Null1 = r.readNextLong();
		Null2 = r.readNextLong();
		ScriptNameHash = r.readNextInt();
		UnkUsually1 = r.readNextInt();
		ScriptNamePointer = r.readNextLong();
		StringBlocksBasePointer = r.readNextLong();
		StringSize = r.readNextInt();
		Null3 = r.readNextInt();
		Null4 = r.readNextInt();
		Null5 = r.readNextInt();
					
		CorrectPointers ();
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("YSCHeader", 0);
		
		structure.add(QWORD, 8,  "pageBase" , " 0x00");
		structure.add(QWORD, 8,  "pageMapPointer" , " 0x08");
		structure.add(QWORD, 8,  "CodeBlocksBasePointer" , " 0x10 Points to an array of code block offsets");
		structure.add(DWORD, 4,  "GlobalsSignature" , " 0x18");
		structure.add(DWORD, 4,  "CodeSize" , " 0x1C - The size of all the code tables");
		structure.add(DWORD, 4,  "ParameterCount" , " 0x20 - These are for starting a script with args. The args appear at the start of the script static variables");
		structure.add(DWORD, 4,  "StaticCount" , " 0x24 - The number of static variables in the script");
		structure.add(DWORD, 4,  "GlobalCount" , " 0x28 - This is used for scripts that seem to initialise global variable tables");
		structure.add(DWORD, 4,  "NativesCount" , " 0x2C - The total amount of natives in the native table");
		structure.add(QWORD, 8,  "StaticsPointer" , " 0x30 - The Offset in file where static variables are initialised");
		structure.add(QWORD, 8,  "GlobalsPointer" , " 0x38 - The Offset in file where global variales are initilaised(only used for registration scripts)");
		structure.add(QWORD, 8,  "NativesPointer" , " 0x40 - The Offset in file where the natives table is stored");
		structure.add(QWORD, 8,  "Null1" , "0x48");
		structure.add(QWORD, 8,  "Null2" , "0x50;");
		structure.add(DWORD, 4,  "ScriptNameHash" , "0x58 - A Jenkins hash of the scripts name");
		structure.add(DWORD, 4,  "UnkUsually1" , "0x5C");
		structure.add(QWORD, 8,  "ScriptNamePointer" , "0x60 - Points to an offset in the file that has the name of the script");
		structure.add(QWORD, 8,  "StringBlocksBasePointer" , "0x68 - Points to an array of string block offsets");
		structure.add(DWORD, 4,  "StringSize" , "0x70 - The Size of all the string tables");
		structure.add(DWORD, 4,  "Null3" , "0x74");
		structure.add(DWORD, 4,  "Null4" , "0x78");
		structure.add(DWORD, 4,  "Null4" , "0x7C");
		return null;
	}

}
