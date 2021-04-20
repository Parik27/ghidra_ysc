/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidraysc;

import java.io.IOException; 
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import yscFormat.YscHeader;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidraYSCLoader extends AbstractLibrarySupportLoader {

	private long STRO;
	private long STO;
	private long NO;
	private long GLO;
	
	private long currentOffset = 0;
	
	@Override
	public String getName() {
		return "RAGE Script Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader br = new BinaryReader (provider, true);
		new YscHeader (br);

		List<QueryResult> queries =
				QueryOpinionService.query(getName(), null, null);
		for(QueryResult result : queries) {
			loadSpecs.add(new LoadSpec(this, 0, result));
		}
		
		return loadSpecs;
	}
	
	private long loadCode (BinaryReader br, YscHeader header, Program program, MessageLog log) throws IOException, MemoryAccessException
	{
		// Create a .code block
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress( currentOffset );
		MemoryBlockUtils.createInitializedBlock(program, false, "code", start, header.CodeSize,
				"code", "", true, false, true, log);
		
		currentOffset += header.CodeSize;
		
		// Read Code pages
		for (int i = 0; i < header.GetPagesCount(header.CodeSize); i++)
		{
			br.setPointerIndex (header.CodeBlocksBasePointer + (i * 8));
			br.setPointerIndex(header.CorrectPointer(br.readNextLong()));
			
			long pageSize = header.GetPageSize(i, header.CodeSize);
			byte[] codeBlock = br.readNextByteArray((int) pageSize);
			
			program.getMemory().setBytes(start, codeBlock);
			start = start.add (pageSize);
		}
		
		return start.getOffset();
	}
	
	private long loadStrings (BinaryReader br, YscHeader header, Program program, MessageLog log) throws IOException, MemoryAccessException
	{
		// Create a .strings block
		Address start = program.getAddressFactory().getAddressSpace("ram").getAddress( currentOffset );
		MemoryBlockUtils.createInitializedBlock(program, false, "strings", start, header.StringSize,
				"strings", "", true, false, false, log);
		
		currentOffset += header.StringSize;
		
		// Read Code pages
		for (int i = 0; i < header.GetPagesCount(header.StringSize); i++)
		{
			br.setPointerIndex (header.StringBlocksBasePointer + (i * 8));
			br.setPointerIndex(header.CorrectPointer(br.readNextLong()));
			
			long pageSize = header.GetPageSize(i, header.StringSize);
			byte[] stringBlock = br.readNextByteArray((int) pageSize);
			
			program.getMemory().setBytes(start, stringBlock);
			start = start.add (pageSize);
		}
		
		return currentOffset - header.StringSize;
	}
	
	private long addBlock(byte[] array, String name, Program program,
			MessageLog log, String space) throws MemoryAccessException
	{
		if(array.length == 0) return currentOffset; 
		Address start = program.getAddressFactory().getAddressSpace(space).getAddress( currentOffset );
		
		MemoryBlockUtils.createInitializedBlock(program, false, name, start, array.length,
				name, "", true, true, false, log);
		
		currentOffset += array.length;
		
		program.getMemory().setBytes(start, array);
		return start.getOffset();
	}
	
	private long addBlock(byte[] array, String name, Program program,
			MessageLog log) throws MemoryAccessException
	{
		return addBlock (array, name, program, log, "ram");
	}
	
	private long addBlock(String name, Program program, MessageLog log, long length, String space, boolean write)
	{
		Address start = program.getAddressFactory().getAddressSpace(space).getAddress( currentOffset );
		MemoryBlockUtils.createUninitializedBlock(program, false, name, start, length, "", "", true, write, false, log);
		
		currentOffset += length;
		return start.getOffset();
	}
	
	private long addBlock(String name, Program program, MessageLog log, long length)
	{
		return addBlock (name, program, log, length, "ram", true);
	}
	
	private void setRegisterVal (Program program, Address start, Address end, String register, long value)
	{
		var reg = program.getRegister (register);
		RegisterValue val = new RegisterValue (reg, BigInteger.valueOf(value));
		
		try {
			program.getProgramContext().setRegisterValue(start, end, val);
		} catch (ContextChangeException e) {
			e.printStackTrace();
		}
	}
	
	private void setRegisterValues (Program program, YscHeader header)
	{
		Address start = program.getAddressFactory().getDefaultAddressSpace ().getAddress (0);
		Address end = program.getAddressFactory().getDefaultAddressSpace ().getAddress (header.CodeSize);
				
		setRegisterVal (program, start, end, "STRO", STRO);
		setRegisterVal (program, start, end, "STO", STO);
		setRegisterVal (program, start, end, "NO", NO);
		setRegisterVal (program, start, end, "GLO", GLO);
	}
	
	long getNativeHash(long nativeEnc, short index, long codeSize)
	{
		byte rotate = (byte) ((index + codeSize) & 0x3F);
		return nativeEnc << rotate | nativeEnc >>> (64 - rotate);
	}
	
	private void readNatives (Program program, BinaryReader br, YscHeader header) throws IOException, InvalidInputException, AddressOutOfBoundsException, OverlappingFunctionException
	{
		long[] natives = br.readLongArray(header.NativesPointer, header.NativesCount);
		short index = 0;
		
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(NO);
		for (long nat : natives) {
			program.getFunctionManager().createFunction(
					String.format("n_%016X", getNativeHash (nat, index, header.CodeSize)), addr,
					new AddressSet (addr, addr.add(7)), SourceType.IMPORTED);
			System.out.println(getNativeHash (nat, index, header.CodeSize));
			
			index++;			
			addr = addr.add(8);
		}
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		BinaryReader br = new BinaryReader (provider, true);
		YscHeader header = new YscHeader (br);
		
		try {
			loadCode (br, header, program, log);			
			STO = addBlock (br.readByteArray(header.StaticsPointer, header.StaticCount * 8), ".statics", program, log);
			STRO = loadStrings (br, header, program, log);
			NO = addBlock (".natives", program, log, header.NativesCount * 8, "ram", false);
			GLO = addBlock (".globals", program, log, 0x100000);
			
			setRegisterValues(program, header);
			readNatives (program, br, header);
			
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidInputException e) {
			e.printStackTrace();
		} catch (AddressOutOfBoundsException e) {
			e.printStackTrace();
		} catch (OverlappingFunctionException e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new Option("Global Variables Size", 0x800000));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
