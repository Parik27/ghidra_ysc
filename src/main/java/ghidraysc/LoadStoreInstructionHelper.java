package ghidraysc;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class LoadStoreInstructionHelper {

	Instruction inst;
	
	private int count = 0;
	
	private boolean foundPtr = false;
	private boolean foundSize = false;
	
	private int ptrAlign = 0;
	private boolean ptrNegativeGrowth = false;
	
	// Opcodes from which the pointer's nature can be deduced. This includes local,
	// static and global opcodes. The ignored opcodes are array and offset opcodes.
	private static final byte PTR_FINAL_OPS[] = { 55, 76, 58, 79, 82, 94, 93 };
	private static final byte PTR_IGNORE_OPS[] = { 52, 73, 64, 70 };

	// Opcodes from which size can be deduced. This includes all constant push
	// functions.
	private static final byte SIZE_FINAL_OPS[] = { 37, 40, 67, 97, 112, 113, 114, 115, 116, 117 };
	
	public LoadStoreInstructionHelper(Program program, InjectContext con) {
		inst = program.getListing().getInstructionAt(con.baseAddr).getPrevious();
	}
	
	private void setPointerFromCurrentInstruction ()
	{
		foundPtr = true;
		
		if(inst.getMnemonicString().startsWith("LOCAL"))
		{
			ptrAlign = 4;
			ptrNegativeGrowth = true;
		}
		else
		{
			ptrAlign = 8;
			ptrNegativeGrowth = false;
		}
	}
	
	private void setSizeFromCurrentInstruction () throws MemoryAccessException
	{
		foundSize = true;
		
		byte instByte = inst.getByte(0);
		if (instByte > 110)
			this.count = instByte - 110;
		else
			this.count = (int) inst.getScalar(0).getValue();
	}
	
	private boolean processFindPtr () throws MemoryAccessException
	{
		byte instByte = inst.getByte(0);
		if (ArrayUtils.contains(PTR_FINAL_OPS, instByte)) {
			setPointerFromCurrentInstruction ();
			return true;
		}
		return ArrayUtils.contains(PTR_IGNORE_OPS, instByte);
	}
	
	private boolean processFindSize() throws MemoryAccessException
	{
		byte instByte = inst.getByte(0);
		if (ArrayUtils.contains(SIZE_FINAL_OPS, instByte)) {
			setSizeFromCurrentInstruction ();
			return true;
		}
		return false;
	}
	
	public boolean processFind () throws MemoryAccessException
	{
		while (inst != null)
		{
			if (!foundPtr) {
				if (!processFindPtr ())
					return false;
			}
			else if (!foundSize) {
				if (!processFindSize ())
					return false;
			}
			else
				return true;
				
			inst = inst.getPrevious();
		}
		return foundPtr && foundSize;
	}

	public boolean isPtrGrowthNegative() {
		return ptrNegativeGrowth;
	}

	public int getPtrAlign() {
		return ptrAlign;
	}

	public int getCount() {
		return count;
	}
}
