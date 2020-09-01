package ghidraysc;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GhidraYSCAnalyzer extends AbstractAnalyzer {

	public GhidraYSCAnalyzer() {
		super("YSC Subroutine Analyzer", "Discovers new functions in the ysc file", AnalyzerType.BYTE_ANALYZER);
		setPriority (AnalysisPriority.BLOCK_ANALYSIS.before());
	}

	private void createFunction (Address entryPoint, Program program, TaskMonitor monitor, String name)
	{
		CreateFunctionCmd cmd = new CreateFunctionCmd(name, entryPoint, null,
				name != null ? SourceType.USER_DEFINED : SourceType.DEFAULT);
		cmd.applyTo(program, monitor);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		MemoryBlock block = program.getMemory().getBlock("code");
		
		PseudoDisassembler disass = new PseudoDisassembler(program);
		
		Address addr = block.getStart();
		while (addr.getOffset() < block.getEnd().getOffset())
		{
			try {
				System.out.println(addr);
				PseudoInstruction inst = disass.disassemble(addr);
				if (inst.getMnemonicString().equals("ENTER"))
					createFunction (addr, program, monitor, null);
				
				long disp = 0;
				if (!inst.getMnemonicString().equals("SWITCH"))
					disp = inst.getLength();
				else
					disp = (program.getMemory().getByte(addr.add(1)) & 0xff) * 6 + 2;
				
				addr = addr.add(disp);
				
			} catch (InsufficientBytesException | UnknownInstructionException | UnknownContextException | AddressOutOfBoundsException | MemoryAccessException e) {
				log.appendException(e);
			}
		}
		return false;
	}

}
