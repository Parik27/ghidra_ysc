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

import java.util.ArrayList;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class YSCSwitchAnalyzer extends AbstractAnalyzer {

	public YSCSwitchAnalyzer() {

		super("YSC Switch Analyzer", "Analyzes YSC switch statements", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.before());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return false;
		//return program.getLanguage().getProcessor().toString().equals("YSC");
	}

	@Override
	public void registerOptions(Options options, Program program) {
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		
		for (Instruction inst : program.getListing().getInstructions(true)) {
			try {
				if (!inst.getMnemonicString().equals("SWITCH"))
					continue;
				
				Address addr = inst.getAddress();
				
				byte numBranches = program.getMemory().getByte (addr.add(1));
				ArrayList<Address> dests = new ArrayList<Address>(); 
				
				if (numBranches == 0)
					continue;
				
				for (int i = 0; i < numBranches; i++)
				{
					short dest = program.getMemory().getShort(addr.add(6+6*i));
					Address destAddr = addr.add(dest + 6 * (i+1) + 2);
					
					inst.addOperandReference(0, destAddr, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
					
					DisassembleCommand dCommand = new DisassembleCommand(destAddr, null, true);
					dCommand.applyTo (program, monitor);
					
					dests.add(destAddr);
				}
				
				Function function = program.getListing().getFunctionContaining(addr);
				JumpTable jumpTable = new JumpTable (addr, dests, true);
				if (function != null) {
					jumpTable.writeOverride(function);
					CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
				}
				
				
			} catch (MemoryAccessException e) {
				log.appendException(e);
				return false;
			} catch (AddressOutOfBoundsException e) {
				log.appendException(e);
				return false;
			} catch (InvalidInputException e) {
				log.appendException(e);
				return false;
			}
		}

		return true;
	}
}
