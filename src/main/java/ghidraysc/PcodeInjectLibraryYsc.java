package ghidraysc;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryYsc extends PcodeInjectLibrary {

	private InjectPayloadYscReturn returnPayload = null;
	private InjectPayloadYscMemcpy memcpyPayload = null;
	
	public PcodeInjectLibraryYsc(SleighLanguage l) {
		super(l);
	}

	@Override
	public InjectPayload getPayload(int type, String name, Program program, String context) {
		
		if (type == InjectPayload.CALLMECHANISM_TYPE) {
			if (returnPayload == null) {
				returnPayload = new InjectPayloadYscReturn();
			}
			return returnPayload;
		}
		else if (type == InjectPayload.CALLOTHERFIXUP_TYPE && name.equals("memcpy")) {
			if (memcpyPayload == null) {
				memcpyPayload = new InjectPayloadYscMemcpy();
			}
			return memcpyPayload;
		}
		
		return super.getPayload(type, name, program, context);
	}

}
