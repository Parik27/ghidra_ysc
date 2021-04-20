package ghidraysc;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class InjectPayloadYscReturn implements InjectPayload {

	static final long TMP_VAR0 = 0;
	
	private InjectParameter[] noParams;
	private Language language;
	
	private AddressSpace constSpace;
	private AddressSpace defSpace;
	private Varnode defSpaceId;
	private AddressSpace uniqueSpace;

	private Varnode spVarnode;

	private Function func;
	
	public InjectPayloadYscReturn() {
		noParams = new InjectParameter[0];
	}

	@Override
	public String getName() {
		return "yscreturns";
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return "yscreturns";
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
	}

	public Varnode getRegister (String name)
	{
		Register reg = language.getRegister(name);
		return new Varnode(reg.getAddress(), reg.getBitLength() / 8);
	}
	
	private Varnode getConstant(long val, int size) {            
        return new Varnode(constSpace.getAddress(val), size);
	}                                                            
	
	private Varnode getTemp (long addr, int size)
	{
		return new Varnode(uniqueSpace.getAddress(addr), size);
	}
	
	public PcodeOp[] getSimpleFunctionOp(Program program, InjectContext con) {
		ArrayList<PcodeOp> opList = new ArrayList<PcodeOp>();
		int seqIdx = 0;

		// SP = SP - 4
		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(8, spVarnode.getSize());
		PcodeOp op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.INT_SUB, in, spVarnode);
		opList.add(op);

		in = new Varnode[3];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		in[2] = func.getReturn().getFirstStorageVarnode();
		op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.STORE, in);
		opList.add(op);

		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);

		return res;
	}
	
	public PcodeOp[] getComplexFunctionOp(Program program, InjectContext con) {
		ArrayList<PcodeOp> opList = new ArrayList<PcodeOp>();
		int seqIdx = 0;

		int size = ((Pointer)this.func.getReturnType()).getDataType().getLength();
		if (size % 4 != 0)
			return new PcodeOp[0];
		
		size /= 4;
		
		Varnode Rptr = func.getReturn().getFirstStorageVarnode();
		Varnode OutTmp = this.getTemp(TMP_VAR0, 4);
		
		for (int i = 0; i < size; i++) {
			Varnode[] in = new Varnode[2];
			in[0] = spVarnode;
			in[1] = getConstant(4, spVarnode.getSize());
			PcodeOp op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.INT_SUB, in, spVarnode);
			opList.add(op);
			
			in = new Varnode[2];
			in[0] = defSpaceId;
			in[1] = Rptr;
			op = new PcodeOp (con.baseAddr, seqIdx++, PcodeOp.LOAD, in, OutTmp);
			opList.add(op);
			
			in = new Varnode[3];

			in[0] = defSpaceId;
			in[1] = spVarnode;
			in[2] = OutTmp;
			op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.STORE, in);
			opList.add(op);
			
			in = new Varnode[2];
			in[0] = Rptr;
			in[1] = getConstant(4, Rptr.getSize());
			op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.INT_ADD, in, Rptr);
			opList.add(op);
		}
		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);

		return res;
	}
	
	private void setFuncFromInstruction (Program program, Instruction inst)
	{
		switch (inst.getMnemonicString())
		{
		case "CALL":
			this.func = program.getListing().getFunctionAt(inst.getAddress(0));
			break;
		case "NATIVE":
			MemoryBlock natives = program.getMemory().getBlock(".natives");
			long imm16 = inst.getScalar(1).getValue();
			this.func = program.getListing().getFunctionAt(
					natives.getStart().add(((imm16>>8&0xFFFF) | (imm16<<8&0xFFFF)) * 8));
			break;
		}
	}
	
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		
		this.language = con.language;
		this.constSpace = this.language.getAddressFactory().getConstantSpace();
		this.defSpace = this.language.getDefaultDataSpace();
		this.defSpaceId = getConstant(defSpace.getSpaceID(), 4);
		this.uniqueSpace = this.language.getAddressFactory().getUniqueSpace();
		this.spVarnode = getRegister("SP");
		
		if (con.refAddr != null)
			this.func = program.getFunctionManager().getFunctionContaining(con.refAddr);
		else
			setFuncFromInstruction (program, program.getListing().getInstructionAt(con.baseAddr));
		
		if (func == null || func.getReturn().getFirstStorageVarnode() == null)
			return new PcodeOp[0];
				
		if (func.getReturn().getRegister().getName().equals("RPTR"))
			return getComplexFunctionOp (program, con);
		else if (func.getReturn().getRegister().getName().equals("RV"))
			return getSimpleFunctionOp (program, con);	
		
		return new PcodeOp[0];
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

}
