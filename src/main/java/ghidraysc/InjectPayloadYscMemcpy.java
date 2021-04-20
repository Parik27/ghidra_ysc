package ghidraysc;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class InjectPayloadYscMemcpy implements InjectPayload {

	static final long TMP_VAR0 = 0;

	private Language language;

	private AddressSpace constSpace;
	private AddressSpace defSpace;
	private Varnode defSpaceId;
	private AddressSpace uniqueSpace;

	private Varnode spVarnode;

	private Function func;

	private LoadStoreInstructionHelper helper;

	public InjectPayloadYscMemcpy() {
	}

	@Override
	public String getName() {
		return "yscmemcpy";
	}

	@Override
	public int getType() {
		return CALLOTHERFIXUP_TYPE;
	}

	@Override
	public String getSource() {
		return "yscmemcpy";
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return null;
	}

	@Override
	public InjectParameter[] getOutput() {
		return null;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
	}

	public Varnode getRegister(String name) {
		Register reg = language.getRegister(name);
		return new Varnode(reg.getAddress(), reg.getBitLength() / 8);
	}

	private Varnode getConstant(long val, int size) {
		return new Varnode(constSpace.getAddress(val), size);
	}

	private Varnode getTemp(long addr, int size) {
		return new Varnode(uniqueSpace.getAddress(addr), size);
	}

	public PcodeOp[] getStorePcode(InjectContext con) {
		ArrayList<PcodeOp> opList = new ArrayList<PcodeOp>();
		Varnode OutTmp = this.getTemp(TMP_VAR0, 4);
		int seqIdx = 0;

		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant((this.helper.getCount()) * 4, spVarnode.getSize());
		PcodeOp op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
		
		for (int i = 0; i < this.helper.getCount(); i++) {
			// SP = SP - 4
			in = new Varnode[2];
			in[0] = spVarnode;
			in[1] = getConstant(4, spVarnode.getSize());
			op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.INT_SUB, in, spVarnode);
			opList.add(op);

			// tmp:4 = *:4 SP
			in = new Varnode[2];
			in[0] = defSpaceId;
			in[1] = spVarnode;
			op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.LOAD, in, OutTmp);
			opList.add(op);

			// *:4 out = tmp;
			in = new Varnode[3];
			in[0] = defSpaceId;
			in[1] = con.inputlist.get(0);
			in[2] = OutTmp;
			op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.STORE, in);
			opList.add(op);

			// out += 8; (or -= 4, depends on the type)
			in = new Varnode[2];
			in[0] = con.inputlist.get(0);
			in[1] = getConstant(this.helper.getPtrAlign(), con.inputlist.get(0).getSize());
			op = new PcodeOp(con.baseAddr, seqIdx++,
					this.helper.isPtrGrowthNegative() ? PcodeOp.INT_SUB : PcodeOp.INT_ADD, in, con.inputlist.get(0));
			opList.add(op);

		}
		
		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);

		return res;
	}

	public PcodeOp[] getGenericPcode(InjectContext con) {
		ArrayList<PcodeOp> opList = new ArrayList<PcodeOp>();

		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);

		return res;
	}

	public PcodeOp[] getLoadPcode(InjectContext con) {
		ArrayList<PcodeOp> opList = new ArrayList<PcodeOp>();
		Varnode OutTmp = this.getTemp(TMP_VAR0, 4);
		int seqIdx = 0;

		for (int i = 0; i < this.helper.getCount(); i++) {
			Varnode[] in = new Varnode[2];

			// SP = SP - 4
			in[0] = spVarnode;
			in[1] = getConstant(4, spVarnode.getSize());
			PcodeOp op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.INT_SUB, in, spVarnode);
			opList.add(op);

			// tmp:4 = *:4 in
			in = new Varnode[2];
			in[0] = defSpaceId;
			in[1] = con.inputlist.get(1);
			op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.LOAD, in, OutTmp);
			opList.add(op);

			// *:4 SP = tmp;
			in = new Varnode[3];
			in[0] = defSpaceId;
			in[1] = spVarnode;
			in[2] = OutTmp;
			op = new PcodeOp(con.baseAddr, seqIdx++, PcodeOp.STORE, in);
			opList.add(op);

			// in += 8; (or -= 4, depends on the type)
			in = new Varnode[2];
			in[0] = con.inputlist.get(1);
			in[1] = getConstant(this.helper.getPtrAlign(), con.inputlist.get(1).getSize());
			op = new PcodeOp(con.baseAddr, seqIdx++,
					this.helper.isPtrGrowthNegative() ? PcodeOp.INT_SUB : PcodeOp.INT_ADD, in, con.inputlist.get(1));
			opList.add(op);

		}

		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);

		return res;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {

		this.language = con.language;
		this.constSpace = this.language.getAddressFactory().getConstantSpace();
		this.defSpace = this.language.getDefaultDataSpace();
		this.defSpaceId = getConstant(defSpace.getSpaceID(), 4);
		this.uniqueSpace = this.language.getAddressFactory().getUniqueSpace();
		this.spVarnode = getRegister("SP");

		this.helper = new LoadStoreInstructionHelper(program, con);
		try {
			if (helper.processFind()) {
				switch (program.getListing().getInstructionAt(con.baseAddr).getMnemonicString()) {
				case "LOAD_N":
					return getLoadPcode(con);
				case "STORE_N":
					return getStorePcode(con);
				}
			}
		} catch (MemoryAccessException e) {
			e.printStackTrace();
		}

		return getGenericPcode(con);
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

}
