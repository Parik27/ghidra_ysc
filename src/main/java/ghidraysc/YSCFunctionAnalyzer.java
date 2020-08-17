/**
 * 
 */
package ghidraysc;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import java.util.regex.MatchResult;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.task.TaskMonitor;

/**
 * @author Parik
 *
 */
public class YSCFunctionAnalyzer extends AbstractAnalyzer {

	private HashMap<Long, String> natives;
	private HashMap<Long, Long> nativesTranslation;
	
	private static final String OPTION_NAME_NATIVE_JSON = "Natives JSON";
	private static final String OPTION_NAME_TRANSLATION = "Natives Translation Table";
	
	public YSCFunctionAnalyzer() {

		super("YSC Function Analyzer", "Analyzes YSC functions and corrects their signatures", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS);
		
		natives = new HashMap<Long, String>();
		nativesTranslation = new HashMap<Long, Long>();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("YSC");
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_NATIVE_JSON, OptionType.FILE_TYPE, null, null, "natives.json generated from NativeDB");
		options.registerOption(OPTION_NAME_TRANSLATION, OptionType.FILE_TYPE, null, null,
				"Required for versions greater than b350, in format <latest hash -> natives.json hash>");
	}
	
	private void ReadNativesList (JSONObject obj, String namespace)
	{
		obj.keys().forEachRemaining(key -> {
			long hash = Long.parseUnsignedLong(key.substring(2), 16);
			
			String name = obj.getJSONObject(key).getString("name");
			if (name.length() == 0) // Natives that aren't named yet
				name = key;
			
			natives.put(hash, namespace + "::" + name);
		});
	}
	
	private void ReadNativesJSONFile (File file) {
		if (file == null)
			return;
		
		natives.clear();
		try {
			JSONObject obj = new JSONObject(new JSONTokener(new FileReader(file)));
			obj.keys().forEachRemaining(key -> {
				String namespace = key;
				ReadNativesList (obj.getJSONObject(key), namespace);				
			});
			
		} catch (JSONException | FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	private void ReadTranslationTable (File file)
	{
		if (file == null)
			return;
		
		nativesTranslation.clear();
		
		try {
			Scanner sc = new Scanner (file);
			sc.findAll("(.+) -> (.+)").forEach(match -> {
				long originalHash = Long.parseUnsignedLong(match.group(1),16);
				long newHash      = Long.parseUnsignedLong(match.group(2),16);
				
				nativesTranslation.put(newHash, originalHash);
			});
			
			sc.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
	}
	
	@Override
	public void optionsChanged(Options options, Program prog) {
		ReadNativesJSONFile (options.getFile(OPTION_NAME_NATIVE_JSON, null));
		ReadTranslationTable (options.getFile(OPTION_NAME_TRANSLATION, null));
	}

	/* This function will see an enter instruction and set the proper return value based on it */
	private void handleEnterInstruction (Program program, Address addr) throws DuplicateNameException, InvalidInputException, MemoryAccessException, AddressOutOfBoundsException
	{
		
		Function function = program.getListing().getFunctionContaining(addr);
		byte numArgs = program.getMemory().getByte (addr.add(1));
		
		if (function != null) {
			ArrayList<ParameterImpl> params = new ArrayList<ParameterImpl>();
			for (int i = 0; i < numArgs; i++)
				params.add(new ParameterImpl (null, Undefined4DataType.dataType, program));
			
			function.replaceParameters(params,
					Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
					true,
					SourceType.ANALYSIS);
		}
	}
	
	private void handleNativeInstruction (Program program, Address addr) throws MemoryAccessException, AddressOutOfBoundsException, DuplicateNameException, InvalidInputException
	{
		Instruction inst = program.getListing().getInstructionAt(addr);
		long NO = inst.getValue(program.getRegister("NO"), false).longValue();
		
		byte opA = program.getMemory().getByte(addr.add(1));
		long tableOffset = program.getMemory().getShort(addr.add(2), true);
		
		byte numArgs = (byte) ((opA & 0b11111100) >> 2);
		byte numRets = (byte) (opA & 0b11);
		
		Function func = program.getListing().getFunctionAt (program.getAddressFactory().getDefaultAddressSpace().
				getAddress (NO).add(tableOffset * 8));
		
		if (func != null)
		{
			ArrayList<ParameterImpl> params = new ArrayList<ParameterImpl>();
			for (int i = 0; i < numArgs; i++)
				params.add(new ParameterImpl (null, Undefined4DataType.dataType, program));
			
			func.replaceParameters(params,
					Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
					true,
					SourceType.ANALYSIS);
			
			func.setReturnType(
					(numRets == 0) ? VoidDataType.dataType : Undefined4DataType.dataType,
					SourceType.ANALYSIS);
			
			String name = func.getName(true);
			if (name.startsWith("n_"))
			{
				try
				{
					long hash = Long.parseUnsignedLong(name.substring(2), 16);
					long translatedHash = nativesTranslation.getOrDefault(hash, 0L);
					
					String newName = natives.getOrDefault(translatedHash, name);
					func.setName(newName, SourceType.ANALYSIS);
				}
				catch (NumberFormatException e) {}
			}
		}
	}
	
	private void handleLeaveInstruction (Program program, Address addr) throws MemoryAccessException, AddressOutOfBoundsException, InvalidInputException
	{
		
		Function function = program.getListing().getFunctionContaining(addr);
		byte retVals = program.getMemory().getByte (addr.add(2));
		
		if (function != null) {
			function.setReturnType(
					(retVals == 0) ? VoidDataType.dataType : Undefined4DataType.dataType,
					SourceType.ANALYSIS);
		}
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		long progress = 0;
		monitor.setMaximum(program.getListing().getNumInstructions());
		for (Instruction inst : program.getListing().getInstructions(true)) {
			try {
				if (inst.getMnemonicString().equals("ENTER"))
					handleEnterInstruction (program, inst.getAddress());
				else if (inst.getMnemonicString().equals("LEAVE"))
					handleLeaveInstruction (program, inst.getAddress());
				else if (inst.getMnemonicString().equals("NATIVE"))
					handleNativeInstruction (program, inst.getAddress());
				
				monitor.setProgress(progress++);
				
			} catch (MemoryAccessException e) {
				log.appendException(e);
				return false;
			} catch (AddressOutOfBoundsException e) {
				log.appendException(e);
				return false;
			} catch (InvalidInputException e) {
				log.appendException(e);
				return false;
			} catch (DuplicateNameException e) {
				log.appendException(e);
			}
		}
		return false;
	}

}
