// DynImportPass.cpp - LLVM pass which obfuscates dynamic imports
// By AlSch092 @ Github
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/PassBuilder.h"
#include <random>

using namespace llvm;

namespace
{
	constexpr size_t MAX_IMPORT_NAME_LEN = 48; //for the sake of our example, assume no import name is above 32 bytes. in production code, manual unfolding could be replaced with a small loop or this value increased to 64 (no windows functions are above 64 bytes)

	/*
		xorObfuscate - XOR obfuscation helper function
		returns `std::string`(`str` ^ `key`)
	*/
	std::string xorObfuscate(__in const std::string& str, __in const uint8_t* key)
	{
		std::string result = str;
		int index = 0;
		for (char& c : result)
			c ^= (key[index++]);

		return result;
	}

	/*
		ConvertToHexByte - Converts a byte to a hexadecimal string representation
		returns `std::string` of the byte in hex format
	*/
	std::string ConvertToHexByte(__in const uint8_t& byte)
	{
		std::string hexByte = "0x";
		char buffer[3];
		sprintf_s(buffer, "%02X", byte);
		hexByte += buffer;
		return hexByte;
	}

	/*
		InsertUnreachableJunkBlock - Inserts a random block of unreachable junk code into the function `F` at the specified `TargetBlock` of size `JunkByteSize`.
	*/
	void InsertUnreachableJunkBlock(__inout BasicBlock* TargetBlock, __in const int& JunkByteSize)
	{
		IRBuilder<> Builder(TargetBlock);

		FunctionType* JunkTy = FunctionType::get(Builder.getVoidTy(), false);

		std::string byteString = ".byte ";

		for (int i = 0; i < JunkByteSize; i++)
		{
			std::mt19937 rng((std::random_device())());
			uint8_t byte = rng() % 256; // Generate a random byte
			std::string hexByte = ConvertToHexByte(byte);
			byteString += hexByte;

			if (i < JunkByteSize - 1)
				byteString += ",";
		}

		errs() << "Generated junk byte string: " << byteString << "\n";

		InlineAsm* IA = InlineAsm::get(JunkTy, byteString, "", true); //use 'true' as 2nd param to avoid getting optimized out
		Builder.CreateCall(IA);
		Builder.CreateUnreachable(); // ensures nothing follows
	}

	/*
		AddOpaquePredicate - Inserts an opaque predicate into the function `F`.
	*/
	void AddOpaquePredicate(__in Function* F)
	{
		LLVMContext& Ctx = F->getContext();

		for (BasicBlock& BB : *F)
		{
			for (Instruction& I : BB)
			{
				if (auto* Ret = dyn_cast<ReturnInst>(&I))
				{
					BasicBlock* RetBlock = Ret->getParent()->splitBasicBlock(Ret, "retBlock");

					BasicBlock* OpaqueEntry = BasicBlock::Create(Ctx, "opaque_entry", F, RetBlock);
					BasicBlock* TrueBlock = BasicBlock::Create(Ctx, "trueBlock", F, RetBlock);
					BasicBlock* FalseBlock = BasicBlock::Create(Ctx, "falseBlock", F, RetBlock);

					InsertUnreachableJunkBlock(FalseBlock, 100); //insert 100 junk bytes in false block of predicate

					llvm::Type* voidTy = llvm::Type::getVoidTy(Ctx);
					llvm::FunctionType* asmFuncTy = llvm::FunctionType::get(voidTy, false);

					IRBuilder<> Builder(OpaqueEntry);

					llvm::InlineAsm* PushAsm = llvm::InlineAsm::get(asmFuncTy, ".byte 0x50", "", true); //insert push rax since we muddy up the 'al' register with the .getTrue() statement.  we use "true" as the 2nd param to avoid it being optimized out by accident

					Builder.CreateCall(PushAsm);

					Value* Cond = Builder.getTrue();

					Builder.CreateCondBr(Cond, TrueBlock, FalseBlock);

					llvm::InlineAsm* PopAsm = llvm::InlineAsm::get(asmFuncTy, ".byte 0x58", "", true); //pop rax   , the true as 2nd parameter forces it to not be optimized out

					IRBuilder<>(TrueBlock).CreateCall(PopAsm); //pop the return value back into rax so that it can be properly returned

					IRBuilder<>(TrueBlock).CreateBr(RetBlock); //in the true block which is always taken, jump to the ending ret block which was previously split

					BB.getTerminator()->eraseFromParent();
					IRBuilder<>(&BB).CreateBr(OpaqueEntry);

					return; // insert once only per func
				}
			}
		}
	}

	/*
		TransformImportNames - applies IR transformations to the `ImportNames` global variable (string obfuscation)
				returns `true` on success (one or more IR transformations)
	*/
	bool TransformImportNames(__in GlobalVariable& GV, __in LLVMContext& Ctx, __in const  uint8_t* ImportStrXorKey)
	{
		bool transformed = false;
		Constant* init = GV.getInitializer();

		if (auto* agg = dyn_cast<ConstantAggregate>(init)) //`importNames` is a pointer to char* pointers (aggregate)
		{
			for (unsigned i = 0; i < agg->getNumOperands(); ++i) //get each element (string) of the const char* array
			{
				Constant* op = agg->getOperand(i);

				if (auto* strGV = dyn_cast<GlobalVariable>(op)) //cast operand to string
				{
					if (!strGV->hasInitializer())
						continue;

					if (auto* CDA = dyn_cast<ConstantDataArray>(strGV->getInitializer()))
					{
						if (!CDA->isString())
							continue;

						std::string origStr = CDA->getAsCString().str(); //get the string value

						std::string enc = xorObfuscate(origStr, ImportStrXorKey); //get a new string, where each char element is XOR'd with our key

						auto* NewCDA = ConstantDataArray::getString(Ctx, enc, true); //create the new XOR'd string

						strGV->setInitializer(NewCDA); //set the new string value to our XOR'd string
						strGV->setConstant(false);

						errs() << "XOR'd string: " << origStr << " => " << enc << "\n";
						transformed = true;
					}
				}
			}
		}

		return transformed ? true : false; //return true if we transformed any strings
	}

	/*
	TransformResolveImportsFunction - applies IR transformations to the `ResolveImports` function
			returns `true` on success (one or more IR transformations)
	*/
	bool TransformResolveImportsFunction(__in Function& F, __in LLVMContext& Ctx, __in const uint8_t* ImportStrXorKey, __in const uint64_t& ImportAddressXorKey)
	{
		bool transformed = false;

		for (BasicBlock& BB : F)
		{
			for (Instruction& I : BB)
			{
				if (auto* CI = dyn_cast<CallInst>(&I)) //this 'if' block adds string decryption before calls to GetProcAddress: we create a decryption routine block which is jumped to before the call to GetProcAddress
				{
					Function* Callee = CI->getCalledFunction();
					if (!Callee || !Callee->getName().contains("GetProcAddress"))
						continue;

					if (CI->arg_size() < 2) //make sure enough arguments are passed to the called `GetProcAddress` function
						continue;

					//there are of course multiple ways to do this, but if we just modify the argument passed to GetProcAddress, our `cout` will print encrypted strings, so we need a 'catchall' approach
					//a correct way which handles printing the decrypted "NtQuery..." and using it in GetProcAddress is to modify the %4 variable, as its used to assign new values which are passed into multiple functions
					Type* i8Ty = Type::getInt8Ty(Ctx);
					StoreInst* _store = nullptr;

					Value* originalStr = nullptr;
					Value* originalPtr = CI->getArgOperand(1);
					LoadInst* loadInst = dyn_cast<LoadInst>(originalPtr);

					if (!loadInst)
					{
						errs() << "[ERROR] Argument to GetProcAddress was not a LoadInst as expected!\n";
						std::terminate();
					}

					Value* targetLocal = loadInst->getPointerOperand();

					for (User* U : targetLocal->users())
					{
						if (StoreInst* store = dyn_cast<StoreInst>(U))
						{
							if (store->getPointerOperand() == targetLocal)
							{
								originalStr = store->getValueOperand();
								_store = store; //fetch the store instruction before the call to GetProcAddress, we will place our decryption logic after that inst
							}
						}
					}

					if (!_store || !originalStr)
					{
						errs() << "[ERROR] Failed to find store instruction for GetProcAddress argument!\n";
						std::terminate();
					}

					IRBuilder<> B(_store->getNextNode()); //insert our own logic right after the store instructions

					AllocaInst* xorBuf = B.CreateAlloca(ArrayType::get(i8Ty, MAX_IMPORT_NAME_LEN), nullptr, "xorbuf"); //create buffer on stack to store decrypted string rather than decrypting in data sections of program

					// manually unroll the loop -> creates assembler bloat (MAX_IMPORT_NAME_LEN sets of instructions sequentially), which has its pros and cons in the context of reversing 
					for (int i = 0; i < MAX_IMPORT_NAME_LEN - 1; ++i)
					{
						Value* idx = B.getInt32(i);
						Value* srcPtr = B.CreateInBoundsGEP(i8Ty, originalStr, idx);
						Value* ch = B.CreateLoad(i8Ty, srcPtr);
						Value* isZero = B.CreateICmpEQ(ch, B.getInt8(0));

						Value* orVal = B.CreateOr(ch, ConstantInt::get(i8Ty, ImportStrXorKey[i]));
						Value* andVal = B.CreateAnd(ch, ConstantInt::get(i8Ty, ImportStrXorKey[i]));
						Value* result = B.CreateSub(orVal, andVal); // these 3 instructions are equivalent to a XOR, and make it less obvious

						Value* finalCh = B.CreateSelect(isZero, ch, result);

						Value* dstPtr = B.CreateInBoundsGEP(xorBuf->getAllocatedType(), xorBuf, { B.getInt32(0), idx });
						B.CreateStore(finalCh, dstPtr);
					}

					Value* nullPtr = B.CreateInBoundsGEP(xorBuf->getAllocatedType(), xorBuf, { B.getInt32(0), B.getInt32(MAX_IMPORT_NAME_LEN - 1) }); //null-terminate the decrypted string at the final possible index
					B.CreateStore(B.getInt8(0), nullPtr);

					Value* decryptedPtr = B.CreateBitCast(xorBuf, i8Ty->getPointerTo()); //bitcast xorBuf to i8* and store it in the local variable (%4 in this case)
					B.CreateStore(decryptedPtr, targetLocal);

					errs() << "Injected decryption logic for importName\n";
					transformed = true;
				}
				else if (auto* SI = dyn_cast<StoreInst>(&I)) //obfuscate uint64_t values stored in g_importTable, and deobfuscate it on use
				{
					Value* ptr = SI->getPointerOperand(); //if instruction is a store, get the pointer operand

					if (auto* GEP = dyn_cast<GetElementPtrInst>(ptr))
					{
						if (auto* GV = dyn_cast<GlobalVariable>(GEP->getPointerOperand())) //is pointer operand a global variable?
						{
							if (!GV->getName().contains("g_ImportAddresses") && !GV->getMetadata("import_table")) //make sure global var has metadata or suitable name
								continue;

							errs() << "Found a store to g_ImportAddresses!\n";

							Type* i64Ty = Type::getInt64Ty(Ctx);
							Type* i32Ty = Type::getInt32Ty(Ctx);

							Value* val = SI->getValueOperand();
							IRBuilder<> B(SI);
							Value* casted = B.CreatePtrToInt(val, Type::getInt64Ty(Ctx));

							uint32_t lowKey = static_cast<uint32_t>(ImportAddressXorKey & 0xFFFFFFFF); //constants for upper/lower parts of your XOR key
							uint32_t highKey = static_cast<uint32_t>((ImportAddressXorKey >> 32) & 0xFFFFFFFF);

							Value* low32 = B.CreateTrunc(casted, i32Ty); // casted is i64
							Value* high32 = B.CreateTrunc(B.CreateLShr(casted, 32), i32Ty); //split original value into low and high 32 bits

							Value* xoredLow = B.CreateXor(low32, ConstantInt::get(i32Ty, lowKey)); //XOR each half
							Value* xoredHigh = B.CreateXor(high32, ConstantInt::get(i32Ty, highKey));

							Value* xoredHigh64 = B.CreateZExt(xoredHigh, i64Ty); //recombine into 64-bit
							xoredHigh64 = B.CreateShl(xoredHigh64, 32);
							Value* xoredLow64 = B.CreateZExt(xoredLow, i64Ty);
							Value* obfVal = B.CreateOr(xoredLow64, xoredHigh64);
							Value* obfPtr = B.CreateIntToPtr(obfVal, val->getType());

							SI->setOperand(0, obfPtr);
							transformed = true;
							errs() << "Transformed the store instruction to import table to be XOR'd with the key: " << ImportAddressXorKey << ", which is stored in g_importTable!\n";

						}
					}
				}
			}
		}

		return transformed ? true : false; //return true if we transformed any strings
	}


	/*
		TransformGetImportTableEntryFunction - applies IR transformations to the `GetImportTableEntry` function
		returns `true` on success (one or more IR transformations)
	*/
	bool TransformGetImportTableEntryFunction(__in Function& F, __in LLVMContext& Ctx, __in GlobalVariable* gImportTable)
	{
		if (!gImportTable)
		{
			errs() << "Error: g_importTable not found\n";
			return false;
		}

		std::mt19937 rng((std::random_device())());
		uint8_t randomIndex = 0;
		uint16_t randomIndex16 = 0;

		while (randomIndex == 0) //make sure we don't generate 0 as the random number
			randomIndex = rng();

		while (randomIndex16 == 0)
			randomIndex16 = rng();

		F.deleteBody(); //delete body of our function and replace with our own

		BasicBlock* entry = BasicBlock::Create(Ctx, "entry", &F);
		IRBuilder<> B(entry);
		Argument* arg = F.getArg(0); // get the index arg

		Value* subIndex = B.CreateUDiv(arg, B.getInt32(randomIndex16)); // divide the `index` parameter by random amount 
		Value* subOneIndex = B.CreateSub(subIndex, B.getInt32(randomIndex)); // subtract 1 from the `index` parameter to get the real index

		Value* importPtr = B.CreateInBoundsGEP(gImportTable->getValueType(), gImportTable, { B.getInt32(0), subOneIndex });
		Value* encrypted = B.CreateLoad(Type::getInt64Ty(Ctx), importPtr);

		Value* result = B.CreateIntToPtr(encrypted, F.getReturnType());

		B.CreateRet(result);  //manually re-create the `return g_importTable[index]` instruction

		//modify `index` parameter in calls to `GetImportTableEntry` to use the indirect index (using multiply + add with random numbers)
		for (User* U : F.users())
		{
			if (CallInst* CI = dyn_cast<CallInst>(U))
			{
				Value* addIndex = B.CreateAdd(CI->getArgOperand(0), B.getInt32(randomIndex));
				Value* transformedIndex = B.CreateMul(addIndex, B.getInt32(randomIndex16));

				CI->setOperand(0, transformedIndex);
				errs() << "Modified index to " << *transformedIndex << " in call to GetImportTableEntry\n";
			}
		}

		AddOpaquePredicate(&F); //add opaque predicate to the function to make the return value less obvious when static reversing
		return true;
	}

	/*
		TransformCallImportsFunction - applies IR transformations to the `CallImports` function
		returns `true` on success (one or more IR transformations)
	*/
	bool TransformCallImportsFunction(__in Function& F, __in LLVMContext& Ctx, __in const uint64_t& ImportAddressXorKey)
	{
		bool transformed = false;

		for (BasicBlock& BB : F)
		{
			for (Instruction& I : BB)
			{
				if (auto* CI = dyn_cast<CallInst>(&I)) //find calls to GetImportTableEntry
				{
					Function* Callee = CI->getCalledFunction();
					if (!Callee || !Callee->getName().contains("GetImportAddress"))
						continue;

					for (User* U : CI->users())
					{
						if (auto* store = dyn_cast<StoreInst>(U)) //get store instruction that references the returned value from `GetImportAddress`
						{
							if (store->getValueOperand() != CI)
								continue;

							if (store->getFunction() != CI->getFunction()) //make sure store inst is in the same function as the call inst we gathered before
								continue;

							IRBuilder<> B(store);

							Type* i64Ty = Type::getInt64Ty(Ctx);
							Type* i32Ty = Type::getInt32Ty(Ctx);

							Value* casted = B.CreatePtrToInt(CI, i64Ty); //CI is the pointer returned from GetImportTableEntry

							uint32_t lowKey = static_cast<uint32_t>(ImportAddressXorKey & 0xFFFFFFFF); //split the key into upper/lower 32-bit parts
							uint32_t highKey = static_cast<uint32_t>((ImportAddressXorKey >> 32) & 0xFFFFFFFF);

							Value* low32 = B.CreateTrunc(casted, i32Ty);
							Value* high32 = B.CreateTrunc(B.CreateLShr(casted, 32), i32Ty);

							Value* xoredLow = B.CreateXor(low32, ConstantInt::get(i32Ty, lowKey)); //XOR each half
							Value* xoredHigh = B.CreateXor(high32, ConstantInt::get(i32Ty, highKey));

							Value* xoredHigh64 = B.CreateZExt(xoredHigh, i64Ty); //recombine into a 64-bit value
							xoredHigh64 = B.CreateShl(xoredHigh64, 32);
							Value* xoredLow64 = B.CreateZExt(xoredLow, i64Ty);

							Value* obfVal = B.CreateOr(xoredLow64, xoredHigh64);
							Value* deobfPtr = B.CreateIntToPtr(obfVal, CI->getType()); //convert back to pointer

							store->setOperand(0, deobfPtr); // replace the store with obfuscated pointer

							errs() << "Rewrote store using result of GetImportAddress\n";
							transformed = true;
						}
					}
				}
			}
		}

		return transformed ? true : false; //return true if we transformed the function
	}

	struct ObfuscateDynamicImports : PassInfoMixin<ObfuscateDynamicImports>
	{
		PreservedAnalyses run(Module& M, ModuleAnalysisManager&)
		{
			bool madeAnyModification = false;
			LLVMContext& Ctx = M.getContext();

			std::mt19937 rng((std::random_device())());

			uint8_t* ImportStrXorKey = new uint8_t[MAX_IMPORT_NAME_LEN]{ 0 }; //rather than just using one xor key, each element of the string gets a randomly generated one
			const uint64_t ImportAddressXorKey = (static_cast<uint64_t>(rng()) << 32) | rng(); //get 64 bits of random, shift bytes over since the rng() routine usually returns 32 bits

			for (int i = 0; i < MAX_IMPORT_NAME_LEN; i++)
			{
				uint8_t b = 0;
				do
				{
					b = rng() % 256;
				} while (b == 0 || std::isalnum(b));
				ImportStrXorKey[i] = b;
			}

			GlobalVariable* gImportTable = nullptr; //save this GV for later

			//1. Obfuscate the elements of `importNames`, which are used to look up system call addresses. Instead of looking for any global string starting with "NtQuery...", we focus on the `importNames` variable
			for (GlobalVariable& GV : M.globals())
			{
				if (GV.getName() == "g_ImportNames" || GV.getName().contains("ImportNames"))
				{
					if (!TransformImportNames(GV, Ctx, ImportStrXorKey)) //transform the import names to be XOR'd with our key
					{
						errs() << "Failed to transform import names!\n";
						goto cleanup;
					}
					else
					{
						madeAnyModification = true; //if we transformed any strings, set this to true
						errs() << "Transformed import names!\n";
					}
				}
				else if (GV.getName() == "g_ImportAddresses" || GV.getName().contains("g_importTable") || GV.getName().contains("g_ImportAddresses"))
				{
					gImportTable = &GV; //save this GV for later
					errs() << "Found g_importTable\n";
				}
			}

			//all transformations besides modifying importNames (GV loop) can be done in a single function loop to save execution time
			for (Function& F : M)
			{
				if (F.hasFnAttribute("resolves-imports") || F.getName() == "GetImportAddresses" || F.getName().contains("GetImportAddresses")) //we can apply this transformation to tagged functions or by function name
				{
					if (!TransformResolveImportsFunction(F, Ctx, ImportStrXorKey, ImportAddressXorKey)) //transform the ResolveImports function
					{
						errs() << "Failed to transform GetImportAddresses function!\n";
						goto cleanup;
					}
					else
					{
						madeAnyModification = true; //if we transformed any code, set this to true
						errs() << "Transformed GetImportAddresses function!\n";
					}
				}
				else if (F.getName() == "GetImportAddress" || F.getName().contains("GetImportAddress") || F.hasFnAttribute("resolves-imports")) //custom logic to not make the mapping of the `index` argument direct
				{
					if (!TransformGetImportTableEntryFunction(F, Ctx, gImportTable)) //transform the GetImportTableEntry function to use our custom logic
					{
						errs() << "Failed to transform GetImportAddress function!\n";
						goto cleanup;
					}
					else
					{
						madeAnyModification = true; //if we transformed any code, set this to true
						errs() << "Transformed GetImportAddress function!\n";
					}
				}
				else if (F.getName() == "CallImportFunction" || F.getName().contains("CallImportFunction") || F.hasFnAttribute("calls-imports")) //fetch calls to `GetImportTableEntry`
				{
					if (!TransformCallImportsFunction(F, Ctx, ImportAddressXorKey)) //transform the CallImports function to use our custom logic
					{
						errs() << "Failed to transform CallImportFunction routine!\n";
						goto cleanup;
					}
					else
					{
						madeAnyModification = true; //if we transformed any code, set this to true
						errs() << "Transformed CallImportFunction routine!\n";
					}
				}
			}

			if (madeAnyModification)
				errs() << "Pass ran successfully and made atleast one code transformation!\n";
		cleanup:
			if (ImportStrXorKey)
				delete[] ImportStrXorKey;

			return madeAnyModification ? PreservedAnalyses::none() : PreservedAnalyses::all();
		}
	};

} // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo()
{
	return
	{
		LLVM_PLUGIN_API_VERSION, "ObfuscateDynamicImports", LLVM_VERSION_STRING,
		[](PassBuilder& PB) {
			PB.registerPipelineParsingCallback(
				[](StringRef Name, ModulePassManager& MPM, ArrayRef<PassBuilder::PipelineElement>)
				{
					if (Name == "obf-dynimports")
					{
						MPM.addPass(ObfuscateDynamicImports());
						return true;
					}

					return false;
				});
		} };
}
