/*
  Ref:
  * https://llvm.org/doxygen/
  * https://llvm.org/docs/GettingStarted.html
  * https://llvm.org/docs/WritingAnLLVMPass.html
  * https://llvm.org/docs/ProgrammersManual.html
 */
#include "lab-pass.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"

using namespace llvm;

char LabPass::ID = 0;

bool LabPass::doInitialization(Module &M)
{
  return true;
}

static FunctionCallee printfPrototype(Module &M)
{
  LLVMContext &ctx = M.getContext();

  FunctionType *printfType = FunctionType::get(
      Type::getInt32Ty(ctx),
      {Type::getInt8PtrTy(ctx)},
      true);

  FunctionCallee printfCallee = M.getOrInsertFunction("printf", printfType);

  return printfCallee;
}

static Constant *getI8StrVal(Module &M, const char *str, Twine const &name)
{
  LLVMContext &ctx = M.getContext();

  Constant *strConstant = ConstantDataArray::getString(ctx, str);

  GlobalVariable *gvStr = new GlobalVariable(M, strConstant->getType(), true,
                                             GlobalValue::InternalLinkage, strConstant, name);

  Constant *zero = Constant::getNullValue(IntegerType::getInt32Ty(ctx));
  Constant *indices[] = {zero, zero};
  Constant *strVal = ConstantExpr::getGetElementPtr(Type::getInt8PtrTy(ctx),
                                                    gvStr, indices, true);

  return strVal;
}

bool LabPass::runOnModule(Module &M)
{
  errs() << "runOnModule\n";

  LLVMContext &ctx = M.getContext();

  FunctionCallee printfCallee = printfPrototype(M);

  // init depth
  Constant *depth = Constant::getIntegerValue(Type::getInt32Ty(ctx), APInt(32, 0));
  GlobalVariable *gvDepth = new GlobalVariable(M, depth->getType(), false,
                                               GlobalValue::InternalLinkage, depth, "depth");

  Constant *one = Constant::getIntegerValue(Type::getInt32Ty(ctx), APInt(32, 1));
  Constant *colon = getI8StrVal(M, ": ", "colon");
  Constant *newLine = getI8StrVal(M, "\n", "newLine");
  Constant *space = getI8StrVal(M, " ", "space");
  Constant *printAddressFormat = getI8StrVal(M, "%p", "printAddressFormat");
  Constant *printNumberFormat = getI8StrVal(M, "%d", "printNumberFormat");
  Constant *printDepthSpaceFormat = getI8StrVal(M, "%*s", "printDepthSpaceFormat");

  for (auto &F : M)
  {
    if (F.empty())
    {
      continue;
    }

    errs() << F.getName() << "\n";

    BasicBlock &Bstart = F.front();
    BasicBlock &Bend = F.back();

    Instruction &ret = *(++Bend.rend());
    Instruction &Istart = Bstart.front();

    IRBuilder<> BuilderStart(&Istart);
    IRBuilder<> BuilderEnd(&ret);

    // inc
    Value *depth = BuilderStart.CreateLoad(IntegerType::getInt32Ty(ctx), gvDepth);
    Value *Inc = BuilderStart.CreateAdd(depth, one);
    StoreInst *Store = BuilderStart.CreateStore(Inc, gvDepth);

    // don't print space for main()
    if (F.getName() != "main")
    {
      BuilderStart.CreateCall(printfCallee, {printDepthSpaceFormat, depth, space});
    }

    Constant *functionName = getI8StrVal(M, F.getName().data(), "functionName");
    BuilderStart.CreateCall(printfCallee, {functionName});
    BuilderStart.CreateCall(printfCallee, {colon});
    BuilderStart.CreateCall(printfCallee, {printAddressFormat, &F});
    BuilderStart.CreateCall(printfCallee, {newLine});

    // dec
    depth = BuilderEnd.CreateLoad(IntegerType::getInt32Ty(ctx), gvDepth);
    Value *Sub = BuilderEnd.CreateSub(depth, one);
    Store = BuilderEnd.CreateStore(Sub, gvDepth);
  }

  return true;
}

static RegisterPass<LabPass> X("labpass", "Lab Pass", false, false);