#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
  struct FINJInst : public ModulePass {
    FINJInst(): ModulePass(ID) {}

    bool runOnModule(Module &M) override;

    static char ID;
    static StringSet<> funcsToReplace;
  };
}

StringSet<> FINJInst::funcsToReplace = {
  "malloc","calloc","realloc","mmap",
  "fstat","lstat","fstatat",
  "creat","lseek","read","write","close",
  "rename","renameat","link","linkat","unlink","unlinkat",
  "truncate","ftruncate","remove","symlink","symlinkat",
  "opendir","fdopendir","mkdir","mkdirat","rmdir",
  "mkdtemp","mkstemp","mkfifo","mkfifoat",
  "dup","dup2","pread","pwrite", "chdir","fchdir",
  "chown","fchown","lchown","fchownat",
  "chmod","fchmod","fchmodat",
  "getgrnam","getgrgid","getpwnam","getpwuid"
};

char FINJInst::ID = 0;

bool FINJInst::runOnModule(Module &M) {
  for (auto &&F : M) {
    if (F.isDeclaration()) {
      StringRef fName = F.getName();
      if (funcsToReplace.find(fName) != funcsToReplace.end()) {
        F.setName("finj_" + fName);
        errs() << "hook: " << fName << "\n";
      }
    }
  }
  return true;
}

static void registerFINJInst(const PassManagerBuilder &,
                             legacy::PassManagerBase &PM) {
  PM.add(new FINJInst());
}

static RegisterStandardPasses Register(
    PassManagerBuilder::EP_OptimizerLast, registerFINJInst);

static RegisterStandardPasses RegisterLevel0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerFINJInst);
