//===- Hello.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "hello"

STATISTIC(HelloCounter, "Counts number of functions greeted");

namespace {

  struct Hello : public FunctionPass {

    static char ID; // Pass identification, replacement for typeid

    Hello() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
      ++HelloCounter;
      errs() << "Hello: ";
      errs().write_escaped(F.getName()) << '\n';
      return false;
    }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.setPreservesAll();
    }
  };
}

char Hello::ID = 0;

static void registerHello(const PassManagerBuilder &,
                          legacy::PassManagerBase &PM) {
  PM.add(new Hello());
}

static RegisterStandardPasses RegisterHelloPass(
    PassManagerBuilder::EP_EarlyAsPossible, registerHello);
