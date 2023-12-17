/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <string.h>
#include <sys/wait.h>

#include <iostream>
#include <fstream>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Instrumentation/AddressSanitizer.h"

#define FUNC_SIZE_POW2 16
#define FUNC_SIZE (1U << FUNC_SIZE_POW2)

#define DEBUG_TYPE "ff-asan"


using namespace llvm;

struct FishFuzzASan {

  FishFuzzASan(Module &M) {
    C = &(M.getContext());
  }

  bool instrumentModule(Module &M);
  size_t getInstrumentId(const char *IdFile, size_t NewSize);
  bool hasSanInstrument(BasicBlock &BB);
  bool isBlacklisted(const Function *F);
  std::string encodePathStr(std::string Path);

private:
  LLVMContext *C;

};


size_t FishFuzzASan::getInstrumentId(const char *IdFile, size_t NewSize) {

  int fd = open(IdFile, O_RDWR, 0666);
  if (fd < 0) {perror("failed open fd:"); exit(-1);}

  srand(getpid());
  usleep(rand() % 1000);

  while (flock(fd, LOCK_EX|LOCK_NB) == -1) {

    // printf("[DEBUG] Still locked, waiting...\n");
    usleep(rand() % 1000);

  }

  // printf("[DEBUG] We Locked\n");
  // ok, we have a exclusive lock now

  size_t current_start = 0, current_end = 0;
  std::ifstream fidr;
  std::ofstream fidw;

  fidr.open(IdFile, std::ios_base::in);
  if (fidr.is_open()) {

    std::string line, last_line;
    while (getline(fidr, line)) last_line = line;

    std::size_t end_pos = last_line.find(",");
    std::string end_id_s = last_line.substr(end_pos + 1, last_line.length() - end_pos);
    current_start = atoi(end_id_s.c_str());
    current_end = current_start + NewSize + 1;

    fidr.close();

  } else { perror("failed open fid:"); exit(-1);}

  fidw.open(IdFile, std::ios_base::app);
  if (fidw.is_open()) {
  
    fidw << current_start << "," << current_end << std::endl;
    fidw.close(); 

  } else { perror("failed open fid:"); exit(-1);}

  // release the lock
  // printf("[DEBUG] We Release\n");

  flock(fd, LOCK_UN);
  close(fd);

  return current_start;

}

bool FishFuzzASan::hasSanInstrument(BasicBlock &BB) {
  bool ExistsSan = false;
  for (Instruction& Inst : BB.getInstList()) {
    if (auto Call = dyn_cast<CallInst>(&Inst)) {
      Function* CalledFunc = Call->getCalledFunction();
      if (CalledFunc) {
        // probably with asan_handle or mem as well
        if (CalledFunc->getName().startswith("__asan_report"))
          ExistsSan = true;

      }
    }
  }
  return ExistsSan;
}

bool FishFuzzASan::isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "__asan_report",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}


// char FishFuzzASanPass::ID = 0;

std::string FishFuzzASan::encodePathStr(std::string Path) {

  std::string from = "/", to = ".";
  size_t pos = 0;
  while ((pos = Path.find(from)) != std::string::npos) {

    if (pos == 0) Path.erase(pos, 1);
    else Path.replace(pos, 1, to);
  
  }
  return Path;

}

bool FishFuzzASan::instrumentModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  LLVM_DEBUG(dbgs() << M << "\n");

  GlobalVariable * AFLMapPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_fish_map");

  SmallVector<BasicBlock *, 16> SanBlocks, ReachBlocks, PruneReachBlocks;
  size_t vulnBlocks = 0, beginSanId = 0, curSanId = 0, pruneVulnBlocks = 0,
         numFuncs = 0, beginFuncId = 0, curFuncId = 0;


  /* Obtain the sanitizer target blocks */

  for (auto &F : M) {

    if (isBlacklisted(&F) || F.empty()) continue;

    for (auto &BB : F) {

      BasicBlock* pred = BB.getSinglePredecessor();
      
      if (hasSanInstrument(BB) && pred) {

        vulnBlocks += 1;
        SanBlocks.push_back(&BB);
        ReachBlocks.push_back(pred);
      
      }
    
    }
  
  }

  /* Prune sanitizer targets on the same path */
  for (auto &ReachBB: ReachBlocks) {

    BasicBlock* predBB = ReachBB->getSinglePredecessor();

    if (predBB) {

      // if its pred is a ReachBlocks, it's redundant
      if (std::find(ReachBlocks.begin(), ReachBlocks.end(), predBB) == ReachBlocks.end()) {
      
        PruneReachBlocks.push_back(ReachBB);
        pruneVulnBlocks += 1;
      
      }
    
    }

  }

  std::string TempDir, FidFilename, TempFuncId, TempTargId;
  if (getenv("FF_TMP_DIR")) {

    TempDir = getenv("FF_TMP_DIR");
    FidFilename = TempDir + "/fid/" + encodePathStr(std::string(M.getModuleIdentifier())) + ".fid.txt";
    TempFuncId = TempDir + "/idlog/fid";
    TempTargId = TempDir + "/idlog/targid";
    
  } else perror("Please set the FF_TMP_DIR before start!\n");

  /* Obtain the range of sanitizer ids */

  beginSanId = getInstrumentId(TempTargId.c_str(), pruneVulnBlocks);
  curSanId = beginSanId;

  
  for (auto &SanBB : SanBlocks) {

    /* Instrument the Sanitizer Reach Info */

    BasicBlock *ReachBB = SanBB->getSinglePredecessor();

    if (std::find(PruneReachBlocks.begin(), PruneReachBlocks.end(), ReachBB) == PruneReachBlocks.end()) 
      continue;
    
    BasicBlock::iterator ReachIP = ReachBB->getFirstInsertionPt();
    IRBuilder<> ReachIRB(&(*ReachIP));

    LoadInst *ReachMapPtr = ReachIRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
    ReachMapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    Value *ReachCmpPtrIdx = ReachIRB.CreateGEP(Int8Ty, ReachMapPtr, ConstantInt::get(Int32Ty, FUNC_SIZE + curSanId));

    ReachIRB.CreateStore(ConstantInt::get(Int8Ty, 1), ReachCmpPtrIdx)
      ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));   

    /* Instrument the Sanitizer Trigger Info */

    BasicBlock::iterator SanIP = SanBB->getFirstInsertionPt();
    IRBuilder<> SanIRB(&(*SanIP));

    LoadInst *SanMapPtr = SanIRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
    SanMapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    Value *SanCmpPtrIdx = SanIRB.CreateGEP(Int8Ty, SanMapPtr, ConstantInt::get(Int32Ty, FUNC_SIZE + curSanId));

    SanIRB.CreateStore(ConstantInt::get(Int8Ty, 2), SanCmpPtrIdx)
        ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

    curSanId += 1;
    
  }

  /* Obtain the range of function ids */

  for (auto &F : M) {
    
    if (!isBlacklisted(&F) && !F.empty()) numFuncs += 1;
  
  }

  std::ofstream FuncMap(FidFilename, std::ofstream::out | std::ofstream::app);

  if (!FuncMap.is_open()) { perror("Cannot open FuncMap :"); }

  beginFuncId = getInstrumentId(TempFuncId.c_str(), numFuncs);
  curFuncId = beginFuncId;

  for (auto &F : M) {

    if (isBlacklisted(&F) || F.empty()) continue;

    BasicBlock &BB = F.getEntryBlock();
    BasicBlock::iterator FuncIP = BB.getFirstInsertionPt();
    IRBuilder<> FuncIRB(&(*FuncIP));

    LoadInst *FuncMapPtr = FuncIRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
    FuncMapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    Value *FuncPtrIdx =
      FuncIRB.CreateGEP(Int8Ty, FuncMapPtr, ConstantInt::get(Int32Ty, curFuncId));

    FuncIRB.CreateStore(ConstantInt::get(Int8Ty, 1), FuncPtrIdx)
        ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

    /* write a log for modulename, fname, fid */
    
    FuncMap << F.getName().str() << "," << curFuncId << "\n";
    
    curFuncId += 1;

  }

  FuncMap.close();
  

  /* Say something nice. */

  LLVM_DEBUG(dbgs() << "FishFuzz ASan Module now handling: " << M.getName() << "\n");

  return true;

}


/* define the new pass manager */

/* add registry in llvm/lib/Passes/PassRegistry.def */

FishFuzzASanPass::FishFuzzASanPass() {}

PreservedAnalyses FishFuzzASanPass::run(Module &M, AnalysisManager<Module> &AM) {

  FishFuzzASan FFASan(M);
  if (FFASan.instrumentModule(M))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();

}
