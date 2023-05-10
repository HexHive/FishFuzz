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

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/IR/CFG.h"

#if LLVM_VERSION_MAJOR >= 14
  #include "llvm/Support/GraphWriter.h"
#endif


#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

// #define PREFUZZ_DATA_INST

using namespace llvm;


/* Arguments for distance calculation */

cl::opt<std::string> FuncId(
    "funcid",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("funcid")
);

cl::opt<std::string> IsDebug(
    "debug",
    cl::desc("If specify this argument in analysis mode, will generate binary with _prefuzz_dbg_path"),
    cl::value_desc("debug"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

cl::opt<std::string> PrefuzzMode(
    "pmode",
    cl::desc("Select a mode between cov(coverage tracking), var(capture variable)"),
    cl::value_desc("pmode"));


namespace llvm {
  /* wrapper to generate cfg */
  template<>
  struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
    DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

    static std::string getGraphName(Function *F) {
      return "CFG for '" + F->getName().str() + "' function";
    }

    std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
      if (!Node->getName().empty()) {
        return Node->getName().str();
      }

      std::string Str;
      raw_string_ostream OS(Str);

      Node->printAsOperand(OS, false);
      return OS.str();
    }
  };

}

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };


}


char AFLCoverage::ID = 0;


#include <iostream>


/* Helper function to map basicblock to source code */
static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line, unsigned &Col) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Col = cDILoc.getColumnNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Col = Loc->getColumn();
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Col = oDILoc->getColumn();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}


static inline unsigned int get_block_id(BasicBlock &bb)
{
  unsigned int bbid = 0; 
  MDNode *bb_node = nullptr;
  for (auto &ins: bb){
    if ((bb_node = ins.getMetadata("afl_cur_loc"))) break;
  }
  if (bb_node){
    bbid = cast<ConstantInt>(cast<ValueAsMetadata>(bb_node->getOperand(0))->getValue())->getZExtValue();
  }
  return bbid;
}


static inline unsigned int get_edge_id(BasicBlock &src, BasicBlock &dst) {
  unsigned int src_bbid = 0, dst_bbid = 0; 
  src_bbid = get_block_id(src);
  dst_bbid = get_block_id(dst);
  if (src_bbid && dst_bbid){
    return ((src_bbid >> 1) ^ dst_bbid);
  }
  return 0;
}

static void save_edge(BasicBlock &src, BasicBlock &dst, unsigned is_direct, std::ofstream& outfile) {
  std::string src_name(""), dst_name("");
  for (auto &I : src) {
    std::string filename;
    unsigned line, col;
    getDebugLoc(&I, filename, line, col);
    static const std::string Xlibs("/usr/");
    if (filename.empty() || !filename.compare(0, Xlibs.size(), Xlibs)) continue;

    std::size_t found = filename.find_last_of("/\\");
    if (found != std::string::npos)
      filename = filename.substr(found + 1);
    
    src_name = filename + ":" + src.getParent()->getName().str() + ":";
    break;
  }
  for (auto &I : dst) {
    std::string filename;
    unsigned line, col;
    getDebugLoc(&I, filename, line, col);
    static const std::string Xlibs("/usr/");
    if (filename.empty() || !filename.compare(0, Xlibs.size(), Xlibs)) continue;

    std::size_t found = filename.find_last_of("/\\");
    if (found != std::string::npos)
      filename = filename.substr(found + 1);
    
    dst_name = filename + ":" + dst.getParent()->getName().str() + ":";
    break;
  }
  if (!src_name.empty() && !dst_name.empty()) 
    outfile << src_name << get_block_id(src) << "," 
            << dst_name << get_block_id(dst) << ","
            << get_edge_id(src, dst) << ","
            // is there a constraints?
            << ((is_direct == 1) ? "true" : "false") << "\n";  
  return;
}

static inline bool has_sanitizer_instrumentation(BasicBlock &bb) {
  bool is_lava = (getenv("USE_LAVA_LABEL") != NULL);
  bool is_magma = (getenv("USE_MAGMA_LABEL") != NULL);
  bool is_ubsan = (getenv("USE_UBSAN_LABEL") != NULL);
  bool existSanitizerBr = false;
  for (Instruction& inst : bb.getInstList()) {
    // if (inst.getMetadata("afl_edge_sanitizer") != NULL) {
    //   existSanitizerBr = true;
    //   break;
    // }
    if (auto call = dyn_cast<CallInst>(&inst)) {
      Function* calledFunc = call->getCalledFunction();
      // errs() << calledFunc->getName().str().c_str() << "\n"; 
      if (calledFunc) {
        if (is_lava) {
          // for lava-m, use lava_get as vuln label
          if (calledFunc->getName().compare("lava_get") == 0)
            existSanitizerBr = true;
        }
        else if (is_magma) {
          if (calledFunc->getName().compare("magma_alert") == 0)
            existSanitizerBr = true;
        }
        else {
          if (calledFunc->getName().startswith("__ubsan_handle")) {

            if (is_ubsan) existSanitizerBr = true;

          }
          if (calledFunc->getName().startswith("__asan_report"))
            existSanitizerBr = true;
          if (calledFunc->getName().startswith("__asan_handle"))
            // std::cout << calledFunc->getName().str() << "\n";
            existSanitizerBr = true;
        }
      }
    }
  }
  return existSanitizerBr;
}

static inline bool handle_uncov_interesting_inst(Instruction& instr, std::ofstream& outfile)
{
  bool handled = false;
  switch (instr.getOpcode()) {

    case Instruction::Switch:{
      SwitchInst &sw_instr = cast<SwitchInst>(instr);
      auto src_bb = instr.getParent();
      for (unsigned int i = 0; i < sw_instr.getNumSuccessors(); ++i) {
        // if (i == 0) outfile << get_block_id(*src_bb)<<":";
        auto dst_bb = sw_instr.getSuccessor(i);
        unsigned int pair_edge = get_edge_id(*src_bb, *dst_bb);
        
        if (pair_edge != 0) {
          save_edge(*src_bb, *dst_bb, 1, outfile);
          // outfile << get_block_id(*src_bb) << "," 
          //         << get_block_id(*dst_bb) << ","
          //         << pair_edge << "\n";
        }
      }
      // outfile << "\n";
      handled = true;
      break;
      
    }
    case Instruction::Br:{
      BranchInst &br_instr = cast<BranchInst>(instr);
      if (br_instr.isConditional()){
        auto src_bb = instr.getParent();
        for (unsigned int i = 0; i < br_instr.getNumSuccessors(); ++i) {
          // if (i == 0) outfile << get_block_id(*src_bb)<<":";
          auto dst_bb = br_instr.getSuccessor(i);
          unsigned int pair_edge = get_edge_id(*src_bb, *dst_bb);
          if (pair_edge != 0) {
            save_edge(*src_bb, *dst_bb, 1, outfile);

            // outfile << get_block_id(*src_bb) << "," 
            //         << get_block_id(*dst_bb) << ","
            //         << pair_edge << "\n";
          }
        }
        // outfile << "\n"; 
        handled = true;
      }
      break;
    }

    case Instruction::IndirectBr:{
      IndirectBrInst &ind_br_instr = cast<IndirectBrInst>(instr);
      auto src_bb = instr.getParent();

      for (unsigned int i = 0; i < ind_br_instr.getNumSuccessors(); ++i) {
        // if (i == 0) outfile << get_block_id(*src_bb)<<":";
        auto dst_bb = ind_br_instr.getSuccessor(i);
        unsigned int pair_edge = get_edge_id(*src_bb, *dst_bb);
        /* print_edge(*src_bb, *dst_bb, ind_br_instr.getNumSuccessors(), outfile)*/
        if (pair_edge != 0) {
          save_edge(*src_bb, *dst_bb, 1, outfile);
          // outfile << get_block_id(*src_bb) << "," 
          //         << get_block_id(*dst_bb) << ","
          //         << pair_edge << "\n";
        }
      }
      // outfile << "\n"; 
      handled = true;
      break;
    }

    default: {
      // single successor
      BasicBlock *src_bb = instr.getParent();
      BasicBlock *dst_bb = src_bb->getSingleSuccessor();
      if (dst_bb && get_edge_id(*src_bb, *dst_bb)) {
        save_edge(*src_bb, *dst_bb, 0, outfile);
      }
      handled = false;
    }
  }

  return handled;
}


/* Skip blacklist function */
static bool isBlacklisted(const Function *F) {
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


bool AFLCoverage::runOnModule(Module &M) {

  /* parse configure file and specify the target */
  bool is_coverage = false, is_analysis = false, 
       is_rename = false, is_origin = false, 
       is_function = false;

  if (PrefuzzMode.empty()) {
    /* add support for original coverage tracking only */
    FATAL("Please Specify the instrumentation mode!");
    return false;
  }

  std::string dbg("dbg"), var("var"), conly("conly"), aonly("aonly"),
              fonly("fonly"), analysis("analysis"), orig("origin"), rename("rename");
  if (PrefuzzMode.compare(conly) == 0) is_coverage = true;
  else if (PrefuzzMode.compare(aonly) == 0) is_analysis = true;
  else if (PrefuzzMode.compare(analysis) == 0) {is_coverage = true; is_analysis = true;}
  else if (PrefuzzMode.compare(fonly) == 0) is_function = true;
  else if (PrefuzzMode.compare(orig) == 0) is_origin = true;
  else if (PrefuzzMode.compare(rename) == 0) is_rename = true;
  else {
    FATAL("Unrecognized mode option, select 'cov' or 'var'!");
    return false;
  }


  /* now in coverage tracking mode, we provide argument -OutDirectory -PrefuzzMode 
    in variable tracking mode, we provide initial distance file */


  // std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::vector<std::string> basic_blocks;

  if (is_analysis) {
    /* output previous .bc and output vulnbb.csv, locmap.csv, paired_edges.csv */
    if (!FuncId.empty() || OutDirectory.empty()) {
      FATAL("Now run in analysing mode, provide '-outdir' only!");
      return false;
    }
  }
  else if (is_function) {
    if (FuncId.empty()|| OutDirectory.empty()) {
      FATAL("Now run in function instrumenting mode, provide both '-outdir' and '-funcid'!");
      return false;
    }
  }



  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {
    if (is_analysis || is_coverage)
      SAYF(cCYA "prefuzz %s%s mode " cBRI VERSION cRST " by <lszekeres@google.com>\n", 
          is_analysis ? "analysis" : "", is_coverage ? "coverage" : "");
    else if (is_function)
      SAYF(cCYA "prefuzz function mode " cBRI VERSION cRST " by <lszekeres@google.com>\n");
    else if (is_rename) 
      SAYF(cCYA "prefuzz rename mode " cBRI VERSION cRST " by <lszekeres@google.com>\n");
    else {
      SAYF(cCYA "origin afl " cBRI VERSION cRST " by <lszekeres@google.com>\n");
      return 1;
    }
  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Default: Not selective */
  char* is_selective_str = getenv("PREFUZZ_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of PREFUZZ_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("PREFUZZ_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of PREFUZZ_INST_RATIO (must be between 1 and 100)");

  }

  /* Instrument all the things! */

  int has_blocks = 0, empty_blocks = 0, vuln_blocks = 0, inst_vms = 0, inst_funcs = 0;
  
  /* skip conftest.c, the file generated in configuring... */
  if (strcmp(M.getSourceFileName().c_str(), "conftest.c") == 0) return true;
  

  if (is_rename) {
    for (Function &F: M) {
      for (BasicBlock &BB : F) {
        std::string BName;
        raw_string_ostream OBName(BName);
        BB.printAsOperand(OBName, false);

        std::string filename = F.getParent()->getSourceFileName();
        std::size_t found = filename.find_last_of("/\\");
        if (found != std::string::npos)
          filename = filename.substr(found + 1);
        
        BB.setName(filename + ":" + F.getName().str() + ":" + OBName.str());
        // errs() << filename + ":" + F.getName().str() + ":" + OBName.str() << "\n";
      }
    }
  }
  /* this pass will only be performed on one bc (e.g. objdump.bc) 
      bug_cmp.csv, vulnfunc.csv locmap.csv, paired_edges.csv callmap.csv */
  else if (is_analysis) {

    std::ofstream vulnfunc(OutDirectory + "/vulnfunc.csv", std::ofstream::out | std::ofstream::app);
    std::ofstream funcmap(OutDirectory + "/funcmap.csv", std::ofstream::out | std::ofstream::app);
    std::ofstream paired_edges(OutDirectory + "/paired_edges.csv", std::ofstream::out | std::ofstream::app);
    std::ofstream callmap(OutDirectory + "/callmap.csv", std::ofstream::out | std::ofstream::app);
    std::ofstream cmp_log(OutDirectory + "/cmp_log.csv", std::ofstream::out | std::ofstream::app);
    std::ofstream firstbb(OutDirectory + "/firstbb.csv", std::ofstream::out | std::ofstream::app);
    std::ofstream bug_cmps(OutDirectory + "/bug_cmps.csv", std::ofstream::out | std::ofstream::app);
    std::ofstream dbg_bug(OutDirectory + "/dbg_bug.csv", std::ofstream::out | std::ofstream::app);

    std::string dotfiles(OutDirectory + "/dot-files");
    /* Create dot-files directory */
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

    /* type and function declaration for debuging functions */
    LLVMContext &C = M.getContext();

    /* get callmap, vulnbb, vulnfunc and locmap */
    for (auto &F: M) {

      if (F.empty() || isBlacklisted(&F)) {
        continue;
      }
      bool has_san_func = false; 

      if (!F.getName().empty() && is_analysis) {
        funcmap << F.getName().str() << "\n";
      }

      std::string fst_bb_name("");
      for (auto &BB: F) {
        
        std::string filename = F.getParent()->getSourceFileName();
        std::size_t found = filename.find_last_of("/\\");
        if (found != std::string::npos)
          filename = filename.substr(found + 1);

        std::string bb_name = BB.getName().str();
        // errs() << BB.getName().str() << "\n";

        if (bb_name.empty()) {
          empty_blocks ++;
          continue;
        }
        else has_blocks ++;

        if (fst_bb_name.empty() && !bb_name.empty()) {
          fst_bb_name = bb_name;
        }
        
        bool has_san_label = has_sanitizer_instrumentation(BB); 
        vuln_blocks += has_san_label;
        if (has_san_label && !has_san_func) has_san_func = true;

        if (has_san_label) {
          /* output important cmp, if conf == 0, then visited. */
          if (getenv("USE_LAVA_LABEL") != NULL) {
            /* lava-m like, just use important cmps */
            bug_cmps << bb_name << "\n";
          }
          else {
            /* for original version or magma, 
              predecessor is the sanitizer's dominator cmp */
            BasicBlock *pred = BB.getSinglePredecessor();
            if (pred) {
              /* only one predecessor */
              std::string pred_name = pred->getName().str();
              bug_cmps << pred_name << "\n";
              dbg_bug << pred_name << "," << bb_name << "\n";
            }
          }
        }
        /* cannot deal with indirect calls, save it for later */
        for (auto &I: BB) {
          if (auto *c = dyn_cast<CallInst>(&I)) {
            if (auto *CalledF = c->getCalledFunction()) {
              if (!isBlacklisted(CalledF))
                callmap << bb_name << "," 
                        << CalledF->getName().str() << ","
                        << fst_bb_name << "\n";
            }
          }
            
          /* record the cmp id in the target, prune it later */
          if (CmpInst *cmpIns = dyn_cast<CmpInst>(&I)) {

            cmp_log << bb_name << "\n";
              
          }
        }


      }

      if (is_analysis) {
      
        if (!fst_bb_name.empty()) 
          firstbb << fst_bb_name << "\n";
        if (has_san_func) {
          vulnfunc << F.getName().str() << "\n";
        }

        /* Print CFG */
        if (has_blocks) {

          std::string filename = F.getParent()->getSourceFileName();
          std::size_t found = filename.find_last_of("/\\");
          if (found != std::string::npos)
            filename = filename.substr(found + 1, filename.find_first_of("."));
          // strip .c(pp)
          filename = filename.substr(0, filename.find_last_of('.'));
          // cfgFileName format : cfg.xmllint.main.dot
          // std::string cfgFileName = dotfiles + "/cfg." + filename + "."+ funcName + ".dot";
          std::string cfgFileName = dotfiles + "/cfg." + F.getName().str() + ".dot";
          std::error_code EC;
          raw_fd_ostream cfgFile(cfgFileName, EC, 
#if LLVM_VERSION_MAJOR >= 14
          sys::fs::OF_None
#else
          sys::fs::F_None
#endif
          );
          if (!EC) {
            WriteGraph(cfgFile, &F, true);
          }
        }

      }

    }

    if (is_analysis) {

      /* get paired_edges */
      for (auto &F: M) {
        if (F.empty() || isBlacklisted(&F)) {
          continue;
        }

        for (auto &BB: F) {
          Instruction *termInst = dyn_cast<Instruction>(BB.getTerminator());
          handle_uncov_interesting_inst(*termInst, paired_edges);
        }
      }

    }
  
  }

  /* instrument function trace */
  else if (is_function) {
    LLVMContext &C = M.getContext();

    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    GlobalVariable *AFLMapPtr = // M.getGlobalVariable("__afl_fish_map", true);
            new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                          GlobalValue::ExternalLinkage, 0, "__afl_fish_map");
    
    std::map<std::string, u32> func2id;
    std::ifstream fi(FuncId);
    if (fi.is_open()) {
      std::string line;
      while (getline(fi, line)) {
        
        std::size_t dis_pos = line.find(",");
        std::string fname = line.substr(dis_pos + 1, line.length() - dis_pos);
        std::string idx_str = line.substr(0, dis_pos);
        func2id.emplace(fname, atoi(idx_str.c_str()));
        // std::cout << fname << " : " << idx_str << "\n";
      }
    }
    else PFATAL("function id file not found!");

    std::ifstream bcmps(OutDirectory + "/dbg_bug.csv");
    std::map<std::string, u32> cmp2id, bug2id;
    if (bcmps.is_open()) {
      std::string line;
      std::uint32_t id = 0;
      while (getline(bcmps, line) && id < VMAP_COUNT) {
        std::size_t pos = line.find(",");
        std::string bug_name = line.substr(pos + 1, line.length() - pos);
        std::string cmp_name = line.substr(0, pos);
        if (bug2id.find(bug_name) == bug2id.end()) {
          bug2id.emplace(bug_name, id);
        }
        if (cmp2id.find(cmp_name) == cmp2id.end()) {
          cmp2id.emplace(cmp_name, id);
        }
        id ++;
      }
    }
    else PFATAL("bug cmp file not found!");

    for (auto &F : M) {

      if (F.empty() || isBlacklisted(&F)) {
        continue;
      }
      
      /* function trace instrumentation*/
      
      auto iter = func2id.find(F.getName().str());
      if (iter != func2id.end()) {
        
        // OKF("Found %s.", F.getName().str().c_str());

        BasicBlock::iterator IP = F.front().getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int8Ty, 0),
#endif
          AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *FuncPtrIdx =
            IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
              Int8Ty,
#endif
              MapPtr, ConstantInt::get(Int32Ty, iter->second));

        IRB.CreateStore(ConstantInt::get(Int8Ty, 1), FuncPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

	inst_funcs ++;
      }

      for (auto &BB : F) {

        std::string bb_name = BB.getName().str();

        auto biter = bug2id.find(bb_name);
        if (biter != bug2id.end()) {

          std::uint32_t bugid = biter->second;
          BasicBlock::iterator IP = BB.getFirstInsertionPt();
          IRBuilder<> IRB(&(*IP));

          LoadInst *MapPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int8Ty, 0),
#endif
          AFLMapPtr);
          MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          Value *CmpPtrIdx =
              IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
                Int8Ty,
#endif
                MapPtr, ConstantInt::get(Int32Ty, FUNC_SIZE + (bugid >> 2)));

          LoadInst *Counter = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          Int8Ty,
#endif
          CmpPtrIdx);
          Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *Incr = IRB.CreateOr(Counter, ConstantInt::get(Int8Ty, 1 << ((bugid & 0x3) * 2)));
          IRB.CreateStore(Incr, CmpPtrIdx)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
	        inst_vms ++;

        }
        auto citer = cmp2id.find(bb_name);
        if (citer != cmp2id.end()) {
          std::uint32_t cmpid = citer->second;
          BasicBlock::iterator IP = BB.getFirstInsertionPt();
          IRBuilder<> IRB(&(*IP));

          LoadInst *MapPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int8Ty, 0),
#endif
          AFLMapPtr);
          MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          Value *CmpPtrIdx =
              IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
                Int8Ty,
#endif
                MapPtr, ConstantInt::get(Int32Ty, FUNC_SIZE + (cmpid >> 2)));

          LoadInst *Counter = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          Int8Ty,
#endif
            CmpPtrIdx);
          Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *Incr = IRB.CreateOr(Counter, ConstantInt::get(Int8Ty, 1 << ((cmpid & 0x3) * 2 + 1)));
          IRB.CreateStore(Incr, CmpPtrIdx)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));        }

      }

    }

  }

  /* Say something nice. */
  if (!be_quiet && is_analysis) {

    if (!has_blocks) WARNF("Analysis: No instrumentation targets found.");
    else OKF("Analysis: Among %u basic blocks (ratio %u%%), find %u vuln.",
             has_blocks, inst_ratio, vuln_blocks);
  }

  if (!be_quiet && is_function) {
    OKF("Function: Instrumented %u functions, %u sanitizer location.", inst_funcs, inst_vms);
  }



  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

/* enable debug manually */
static RegisterPass<AFLCoverage> X("test", "AFL insert coverage!\n",
    false, false);



static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
