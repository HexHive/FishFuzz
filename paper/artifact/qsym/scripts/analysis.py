#!/usr/bin/python3

# Written by Zheng Han <kdsjzh@gmail.com>

import os
import subprocess
# from progress.bar import Bar
# from alive_progress import alive_it
import json
from datetime import datetime
import re
import argparse



class AnalysisOneResults:
  """"""
  # -----------------
  def __init__(self, binary_path, binary_args, base_dir, is_asan = True, is_crash = False, round = 0):
    """ Constructor """
    self.binary_path     = binary_path
    self.args            = binary_args
    self.out_dir         = binary_path[:binary_path.rfind('/')]
    self.prog_name       = binary_path[binary_path.rfind('/') + 1:]
    self.base_dir        = base_dir
    self.is_asan         = is_asan
    self.is_crash        = is_crash
    self.round           = round
    # runtime file
    self.__map_path      = '%s/temp.map' % (self.out_dir)
    self.__cov_log       = '%s/%s.cov'   % (self.out_dir, self.prog_name)
    self.__reach_log     = '%s/%s.reach' % (self.out_dir, self.prog_name)
    self.__san_log       = '%s/%s.san'   % (self.out_dir, self.prog_name)
    # configure
    self.MAP_SIZE        = 64 * 1024
    self.FUNC_SIZE       = 16 * 1024
    self.CMP_SIZE        = 64 * 1024
    self.AFL_SHOWMAP     = "/FishFuzz/afl-showmap"
    # storing the edge/reach/san coverage
    self.__all_cov_map   = dict()
    self.__all_reach_map = dict()
    self.__all_san_map = dict()
    self._time2cov       = dict()
    self._time2reach     = dict()
    self._time2san       = dict()
    # seed corpus with timestamp
    self.__seed_list     = dict()
    self.__sorted_list   = dict()
    # fuzzer list we evaluate
    self.__fuzzer_list   = ['afl', 'ffafl']
    for __fuzzer in self.__fuzzer_list:
      self._time2cov[__fuzzer]       = dict()
      self._time2reach[__fuzzer]     = dict()
      self._time2san[__fuzzer]       = dict()
      self.__all_cov_map[__fuzzer]   = [0 for _ in range(self.MAP_SIZE)]
      self.__all_reach_map[__fuzzer] = [0 for _ in range(self.CMP_SIZE * 4)]
      self.__all_san_map[__fuzzer] = []

  # --------------------------------------------------------------------------------------------
  def parse_sname(self, sname):
    """ Get seed's info from its name """
    if sname.count(',') != -1 or sname.find('orig:') != -1:
      id = int(sname[sname.find('id:') + 3: sname.find(',')])
      if sname.find('time:') != -1:
        # AFLplusplus
        exec_ms = int(sname[sname.find('time:') + 5: sname.find(',execs')])
      else :
        # AFL-like
        if sname.find('orig:') != -1:
          exec_ms = 0
        else :
          exec_ms = int(sname[sname.rfind(',') + 1:])
    else :
      # for parmesan
      id_s, exec_ms_s = sname[sname.find(':') + 1:].split(',')
      id = int(id_s)
      exec_ms = int(exec_ms_s)
    return id, exec_ms 
  # --------------------------------------------------------------------------------------------
  def sort_corpus(self, fuzzer):
    """Get sorted corpus according to timestamp"""
    self.__sorted_list[fuzzer] = []
    if not self.__seed_list[fuzzer]:
      print ('[WARN] Empty seed corpus!')
      return
    __seed_dict = dict()
    for _sname in self.__seed_list[fuzzer]:
      _id, _exec_ms = self.parse_sname(_sname)
      __seed_dict[_exec_ms] = _sname
    for _time in sorted(__seed_dict):
      # skip non-new coverage seed for AFL-like fuzzer
      if fuzzer != 'ParmeSan' and not self.is_crash:
        if __seed_dict[_time].find('+cov') == -1:
          continue
      self.__sorted_list[fuzzer].append(__seed_dict[_time])
  # --------------------------------------------------------------------------------------------
  def update_new_cov(self, fuzzer, _exec_ms):
    """Update Coverage/Reach with the map file generated"""
    if not os.path.exists(self.__map_path):
      return 
    with open(self.__map_path, 'rb') as ft:
      shm_map = ft.read()
    for _eid in range(self.MAP_SIZE):
      if shm_map[_eid] and self.__all_cov_map[fuzzer][_eid] == 0:
        self.__all_cov_map[fuzzer][_eid] = 1
        if _exec_ms not in self._time2cov[fuzzer]:
          self._time2cov[fuzzer][_exec_ms] = []
        self._time2cov[fuzzer][_exec_ms].append(_eid)
    cmp_map = shm_map[self.MAP_SIZE + self.FUNC_SIZE:]
    for _bid in range(self.CMP_SIZE * 4):
      val = cmp_map[int(_bid / 4)]
      if not val :
        continue
      if (val & (1 << (2 * (_bid & 3) + 1)) != 0) and (self.__all_reach_map[fuzzer][_bid] == 0):
        self.__all_reach_map[fuzzer][_bid] = 1
        if _exec_ms not in self._time2reach[fuzzer]:
          self._time2reach[fuzzer][_exec_ms] = []
        self._time2reach[fuzzer][_exec_ms].append(_bid)
    return   
  # --------------------------------------------------------------------------------------------
  def update_new_ubsan(self, fuzzer, _exec_ms, berr):
    """Update Sanitizer in UBSan mode"""
    err_msg = berr.decode('utf-8', 'ignore')
    lpos = err_msg.find('SUMMARY: UndefinedBehaviorSanitizer:')
    while lpos != -1:
      err_msg = err_msg[lpos:]
      rpos = err_msg.find(' in \n')
      pattern = err_msg[:rpos + 1]
      pattern = pattern[:pattern.rfind(':')]
      if pattern not in self.__all_san_map[fuzzer]:
        self.__all_san_map[fuzzer].append(pattern)
        if _exec_ms not in self._time2san[fuzzer]:
          self._time2san[fuzzer][_exec_ms] = []
        self._time2san[fuzzer][_exec_ms].append(pattern)
      err_msg = err_msg[rpos+ 1:] 
      lpos = err_msg.find('SUMMARY: UndefinedBehaviorSanitizer:')
    return 
  # --------------------------------------------------------------------------------------------
  def extract_asan_callstack(self, err_msg, max_func = 5):
    patt = '\[frame=[0-9]+, function=.*]' #, location=.*\
    match_list = re.findall(patt, err_msg)
    func_list = []
    for m in match_list:
      func_list.append(m[m.find('function=') + 9: m.find(']')])
    if len(func_list) > max_func:
      func_list = func_list[:max_func]
    return func_list
    
  # --------------------------------------------------------------------------------------------
  def update_new_asan(self, fuzzer, _exec_ms, berr):
    """Update Sanitizer in ASan mode"""
    err_msg = berr.decode('utf-8', 'ignore')
    lpos = err_msg.find('ERROR: AddressSanitizer: ')
    if lpos == -1 and err_msg.find('ERROR: LeakSanitizer: '):
      btype = 'mem-leak'
    else:
      btype = err_msg[lpos + 25:][:err_msg[lpos + 25:].find(' ')]
    patt = '\[frame=[0-9]+, function=.*]' #, location=.*\
    if btype == 'heap-use-after-free':
      # first divide error message
      free_pos = err_msg.find('freed by thread')
      alloc_pos = err_msg.find('previously allocated by')
      use_msg = err_msg[:free_pos]
      free_msg = err_msg[free_pos : alloc_pos]
      alloc_msg = err_msg[alloc_pos:]
      # use 
      stack_trace = 'USE:' + '->'.join(self.extract_asan_callstack(use_msg, 2))
      # free, skip free
      # stack_trace += ', FREE:' + '->'.join(self.extract_asan_callstack(free_msg, 2)[1:])
      # alloc, skip alloc
      # stack_trace += ', ALLOC:' + '->'.join(self.extract_asan_callstack(alloc_msg, 2)[1:])
    elif btype == 'stack-overflow':
      stack_trace =  '->'.join(self.extract_asan_callstack(err_msg))
    else:
      # match_list = re.findall(patt, err_msg)
      # if len(match_list) > 5:
      #   match_list = match_list[:5]
      # # stack_trace = ':'.join(match_list)
      # stack_trace = ''
      # for m in match_list:
      #   stack_trace += m[m.find('function=') + 9: m.find(']')]
      #   stack_trace += ' -> '
      stack_trace =  '->'.join(self.extract_asan_callstack(err_msg, 3))
    type_stack_trace = btype + ' : ' + stack_trace
    if type_stack_trace not in self.__all_san_map[fuzzer] and stack_trace != '':
      self.__all_san_map[fuzzer].append(type_stack_trace)
      self._time2san[fuzzer][_exec_ms] = [btype, stack_trace]
    return 
  # --------------------------------------------------------------------------------------------
  def execute_and_update_cov(self, __fuzzer_base_queue, _sname):
    """Get coverage by afl-whatsup and parse"""
    os.system('cp %s/%s %s/%s' % (__fuzzer_base_queue, _sname, self.out_dir, 'seed.demo'))
    if self.args.find('@@') == -1:
      _is_stdin = True
      _stdin_fd = open('%s/seed.demo' % (self.out_dir))
    else:
      _stdin_fd = subprocess.PIPE
    _cur_args = self.args.replace('@@', '%s/seed.demo' % (self.out_dir))
    if os.path.exists(self.__map_path):
      os.system('rm %s' % (self.__map_path))
    all_cmd = '%s -m none -b -o %s -- %s %s' % (self.AFL_SHOWMAP, \
                self.__map_path, self.binary_path, _cur_args) 
    try:
      p = subprocess.run(all_cmd.split(' '), stdin=_stdin_fd, 
          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout = 15)
      return p.stderr
    except:
      print ('[WARN] while validating, seed %s timeout, skip' % (_sname))
      return ''
  # --------------------------------------------------------------------------------------------
  def execute_and_update_crash(self, __fuzzer_base_crash, _sname):
    """Execute and extract sanitizer pattern"""
    if not self.is_asan:
      print ('[WARN] UBSan Sanitizer Info will be updated in queue mode ...')
      return ''
    os.system('cp %s/%s %s/%s' % (__fuzzer_base_crash, _sname, self.out_dir, 'seed.demo'))
    if self.args.find('@@') == -1:
      _is_stdin = True
      _stdin_fd = open('%s/seed.demo' % (self.out_dir))
    else:
      _stdin_fd = subprocess.PIPE
    _cur_args = self.args.replace('@@', '%s/seed.demo' % (self.out_dir))
    all_cmd = '%s %s' %(self.binary_path, _cur_args)
    asan_env = os.environ
    # can also use location if binary is compiled with '-g'
    asan_env["ASAN_OPTIONS"] = 'stack_trace_format="[frame=%n, function=%f]"' #, location=%S
    try:
      p = subprocess.run(all_cmd.split(' '), stdin=_stdin_fd, 
          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout = 15, env = asan_env)
      return p.stderr
    except:
      print ('[WARN] while validating, seed %s timeout, skip' % (_sname))
      return ''
  # --------------------------------------------------------------------------------------------
  def update_seed_list(self, fuzzer, corpus_dir):
    self.__seed_list[fuzzer] = []
    for _sname in os.listdir(corpus_dir):
      _spath = os.path.join(corpus_dir, _sname)
      if os.path.isdir(_spath):
        continue
      if _sname.startswith('README'):
        continue
      self.__seed_list[fuzzer].append(_sname)
  # --------------------------------------------------------------------------------------------
  def analysis_program_fuzzer(self, fuzzer):
    """Test one fuzzer's results and parse the log"""
    if not os.path.exists(self.base_dir + '/' + fuzzer):
      print ('[WARN] Fuzzer %s dir not found!' % (fuzzer))
      return 
    __fuzzer_base_queue = '%s/%s/%s/%d/queue' % (self.base_dir, fuzzer, self.prog_name, self.round)
    __fuzzer_base_crash = '%s/%s/%s/%d/crashes' % (self.base_dir, fuzzer, self.prog_name, self.round)
    if not os.path.exists(__fuzzer_base_queue) and not os.path.exists(__fuzzer_base_crash):
      print ('[ERROR] Fuzzer %s did not have crash/queue dir!' %(fuzzer))
      exit(-1)
    # first get sorted corpus dir
    if self.is_crash and self.is_asan:
      self.update_seed_list(fuzzer, __fuzzer_base_crash)
    else :
      self.update_seed_list(fuzzer, __fuzzer_base_queue)
    self.sort_corpus(fuzzer)
    # bar = Bar("[%s]" % (fuzzer) , fill='#', max = 100, suffix = '%(percent)d%%')
    for _sid in range(len(self.__sorted_list[fuzzer])):
      _sname = self.__sorted_list[fuzzer][_sid]
      if self.is_crash and self.is_asan:
        berr = self.execute_and_update_crash(__fuzzer_base_crash, _sname)
        if self.is_asan and berr:
          _id, _exec_ms = self.parse_sname(_sname)
          self.update_new_asan(fuzzer, _exec_ms, berr)
      else:
        berr = self.execute_and_update_cov(__fuzzer_base_queue, _sname)
        _id, _exec_ms = self.parse_sname(_sname)
        self.update_new_cov(fuzzer, _exec_ms)
        if not self.is_asan and berr:
          self.update_new_ubsan(fuzzer, _exec_ms, berr)
  def start_all(self):
    for fuzzer in self.__fuzzer_list:
      self.analysis_program_fuzzer(fuzzer)
    if not self.is_crash:
      with open(self.__cov_log, 'w') as fl:
        json.dump(self._time2cov, fl)
      with open(self.__reach_log, 'w') as fl:
        json.dump(self._time2reach, fl)
      if not self.is_asan:
        with open(self.__san_log, 'w') as fl:
          json.dump(self._time2san, fl)
    else:
      with open(self.__san_log, 'w') as fl:
        json.dump(self._time2san, fl)
    print ('[OK] successfully dump all logs!')


# --------------------------------------------------------------------------------------------
def load_config_and_exec(base, json_path, round):
  with open(json_path) as f:
    conf = json.load(f)
  for prog in conf["prog_driver"]:
    bin_name = prog
    args = conf["prog_args"][bin_name]
    # --------------------
    prog_bin_dir  = '%s/%s' % ('/binary/ffafl/', bin_name)
    prog_args     = args
    is_asan       = conf["is_asan"]
    is_crash      = conf["is_crash"]
    # --------------------
    print ('---------------------------------[%s]---------------------------------' % (bin_name))
    Worker = AnalysisOneResults(prog_bin_dir, prog_args, base, is_asan, is_crash, round)
    Worker.start_all()

# --------------------------------------------------------------------------------------------
def copy_results(round, results_dst_dir = ''):
  if results_dst_dir == '':
    results_dst_dir = '/results/log/%d' % (round)
  if not os.path.exists(results_dst_dir):
    os.system('mkdir -p %s' % (results_dst_dir))
  os.system("find /binary/ffafl/ -name '*.cov' -exec mv {} %s \;" % (results_dst_dir))
  os.system("find /binary/ffafl/ -name '*.reach' -exec mv {} %s \;" % (results_dst_dir))
  os.system("find /binary/ffafl/ -name '*.san' -exec mv {} %s \;" % (results_dst_dir))

# --------------------------------------------------------------------------------------------
def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-c", help="configure file to run all")
  parser.add_argument("-b", help="base dir")
  parser.add_argument("-r", help="round of results")
  parser.add_argument("-d", help="destnation of results folder")
  args = parser.parse_args()
  load_config_and_exec(args.b, args.c, int(args.r))
  copy_results(int(args.r), results_dst_dir = args.d)

# --------------------------------------------------------------------------------------------
def main_once():
    """"""
    # logging.basicConfig(level=logging.NOTSET,
    #                     format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
    # binary_path, binary_args, base_dir, san, crash, debug_mode
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help="base dir with results")
    parser.add_argument("-b", help="FishFuzz instrumented binary")
    parser.add_argument("-a", help="argument program use", default="@@")
    parser.add_argument('--asan', action='store_true')
    parser.add_argument('--ubsan', dest='asan', action='store_false')
    parser.set_defaults(asan=True)
    parser.add_argument('--crash', action='store_true')
    parser.add_argument('--queue', dest='crash', action='store_false')
    parser.set_defaults(crash=False)
    args = parser.parse_args()
    Worker = AnalysisOneResults(args.b, args.a, args.i, args.asan, args.crash)
    Worker.start_all()

# --------------------------------------------------------------------------------------------
if __name__ == "__main__":
  main()



# --------------------------------------------------------------------------------------------
'''
demo usage for main_once

python3 analysis.py -i $PWD/djpeg/ -b $PWD/djpeg/djpeg -a "@@" --ubsan --queue
python3 analysis.py -i $PWD/binutils -b $PWD/binutils/nm-new -a "-C @@" --asan --crash

python3 analysis.py -b /results -c asan.json

import json
data = {}
benchmark_list = ['djpeg', 'jasper', 'objdump', 'readelf', 'tcpdump', 'tiff2pdf', 'tiff2ps', 'xmllint']
data['prog_driver'] = benchmark_list
data['prog_args'] = {"djpeg" : " ", "jasper" : "-f @@ -T pnm", "objdump" : "-D @@", "readelf" : "-A @@", 
                      "tcpdump" : "-evnnnr @@", "tiff2pdf" : "@@", "tiff2ps" : "@@", "xmllint" : "@@"}
data['is_asan'] = False
data['is_crash'] = False
with open('ubsan.queue.json', 'w') as f:
  json.dump(data, f)


'''
