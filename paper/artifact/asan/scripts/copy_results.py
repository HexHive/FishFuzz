#!/usr/bin/python3


import os
import subprocess 
import argparse
import shutil

fuzzer_list = ['ffafl', 'ffapp', 'afl', 'aflpp']
benchmark_list = ['catdoc', 'exiv2', 'flvmeta', 'lou_checktable', 'MP4Box', 'nasm', 'nm-new', 'tcpdump', 'tcpprep', 'tiff2pdf', 'gif2tga']

def copy_fuzzer_to_dst(base_run_dir, base_save_dir, fuzzer_name, benchmark_name, n_trials):
  src_results_dir = '%s/out/%s/%s' % (base_run_dir, benchmark_name, fuzzer_name) 
  proc = subprocess.Popen(('find %s -name queue' % (src_results_dir)).split() ,stdout=subprocess.PIPE)
  line = proc.stdout.readline() 
  src_results_queue = line.rstrip().decode('utf-8')
  proc = subprocess.Popen(('find %s -name crashes' % (src_results_dir)).split() ,stdout=subprocess.PIPE)
  line = proc.stdout.readline() 
  src_results_crashes = line.rstrip().decode('utf-8')
  proc = subprocess.Popen(('find %s -name plot_data' % (src_results_dir)).split() ,stdout=subprocess.PIPE)
  line = proc.stdout.readline() 
  src_results_plot = line.rstrip().decode('utf-8')
  if src_results_queue == '' or src_results_crashes == '':
    print ('Skip %s-%s' % (fuzzer_name, benchmark_name))
    return 
  dst_results_dir = '%s/%s/%s/%d' % (base_save_dir, fuzzer_name, benchmark_name, n_trials)
  dst_results_crashes = '%s/crashes' % (dst_results_dir)
  dst_results_queue = '%s/queue' % (dst_results_dir)
  if not os.path.exists(dst_results_dir):
    os.makedirs(dst_results_dir)
  if os.path.exists(dst_results_crashes) or os.path.exists(dst_results_queue):
    print ('queue or crashes in %s already exits!')
    exit(0)
  print ('Copying from %s to %s' % (src_results_dir, dst_results_dir))
  shutil.move(src_results_crashes, dst_results_crashes)
  shutil.move(src_results_queue, dst_results_queue)

  
def copy_all_results(base_run_dir, base_save_dir, n_trials = 0):
  for fuzzer in fuzzer_list:
    for benchmark in benchmark_list:
      copy_fuzzer_to_dst(base_run_dir, base_save_dir, fuzzer, benchmark, n_trials)


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-s", help="src dir that has evaluation results")
  parser.add_argument("-d", help="dst dir to store the results")
  parser.add_argument("-r", help="current is n-th round")
  args = parser.parse_args()
  copy_all_results(args.s, args.d, int(args.r))