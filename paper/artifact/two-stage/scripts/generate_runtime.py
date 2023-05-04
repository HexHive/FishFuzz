#!/usr/bin/python3


import os
import subprocess 
import argparse
import multiprocessing as mp
from argparse import ArgumentTypeError as ArgTypeErr

fuzzer_list = ['ffafl', 'ffapp', 'afl', 'aflpp']
benchmark_list = ['cflow', 'cxxfilt', 'w3m', 'mujs', 'mutool', 'tic', 'dwarfdump']


def construct_docker_cmd(base_run_dir, fuzzer_name, benchmark_name, bind_cpu_id, timeout_h = 24):
  docker_cmd = 'docker run -dt ' 
  docker_cmd += '-v %s:%s ' % (base_run_dir, "/work")
  docker_cmd += '--name %s_%s ' % (fuzzer_name, benchmark_name)
  docker_cmd += '--cpuset-cpus %d ' % (bind_cpu_id)
  # make sure current user have access to shared dir without root privilage
  docker_cmd += '--user $(id -u $(whoami)) --privileged '
  # docker_cmd += '--stop-timeout %d ' % (timeout_h * 3600)
  docker_cmd += 'fishfuzz:artifact '
  docker_cmd += '"/work/fuzz_script/%s/%s.sh"' % (fuzzer_name, benchmark_name)
  return docker_cmd

def docker_run_all_trial(base_run_dir):
  # assuming all cpus are free
  # for cpuid in range(max_workers=mp.cpu_count()):\
  cpuid = 0
  for benchmark in benchmark_list:
    for fuzzer in fuzzer_list:
      if cpuid < mp.cpu_count():
        docker_cmd = construct_docker_cmd(base_run_dir, fuzzer, benchmark, cpuid)
        # replace with subprocess.run later
        print (docker_cmd)
        cpuid += 1

def check_out_dir(base_run_dir):
  base_out_dir = '%s/out' % (base_run_dir)
  if not os.path.isdir(base_out_dir):
    os.mkdir(base_out_dir)
  for prog in benchmark_list:
    prog_out_dir = '%s/%s' % (base_out_dir, prog)
    if not os.path.isdir(prog_out_dir):
      os.mkdir(prog_out_dir)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to share the evaluation results ")
  args = parser.parse_args()
  check_out_dir(args.c)
  docker_run_all_trial(args.b)
