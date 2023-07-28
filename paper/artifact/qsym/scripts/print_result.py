#!/usr/bin/python3

# Written by Zheng Han <kdsjzh@gmail.com>

import os
import json
import argparse


fuzzer_list = ['afl', 'ffafl']
benchmark_list = ['djpeg', 'jasper', 'objdump', 'readelf', 'tcpdump', 'tiff2pdf', 'tiff2ps', 'xmllint']

def plot_program_cov(base, prog, timeout):
  with open('%s/%s.cov' % (base, prog)) as f:
    data = json.load(f)
  print ('%12s\t' % prog, end = '')
  for fuzzer in data:
    cov = 0
    for time in data[fuzzer]:
      if int(time) / 3600 / 1000 < timeout:
        cov += len(data[fuzzer][time])
    print ('%12d\t' % cov, end = '')
  print ('')

def plot_all_cov(base, timeout = 24):
  print ('------------------------------------[cov]------------------------------------')
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    plot_program_cov(base, prog, timeout)

def plot_program_san(base, prog, timeout):
  with open('%s/%s.san' % (base, prog)) as f:
    data = json.load(f)
  print ('%12s\t' % prog, end = '')
  for fuzzer in data:
    cov = 0
    for time in data[fuzzer]:
      if int(time) / 3600 / 1000 < timeout:
        cov += len(data[fuzzer][time])
    print ('%12d\t' % cov, end = '')
  print ('')

def plot_all_san(base, timeout = 24):
  print ('------------------------------------[bug]------------------------------------')
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    plot_program_san(base, prog, timeout)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to read the results")
  parser.add_argument("-t", type=str, default = 'all', help="type of report, have 3 options: bug, cov and all")
  args = parser.parse_args()
  if args.t == "bug":
    plot_all_san(args.b, timeout = 24)
  elif args.t == "cov":
    plot_all_cov(args.b, timeout = 24)
  elif args.t == "all":
    plot_all_cov(args.b, timeout = 24)
    plot_all_san(args.b, timeout = 24)
  else :
    print ("[ERROR] unknow type!")
    exit(-1)
  