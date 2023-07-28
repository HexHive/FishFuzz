#!/usr/bin/python3

# Written by Zheng Han <kdsjzh@gmail.com>

import os
import json
import argparse


fuzzer_list = ['afl', 'aflpp', 'ffafl', 'ffapp']
benchmark_list = ['catdoc', 'exiv2', 'flvmeta', 'lou_checktable', 'MP4Box', 'nasm', 'nm-new', 'tcpdump', 'tcpprep', 'tiff2pdf', 'gif2tga']

def plot_program_avg(base, prog, timeout, type = 'cov', round = 0):
  data = {}
  fuzzer_list = []
  for r in range(round + 1):
    with open('%s/%d/%s.%s' % (base, r, prog, type)) as f:
      data[r] = json.load(f)
      if len(fuzzer_list) == 0:
        fuzzer_list = list(data[r].keys())
  print ('%12s\t' % prog, end = '')
  for fuzzer in fuzzer_list:
    total_cov = 0
    for r in range(round + 1):
      for time in data[r][fuzzer]:
        if int(time) / 3600 / 1000 < timeout:
          total_cov += len(data[r][fuzzer][time])
    print ('%12.2f\t' % (total_cov / (round + 1)), end = '')
  print ('')

def plot_program_one(base, prog, timeout, type = 'cov', round = 0):
  with open('%s/%d/%s.%s' % (base, round, prog, type)) as f:
    data = json.load(f)
  print ('%12s\t' % prog, end = '')
  for fuzzer in data:
    cov = 0
    for time in data[fuzzer]:
      if int(time) / 3600 / 1000 < timeout:
        cov += len(data[fuzzer][time])
    print ('%12.2f\t' % (cov), end = '')
  print ('')

def plot_all_cov(base, timeout = 24, round = 0, is_avg = False):
  print ('------------------------------------[cov]------------------------------------')
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    if is_avg:
      plot_program_avg(base, prog, timeout, type = 'cov', round = round)
    else:
      plot_program_one(base, prog, timeout, type = 'cov', round = round)

def plot_all_reach(base, timeout = 24, round = 0, is_avg = False):
  print ('-----------------------------------[reach]-----------------------------------')
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    if is_avg:
      plot_program_avg(base, prog, timeout, type = 'reach', round = round)
    else:
      plot_program_one(base, prog, timeout, type = 'reach', round = round)

def plot_program_vuln_one(base, prog, timeout, round = 0):
  print ('%12s\t' % prog, end = '')
  with open('%s/%d/%s.san' % (base, round, prog)) as f:
    data = json.load(f)
    for fuzzer in data:
      vuln = 0
      for time in data[fuzzer]:
        if int(time) / 3600 / 1000 < timeout:
          vuln += 1
      print ('%12d\t' % vuln, end = '')
    print ('')

def plot_program_vuln_avg(base, prog, timeout, round = 0):
  data = {}
  fuzzer_list = []
  for r in range(round + 1):
    with open('%s/%d/%s.san' % (base, round, prog)) as f:
      data[r] = json.load(f)
      if len(fuzzer_list) == 0:
        fuzzer_list = list(data[r].keys())
  print ('%12s\t' % prog, end = '')
  for fuzzer in fuzzer_list:
    total_vuln = 0
    for r in range(round + 1):
      for time in data[r][fuzzer]:
        if int(time) / 3600 / 1000 < timeout:
          total_vuln += 1
    print ('%12.2f\t' % (total_vuln / (round + 1)), end = '')
  print ('')


def plot_all_vuln(base, timeout = 24, round = 0, is_avg = False):
  print ('------------------------------------[bug]------------------------------------')
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    if is_avg:
      plot_program_vuln_avg(base, prog, timeout, round = round)
    else:
      plot_program_vuln_one(base, prog, timeout, round = round)


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to read the results")
  parser.add_argument("-r", help="round of results")
  parser.add_argument('--avg', action='store_true')
  parser.set_defaults(avg=False)
  parser.add_argument("-t", type=str, default = 'all', help="type of report, have 4 options: bug, cov, reach and all")
  args = parser.parse_args()
  if args.t == "bug":
    plot_all_vuln(args.b, timeout = 24, round = int(args.r), is_avg = args.avg)
  elif args.t == "cov":
    plot_all_cov(args.b, timeout = 24, round = int(args.r), is_avg = args.avg)
  elif args.t == "reach":
    plot_all_reach(args.b, timeout = 24, round = int(args.r), is_avg = args.avg)
  elif args.t == "all":
    plot_all_cov(args.b, timeout = 24, round = int(args.r), is_avg = args.avg)
    plot_all_reach(args.b, timeout = 24, round = int(args.r), is_avg = args.avg)
    plot_all_vuln(args.b, timeout = 24, round = int(args.r), is_avg = args.avg)
  else :
    print ("[ERROR] unknow type!")
    exit(-1)
  