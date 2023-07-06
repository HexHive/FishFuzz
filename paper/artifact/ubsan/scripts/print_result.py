#!/usr/bin/python3

# Written by Zheng Han <kdsjzh@gmail.com>

import os
import json
import argparse


fuzzer_list = ['afl', 'aflpp', 'ffafl', 'ffapp']
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
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    plot_program_cov(base, prog, timeout)

def plot_all_vuln(base, timeout):
  print ('%12s\t' % '', end = '')
  for fuzzer in fuzzer_list:
    print ('%12s\t' % fuzzer, end = '')
  print ('')
  for prog in benchmark_list:
    print ('%12s\t' % prog, end = '')
    with open('%s/%s.san' % (base, prog)) as f:
      data = json.load(f)
      for fuzzer in data:
        vuln = 0
        for time in data[fuzzer]:
          if int(time) / 3600 / 1000 < timeout:
            vuln += 1
        print ('%12d\t' % vuln, end = '')
      print ('')


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to read the results")
  args = parser.parse_args()
  plot_all_cov(args.b, timeout = 24)
  plot_all_vuln(args.b, timeout = 24)