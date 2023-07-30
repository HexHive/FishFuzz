#!/usr/bin/python3

import json
import os
from scipy.stats import mannwhitneyu
import argparse

fuzzer_list = ['afl', 'aflpp', 'ffafl', 'ffapp']
benchmark_list = ['djpeg', 'jasper', 'objdump', 'readelf', 'tcpdump', 'tiff2pdf', 'tiff2ps', 'xmllint']

def parse_report(base_dir, round, type, timeout = 24):
  report_data = {}
  data = {}
  for fuzzer in fuzzer_list:
    report_data[fuzzer] = {}
  for prog in benchmark_list:
    for r in range(round):
      with open('%s/%d/%s.%s' % (base_dir, r, prog, type)) as f:
        data[r] = json.load(f)
    for fuzzer in fuzzer_list:
      report_data[fuzzer][prog] = []
      for r in range(round):
        one_round_cov = 0
        for time in data[r][fuzzer]:
          if int(time) / 3600 / 1000 < timeout:
            one_round_cov += len(data[r][fuzzer][time])
        report_data[fuzzer][prog].append(one_round_cov)
  return report_data


def calc_pval(data, base_fuzzer):
  p_val_list = {}
  for prog in benchmark_list:
    if prog not in p_val_list:
      p_val_list[prog] = []
    for fuzzer in fuzzer_list:
      if fuzzer != base_fuzzer:
        stat, pval = mannwhitneyu(data[base_fuzzer][prog], data[fuzzer][prog])
        p_val_list[prog].append(pval)
      else:
        p_val_list[prog].append(1)
  return p_val_list

def calc_and_print(base_dir, round, base_fuzzer, type):
  data = parse_report(base_dir, round, type)
  p_val_list = calc_pval(data, base_fuzzer)
  # ----------------- printing stuffs ----------------
  print ('%12s' % (''), end = '')
  for fuzzer in fuzzer_list:
    print ('    %12s' % (fuzzer), end = '')
  print ()
  for prog in p_val_list:
    print ('%12s' % (prog), end = '')
    for pval in p_val_list[prog]:
      str_pval = '%.04f' % pval
      print ('    %12s' % (str_pval), end = '')
      #print (',%12s' % (str_pval), end = '')
    print ()

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to read the results")
  parser.add_argument("-r", help="round of results", default = "10")
  parser.add_argument("-f", help="base fuzzer, ffafl or ffapp", default ="ffapp")
  parser.add_argument("-t", help="type of data, can be reach/cov", default ="cov")
  args = parser.parse_args()
  calc_and_print(args.b, int(args.r), args.f, args.t)


if __name__ == "__main__":
  main()
