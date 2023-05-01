#!/usr/bin/python3

import csv 
import os
from scipy.stats import mannwhitneyu
import argparse

fuzzer_idx_all = {'two_stage': {'FishFuzz' : 1, 'AFLFast' : 11, 'FairFuzz' : 21, 'EcoFuzz' : 31, 'KScheduler' : 41, 'AFL++' : 51, 'Fish++' : 61, 'AFL': 71}, \
                  'ubsan': {'FishFuzz' : 1, 'Fish++' : 11, 'SAVIOR' : 21, 'AFL++' : 31, 'AFL' : 41}, \
                  'asan': {'FishFuzz' : 1, 'AFL++' : 11, 'TortoiseFuzz' : 21, 'ParmeSan' : 31, 'Fish++' : 41, 'AFL' : 51}}
start_row = 2
round = 10

def read_csv(csv_name, type):
  data = {}
  for f in fuzzer_idx_all[type].keys():
    data[f] = {}
  rcnt = 0
  prog_list = []
  with open(csv_name) as csvfile:
    creader = csv.reader(csvfile)
    for row in creader:
      if rcnt < start_row:
        rcnt += 1
        continue
      prog = row[0]
      if prog not in prog_list:
        prog_list.append(prog)
      for f in fuzzer_idx_all[type].keys():
        data[f][prog] = [int(d) for d in row[fuzzer_idx_all[type][f]: fuzzer_idx_all[type][f] + round]]
  return data, prog_list

def calc_pval(data, prog_list, base_fuzzer, type):
  p_val_list = {}
  for prog in prog_list:
    if prog not in p_val_list:
      p_val_list[prog] = []
    for fuzzer in fuzzer_idx_all[type].keys():
      if fuzzer != base_fuzzer:
        stat, pval = mannwhitneyu(data[base_fuzzer][prog], data[fuzzer][prog])
        p_val_list[prog].append(pval)
      else:
        p_val_list[prog].append(1)
  return p_val_list

def calc_and_print(csv_name, base_fuzzer, type):
  data, prog_list = read_csv(csv_name, type)
  p_val_list = calc_pval(data, prog_list, base_fuzzer, type)
  # ----------------- printing stuffs ----------------
  print ('%12s' % (''), end = '')
  for fuzzer in fuzzer_idx_all[type].keys():
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
  parser.add_argument("-d", help="data file to parse")
  parser.add_argument("-t", help="type of sanitizer")
  parser.add_argument("-b", help="base fuzzer", default ="Fish++")
  args = parser.parse_args()
  calc_and_print(args.d, args.b, args.t)


if __name__ == "__main__":
  main()
