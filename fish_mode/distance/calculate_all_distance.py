#!/usr/bin/python3

import networkx as nx
import argparse
import json
import os

__black_module_list = [
  'conftest'
]

__black_func_list = [
  '__asan',
  '__ubsan',
  '__lsan',
  '__sanitizer',
  'asan.',
  'llvm.', 
  'sancov.'
]

__prefix_name = {
  'fid': '.fid.txt',
  'cg' : '.callgraph.dot',
  'node' : '.node2id.txt',
  'dist' : '.calldst.json'
}

##################################
# Name Parsing Functions
##################################

def __is_black_listed_module(module_name):
  for __black_module in __black_module_list:
    if module_name.startswith(__black_module):
      return 1
  return 0

def __is_black_listed_func(func_name):
  for __black_func in __black_func_list:
    if func_name.startswith(__black_func):
      return 1
  if func_name == '':
    return 1
  return 0

def __is_valid_nodename(node_name):
  if node_name.startswith('Node0x'):
    return 1
  return 0

def __is_valid_labelname(label_name):
  if label_name[:2] == '"{' and \
     label_name[-2:] == '}"':
    return 1
  return 0

def __parse_labelname(label_name):
  if not __is_valid_labelname(label_name):
    return ''
  func_name = label_name[2:-2]
  if __is_black_listed_func(func_name):
    return ''
  return func_name

def remove_prefix(file_name, type_prefix):
  module_name = file_name[: - len(__prefix_name[type_prefix])]
  if __is_black_listed_module(module_name):
    return ''
  return module_name

##################################
# File Parsing Functions
##################################

def check_file_list(base_dir):
  node_list = [remove_prefix(mname, "node") for mname in os.listdir(base_dir + "/node")]
  cg_list = [remove_prefix(mname, "cg") for mname in os.listdir(base_dir + "/cg")]
  overlap_list = list(set(node_list) & set(cg_list))
  return [file_name for file_name in overlap_list if file_name]

def obtain_targ_list(fname):
  '''
    We only match within the module
  '''
  node_func_id = dict()
  with open(fname) as f:
    for line in f:
      node_name, func_id_str = line.strip('\n').split(',')
      node_func_id[node_name] = int(func_id_str)
  return node_func_id

def dump_module_dist(base_dir, module_name, module_calldst):
  if module_calldst == dict():
    return 
  if not os.path.isdir("%s/dist" % (base_dir)):
    os.mkdir("%s/dist" % (base_dir))
  with open("%s/dist/%s%s" % (base_dir, module_name, __prefix_name['dist']), 'w') as f:
    json.dump(module_calldst, f)

def merge_all_calldst(base_dir):
  all_calldst = dict()
  for filename in os.listdir(base_dir + "/dist"):
    with open("%s/dist/%s" % (base_dir, filename)) as f:
      module_calldst = json.load(f)
    for key, val in module_calldst.items():
      if key in all_calldst:
        print ('Collision: module %s, key %s' % (remove_prefix(filename, "dist"), key))
        # exit(-1)
      all_calldst[key] = val 
  with open("%s/calldst.json" % (base_dir), 'w') as f:
    json.dump(all_calldst, f)

##################################
# Working Functions
##################################
def calc_module_distance(cg, node_func_id):
  all_dist_pair = dict(nx.all_pairs_dijkstra_path_length(cg))
  # convert to calldst
  module_calldst = dict()
  for src in all_dist_pair:
    for dst in all_dist_pair[src]:
      if src not in node_func_id or \
         dst not in node_func_id or \
         src == dst:
        continue
      src_id = node_func_id[src]
      dst_id = node_func_id[dst]
      if dst_id not in module_calldst:
        module_calldst[dst_id] = dict()
      module_calldst[dst_id][src_id] = all_dist_pair[src][dst]
  return module_calldst


def main():
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-i', type=str, required=True, help="Path to Temporary directory.")
  args = parser.parse_args()
  for module_name in check_file_list(args.i):
    print ("[*] Distance Calculation for %s..." % (module_name))
    cg_name = '%s%s' % (module_name, __prefix_name['cg'])
    node_map_name = '%s%s' % (module_name, __prefix_name['node'])
    cg = nx.DiGraph(nx.nx_pydot.read_dot('%s/cg/%s' % (args.i, cg_name)))
    module_node_func_id = obtain_targ_list('%s/node/%s' % (args.i, node_map_name))
    module_calldst = calc_module_distance(cg, module_node_func_id)
    dump_module_dist(args.i, module_name, module_calldst)
  merge_all_calldst(args.i)
  print ("[+] Finish the module distance calculation.")


if __name__ == "__main__":
  main()