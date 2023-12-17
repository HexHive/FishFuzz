#!/usr/bin/python3

"""
  This script is designed to map the module:function name to specific callgraph node and it's function id
  As we may know, an source package might contains lots of executable, which means there are lots of function with same name 
  in different module (e.g., in binutils, readelf/cxxfilt/nm-new/... all have main functions), we need to match them with 
  a unique function id we assigned (in the modified llvm pipeline pass) 
  Not sure if different modules may have duplicate node name, in our testing, seems all node ids are unique
"""

import argparse
import networkx as nx
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
  'node' : '.node2id.txt'
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
  fid_list = [remove_prefix(mname, "fid") for mname in os.listdir(base_dir + "/fid")]
  cg_list = [remove_prefix(mname, "cg") for mname in os.listdir(base_dir + "/cg")]
  overlap_list = list(set(fid_list) & set(cg_list))
  return [file_name for file_name in overlap_list if file_name]

def parse_fid_log(fid_name):
  fname2id = dict()
  with open(fid_name) as f:
    for line in f:
      fname, id_str = line.strip('\n').split(',')
      fname2id[fname] = int(id_str)
  return fname2id

def parse_cg_log(cg_name):
  cg = nx.DiGraph(nx.nx_pydot.read_dot(cg_name))
  cg_nodes = dict(cg.nodes(data="label", default=''))
  node2fname = dict()
  for node_name in cg_nodes:
    if not __is_valid_nodename(node_name):
      continue 
    fname = __parse_labelname(cg_nodes[node_name])
    if fname == '':
      continue
    node2fname[node_name] = fname
  return node2fname

##################################
# Main Working Functions
##################################

'''
  We only match function node name with fid within one module
'''
def match_node_with_fid(base_dir, module_name):
  node2fname = parse_cg_log('%s/cg/%s%s' % (base_dir, module_name, __prefix_name['cg']))
  fname2id = parse_fid_log('%s/fid/%s%s' % (base_dir, module_name, __prefix_name['fid']))
  node2id = dict()
  for node in node2fname:
    if node2fname[node] in fname2id:
      node2id[node] = fname2id[node2fname[node]]
  return node2id

def dump_node_id(base_dir, module_name, node2id):
  if node2id == dict():
    return 
  if not os.path.isdir("%s/node" % (base_dir)):
    os.mkdir("%s/node" % (base_dir))
  with open("%s/node/%s%s" % (base_dir, module_name, __prefix_name['node']), 'w') as f:
    for node in node2id:
      f.write('%s,%s\n' % (node, node2id[node]))

##################################
# Testing Functions
##################################

'''
  Not sure if llvm will assign duplicate node name accross the modules
'''

def test_duplicate(node_dir):
  print ("[*] Testing if llvm assign duplciate node name...")
  allnode2id = dict()
  duplicate_counter = 0
  for node_file in os.listdir(node_dir):
    mname = remove_prefix(node_file, "node")
    with open("%s/%s" % (node_dir, node_file)) as f:
      for line in f:
        node_name, id_str = line.strip('\n').split(',')
        if node_name not in allnode2id:
          allnode2id[node_name] = id_str
        else:
          duplicate_counter += 1
  print ("[+] Among %d modules, we find %d/%d nodes has duplicate names!" % ( \
        len(os.listdir(node_dir)), duplicate_counter, len(allnode2id)))
  return allnode2id

def main():
  parser = argparse.ArgumentParser ()
  parser.add_argument ('-i', type=str, required=True, help="Path to base directory containing cg, fid subdirectory.")
  args = parser.parse_args()
  # build a cg node to function id vector
  module2node = dict()
  for module_name in check_file_list(args.i):
    print ("[*] Working with %s..." % (module_name))
    node2id = match_node_with_fid(args.i, module_name)
    dump_node_id(args.i, module_name, node2id)
  print ("[+] Dump all matched Node ID to Function ID")
  allnode2id = test_duplicate("%s/node" % (args.i))
  with open("%s/funcnode.csv" % (args.i), 'w') as f:
    for node in allnode2id:
      f.write("%s,%s\n" % (node, allnode2id[node]))
  


if __name__ == "__main__":
  main()

