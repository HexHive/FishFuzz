#!/usr/bin/env python3
"""
Construct initial CFG/CG distance, enableling further dynamic distance calculation.
"""
import argparse
import multiprocessing as mp
from argparse import ArgumentTypeError as ArgTypeErr
from pathlib import Path, PosixPath
from concurrent.futures import ThreadPoolExecutor
import subprocess
import os


PROJ_ROOT = Path(__file__).resolve().parent.parent
DIST_BIN = PROJ_ROOT / "dyncfg/dis_calc"


def calculate_cfg_distance_from_file(cfg: Path):
  prog = DIST_BIN
  dot_path = str(cfg)[:str(cfg).rfind('/')]
  tmp_path = dot_path[:dot_path.rfind('/')]
  obj = str(cfg)[str(cfg).rfind('/') + 1:]
  # out_cfg = cfg.replace('dot-files', 'runtimes')
  out_cfg = tmp_path + '/runtimes/' + obj
  cmd = [prog,
         "-t", tmp_path,
         "-m", "cfg",
         "-d", cfg,
         "-o", out_cfg]
  pipe = subprocess.PIPE
  # print (cmd)
  try:
    r = subprocess.run(cmd, stdout=pipe, stderr=pipe, check=True)
  except :
    print ("Failed execute cfg %s!" % cfg)
    exit(0)

def calculate_cg_distance_from_file(cg: Path):
  prog = DIST_BIN
  dot_path = str(cg)[:str(cg).rfind('/')]
  tmp_path = dot_path[:dot_path.rfind('/')]
  obj = str(cg)[str(cg).rfind('/') + 1:]
  # out_cfg = cfg.replace('dot-files', 'runtimes')
  out_cfg = tmp_path + '/runtimes/' + obj
  out_map = tmp_path + '/runtimes/' + 'callmap.json'
  cmd = [prog,
         "-t", tmp_path,
         "-m", "cg",
         "-d", cg,
         "-o", out_cfg,
         "-a", out_map]
  pipe = subprocess.PIPE
  try:
    r = subprocess.run(cmd, stdout=pipe, stderr=pipe, check=True)
  except :
    print ("Failed execute cg %s!" % cg)
    exit(0)

# -- Argparse --
def is_path_to_dir(path):
    """Returns Path object when path is an existing directory"""
    p = Path(path)
    if not p.exists():
        raise ArgTypeErr("path doesn't exist")
    if not p.is_dir():
        raise ArgTypeErr("not a directory")
    return p
# ----


def main():
    global STEP
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("temporary_directory", metavar="temporary-directory",
                        type=is_path_to_dir,
                        help="Directory where dot files and target files are "
                             "located")
    args = parser.parse_args()

    dot_dir = args.temporary_directory / "dot-files"
    runtime_dir = args.temporary_directory / "runtimes"
    if not Path(runtime_dir).exists() :
      os.system("mkdir " + str(runtime_dir))
    ## step 1, initialized cfg distance and save to runtime_dir
    print ('Trying to initialized cfg...')
    # for cfg in list(dot_dir.glob("cfg.*.*.*.dot")):
    #   calculate_cfg_distance_from_file(cfg)
    with ThreadPoolExecutor(max_workers=mp.cpu_count()) as executor:
      results = executor.map(calculate_cfg_distance_from_file,
                              dot_dir.glob("cfg.*.dot"))
                              #  dot_dir.glob("cfg.*.*.*.dot"))
    
    print ('Trying to initialized callgraph...')
    calculate_cg_distance_from_file(dot_dir / "callgraph.dot")


if __name__ == "__main__":
  main()

