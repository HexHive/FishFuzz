#!/usr/bin/python3

import os
import argparse


data = [
    #id, prog, commandline, seed_folder
    [1,"tic","@@","txt"],
    [2,"cflow","@@","c"],
    [3,"mujs","@@","js"],
    [4,"mutool","poster @@","pdf"],
    [5,"w3m","-dump @@","html"],
    [6,"cxxfilt","-t","elf"],
    [7,"dwarfdump","-vv -a @@","elf"]
]

fuzzer_name = {'afl' : 'AFL', 'aflpp' : 'AFL++', 'ffafl' : 'FishFuzz', 'ffapp' : 'Fish++'}


def write_script(fuzzer, dir, with_dflag = '-D'):
  if not os.path.exists(dir):
    os.mkdir(dir)
  for item in data:
    id, prog, args, seed_folder = item
    with open('%s/%s.sh' % (dir, prog), 'w') as f:
      f.write("#!/bin/sh\n")
      cmd = "AFL_NO_AFFINITY=1 AFL_SKIP_CRASHES=1 /%s/afl-fuzz -i /work/corpus/%s -o /work/out/%s/%s -m none -t 1000+ %s -- /binary/%s/%s %s\n" \
            % (fuzzer_name[fuzzer], seed_folder, prog, fuzzer, with_dflag, fuzzer, prog, args)
      if fuzzer in ['ffafl', 'ffapp']:
        tmp_env = "TMP_DIR=/binary/%s/TEMP_%s " % (fuzzer, prog)
        cmd = tmp_env + cmd
      if prog == 'tic':
        tmp_env = "service cron start\ncrontab /work/fuzz_script/clear_terminfo.cron\n"
        cmd = tmp_env + cmd
      f.write(cmd)
  os.system('chmod +x %s/*.sh' % (dir))

def write_all(base_dir):
  if not os.path.isdir(base_dir):
    os.system('mkdir %s' % base_dir)
  write_script('ffafl', base_dir + '/ffafl', with_dflag = '')
  write_script('afl', base_dir + '/afl', with_dflag = '')
  # we enable deterministic stage for all fuzzers
  write_script('ffapp', base_dir + '/ffapp', with_dflag = '-D')
  write_script('aflpp', base_dir + '/aflpp', with_dflag = '-D')
  with open('%s/clear_terminfo.cron' % (base_dir), 'w') as f:
    f.write('* * * * * rm -r /usr/share/terminfo/*\n')

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to generate the fuzz script")
  args = parser.parse_args()
  write_all(args.b)