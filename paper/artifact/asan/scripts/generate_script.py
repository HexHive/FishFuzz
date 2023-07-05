#!/usr/bin/python3

import os
import argparse


data = [
    #id, prog, commandline, seed_folder
    [1,"nm-new","-C @@","elf"],
    [2,"catdoc","@@","doc"],
    [3,"exiv2","@@","png"],
    [4,"flvmeta","@@","flv"],
    [5,"MP4Box","-diso @@","mp4"],
    [6,"lou_checktable","@@","font"],
    [7,"tiff2pdf","@@","tiff"], 
    [8,"nasm","-o nasm.out @@","asm"],
    [9,"gif2tga","@@","gif"],
    [10,"tcpdump","-evnnnr @@","pcap"],
    [11,"tcpprep","--auto=bridge --pcap=@@ --cachefile=/dev/null","pcap"]
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