#!/usr/bin/python3

import os
import argparse


data = [
    #id, prog, commandline, seed_folder
    [1,"djpeg","","jpeg"],
    [2,"jasper","-f @@ -T pnm","jp2"],
    [3,"objdump","-D @@","elf"],
    [4,"readelf","-A @@","elf"],
    [5,"tcpdump","-evnnnr @@","pcap"],
    [6,"tiff2pdf","@@","tiff"],
    [7,"tiff2ps","@@","tiff"], 
    [8,"xmllint","@@","xml"]
]

fuzzer_name = {'afl' : 'AFL', 'ffafl' : 'FishFuzz'}


def write_script(fuzzer, dir, with_dflag = '-D'):
  if not os.path.exists(dir):
    os.mkdir(dir)
  for item in data:
    id, prog, args, seed_folder = item
    with open('%s/%s.sh' % (dir, prog), 'w') as f:
      f.write("#!/bin/sh\n")
      if fuzzer in ['ffafl']:
        f.write("sed -i 's/65536/344064/g' `ls /usr/local/lib/python2.7/dist-packages/qsym/minimizer.py`\n")
        f.write("sed -i 's/if name == \"README.txt\":/if name == \"README.txt\" or name == \"others\":/g' `ls /usr/local/lib/python2.7/dist-packages/qsym/afl.py`\n")
      cmd = "AFL_NO_AFFINITY=1 AFL_SKIP_CRASHES=1 /%s/afl-fuzz -M afl-master -i /work/corpus/%s -o /work/out/%s/%s -m none -t 1000+ %s -- /binary/%s/%s %s" \
            % (fuzzer_name[fuzzer], seed_folder, prog, fuzzer, with_dflag, fuzzer, prog, args)
      if fuzzer in ['ffafl', 'ffapp']:
        tmp_env = "TMP_DIR=/binary/%s/TEMP_%s " % (fuzzer, prog)
        cmd = tmp_env + cmd
      screen_cmd = 'screen -S fuzzer -dm bash -c "%s"\n' % (cmd)
      f.write(screen_cmd)
      cmd = "/workdir/qsym/bin/run_qsym_afl.py -a afl-master -o /work/out/%s/%s -n qsym -- /binary/vanilla/%s %s" % (prog, fuzzer, prog, args)
      f.write('sleep 3\n')
      screen_cmd = 'screen -S qsym -dm bash -c "%s"\n' % (cmd)
      f.write(screen_cmd)
      f.write('sleep 24h\n')
  os.system('chmod +x %s/*.sh' % (dir))

def write_all(base_dir):
  if not os.path.isdir(base_dir):
    os.system('mkdir %s' % base_dir)
  write_script('ffafl', base_dir + '/ffafl', with_dflag = '')
  write_script('afl', base_dir + '/afl', with_dflag = '')
  # we enable deterministic stage for all fuzzers
  # write_script('ffapp', base_dir + '/ffapp', with_dflag = '-D')
  # write_script('aflpp', base_dir + '/aflpp', with_dflag = '-D')
  # with open('%s/clear_terminfo.cron' % (base_dir), 'w') as f:
    # f.write('* * * * * rm -r /usr/share/terminfo/*\n')

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-b", help="basedir to generate the fuzz script")
  args = parser.parse_args()
  write_all(args.b)