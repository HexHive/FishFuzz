## Artifact Evaluation

In FishFuzz we conduct 4 set of evaluation, here we provide the script to reproduce Two-Stage fuzzer evaluation.
This directory consist (1) dockerfile to build one image with *all* fuzzers and target programs (2) 
minimized initial corpus that we used for evaluation. (3) script that start all fuzzing campaign automatically 
(4) script to re-organize results folder and analysis the time2cov and time2bug. The time2bug might still need manual deduplication.

Initial seed corpus can be found in `$PWD/runtime/corpus`. The script provided will create scripts for each container to run in `$PWD/runtime/fuzz_script`, 
and campaign results will be write to `$PWD/runtime/out`.


## How to Start

Step 0: Step to two-stage dir (or maybe other dir if we plan to dockerize more evaluations) first :)

Step 1: Build docker image with all fuzzers and target
```
docker build -t fishfuzz:artifact .
```
Step 2: generated the script to fuzz
```
python scripts/generate_script.py -b "$PWD/runtime/fuzz_script"
```

Step 3: generate the commands to run evaluation. Given that two-stage evaluation will requires 7 * 4 cores to run, we only 
print the command. You could copy and run the command or prune the benchmarks/fuzzers as you wish.

```
python3 scripts/generate_runtime.py -b "$PWD/runtime"

docker run -dt -v current_dir:/work --name ffafl_cflow --cpuset-cpus 0 --user $(id -u $(whoami)) --privileged fishfuzz:artifact "/work/fuzz_script/ffafl/cflow.sh" 
....
```

Step 4: we didn't add kill in the script, so it's required to stop it manually after 24h. Copy and generate the coverage/bug report with the given scipts(todo).

```
docker rm -f $(docker ps -a -q -f "ancestor=fishfuzz:artifact")
# copy evaluation results to results folder
mkdir results/
python3 scripts/copy_results.py -s "$PWD/runtime" -d "$PWD/results/" -r 0
```
