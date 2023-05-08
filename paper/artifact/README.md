## Artifact Evaluation

In FishFuzz we conduct 4 set of evaluation, here we provide the script to reproduce Two-Stage fuzzer evaluation.
This directory consist (1) dockerfile to build one image with *all* fuzzers and target programs (2) 
minimized initial corpus that we used for evaluation. (3) script that start all fuzzing campaign automatically 
(4) script to re-organize results folder and analysis the time2cov and time2bug. The time2bug might still need manual deduplication.

Initial seed corpus can be found in `$PWD/runtime/corpus`. The script provided will create scripts for each container to run in `$PWD/runtime/fuzz_script`, and campaign results will be write to `$PWD/runtime/out`.

[Tips & CheckList](https://secartifacts.github.io/usenixsec2023/tips)

## Testing Enviroment

In evaluation, we use ubuntu 18.04 and clang-12, all FF programs are compiled manually but not through wrapper. 

All experiments are performed on a Xeon Gold 5218 CPU (22M Cache, 2.30 GHz) equipped with 64GB of memory.

We create one docker container for each fuzzer-benchmark pair and assign one core for each container.

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
sudo chown -R $(id -u):$(id -g) runtime/out

# copy evaluation results to results folder
mkdir results/
python3 scripts/copy_results.py -s "$PWD/runtime" -d "$PWD/results/" -r 0

# create a new container and copy the results inside,
docker run -it --name validate fishfuzz:artifact bash

# copy results/ and scripts/ to validate:/, the following steps are done in container
apt update && apt install python3-pip -y && pip3 install progress

# delete redundant files
find /results -name README.txt -exec rm {} \;
find /results -name .state -exec rm -r {} \;
find /results -name others -exec rm -r {} \;

# run analysis
python3 scripts/analysis.py -b /results -c scripts/asan.queue.json -r 0
python3 scripts/analysis.py -b /results -c scripts/asan.crash.json -r 0

# plot the results, bug report might need further triaging 
python3 scripts/print_result.py -b /results/log/0/

```

## Resouces Estimation

The docker build process will takes approximate 1.5h in our machine (Xeon Gold 5218 CPU (22M Cache, 2.30 GHz)),
the evaluation process will takes 24h and the analysis script will run for about 20mins.

Disk space required is ~50GB, and the required runtime memory is 16GB.

