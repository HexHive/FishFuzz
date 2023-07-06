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

In this step, we build the image from an empty ubuntu image, install all fuzzers along with the required runtime packages and compile the programs to fuzz.
```
docker build -t fishfuzz:artifact .
```
Step 2: generated the script to fuzz.

In this step, we generate the scripts that are used to start the fuzzing campaigns, which will be set as the entry point when we start the docker container.
```
python scripts/generate_script.py -b "$PWD/runtime/fuzz_script"
```

Step 3: generate the commands to run evaluation. 

This script will automatically generate the command you need to execute to start the fuzzing campain, copy-paste them to the shell to start the campaign.

```
python3 scripts/generate_runtime.py -b "$PWD/runtime"

docker run -dt -v current_dir:/work --name ffafl_cflow --cpuset-cpus 0 --user $(id -u $(whoami)) --privileged fishfuzz:artifact "/work/fuzz_script/ffafl/cflow.sh" 
....
```

Step 4: Manually stop the container and generate the coverage report.

for two-stage and ubsan, stop after 24h, for ASan, use 60h as timeout. 

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

## Results Explaination

The primary metrics for the evaluation are the coverage and number of unique bugs. So in the report we generate the number of edges and unique bugs (for ubsan, unique sanitizer triggered) found by all the fuzzers. 

A 24h sample report looks like below:

```
python3 scripts/print_result.py -b /results/log/0/

root@d0ffb6c3dc67:/# python3 scripts/print_result.py -b /results/log/0/
                         afl           aflpp           ffafl           ffapp
      ...
      MP4Box            8720            7927            9798            8449
      ...
      MP4Box               7               7              19               9

```

This report consists of edge coverage report of each program-fuzzer pair and number of bugs found by fuzzers.

For instance, the AFL find 8720 edges in MP4Box while FF_AFL find 9798. FF_AFL++ find 8449 edges, which is 6.67% more than AFL++. And the number of unique bugs are also listed, e.g., FF_AFL find 19 unique bugs while AFL only find 7.

Note: 
  1) We only do stack-trace based deduplication for unique bugs, which might still have duplicated bugs and require manual triaging. In the paper we manual triaging the bugs so the number are more precise.
  2) For UBSan bugs, usually ubsan allert are not considered as bugs, therefore the bugs in UBSan are "unique triggered sanitizers" but not "unique bugs"

Our Claim: we claim that, in most of the programs, FishFuzz can improve the coverage and bug finding capability of the original fuzzer, which means, FF_AFL/FF_AFL++ should performs better than AFL/AFL++ in general. As indicated in Section 6.5 in the paper, the performance of FishFuzz variant can depends on the original fuzzer.





## Resouces Estimation

The docker build process will takes approximate 1.5h in our machine (Xeon Gold 5218 CPU (22M Cache, 2.30 GHz)),
the two-stage evaluation process will takes 24h and the analysis script will run for about 20mins.

Disk space required is ~50GB, and the required runtime memory is 16GB.

