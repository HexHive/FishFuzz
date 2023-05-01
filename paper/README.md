## Additional materials


Due to the page limitation, we didn't include the raw data for hyperparameter
study and all 10 rounds coverage/reach information in the paper.
In this folder, we attached the raw coverage/reach data along with the 
script for p-value calculation.

In folder `p-value`, we include the raw coverage/reach/bug data in csv format,
and script p-val-calc.py allows calcuate p-value based on FF_AFL or FF_AFL++. 
We use scipy 1.10.0 and as indicated by the [maintainer](https://github.com/scipy/scipy/issues/17821)
, different version of scipy
might approximate differently, therefore can results in different p-values.

Regarding the hyperparameter study, the raw data could be found in folder `hyperparam`,
we only briefly summarized the best vs worst results in the appendix.

In folder `vuln`, we attached a full list of bugs and CVEs FishFuzz found.

In folder `artifact`, we attached the dockerfile and the script to reproduce our evaluation results (todo).

In folder `fuzzbench`, we include an experimental configuration for fuzzbench, to build it locally, copy the FF_AFL to that folder.