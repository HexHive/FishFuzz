Full List of the Bugs found by FishFuzz prototype

| project       | driver                                                       | bug type                 | sanitizer | ref         | CVE            | benchmark    |
| ------------- | ------------------------------------------------------------ | ------------------------ | --------- | ----------- | -------------- | ------------ |
| libcaca       | img2txt                                                      | divide by zero           | asan      | issue_65    | CVE-2022-0856  | GREYONE      |
| liblouis      | lou_checktable                                               | global-buffer-overflow   | asan      | issue_1171  | CVE-2022-26981 | GREYONE      |
| liblouis      | lou_trace                                                    | out-of-bound read        | asan      | issue_1214  | CVE-2022-31783 | GREYONE      |
| libsixel      | img2sixel                                                    | reachable assertion      | asan      | issue_163   | CVE-2022-27938 | GREYONE      |
| ncurse        | tic                                                          | out-of-bound read        | asan      | mail list   | CVE-2022-29458 | GREYONE      |
| ncurse        | tic                                                          | heap-overflow            | asan      | mail list   | bug-only       | GREYONE      |
| tcpreplay     | tcprewrite                                                   | heap-overflow            | asan      | issue_718   | CVE-2022-27940 | TortoiseFuzz |
| tcpreplay     | tcprewrite                                                   | reachable assertion      | asan      | issue_717   | CVE-2022-27939 | TortoiseFuzz |
| tcpreplay     | tcpprep                                                      | heap-overflow            | asan      | issue_716   | CVE-2022-27941 | TortoiseFuzz |
| tcpreplay     | tcpprep                                                      | heap-overflow            | asan      | issue_719   | CVE-2022-27942 | TortoiseFuzz |
| gpac          | MP4Box                                                       | heap-overflow            | ubsan     | issue_2138  | CVE-2022-26967 | TortoiseFuzz |
| gpac          | MP4Box                                                       | heap-overflow            | asan      | issue_2173  | CVE-2022-29537 | TortoiseFuzz |
| gpac          | MP4Box                                                       | heap-overflow            | asan      | issue_2179  | CVE-2022-30976 | TortoiseFuzz |
| libmpeg2      | mpeg2_dec_fuzzer                                             | memcpy overlap           | asan      | 231026247   | CVE-2022-37416 | FuzzGen      |
| libavc        | avc_enc_fuzzer                                               | reachable assertion      | ubsan     | 223984040   | bug-only       | FuzzGen      |
| ibavc         | avc_enc_fuzzer                                               | heap-overflow            | ubsan     | 224160472   | pending        | FuzzGen      |
| Bento4        | mp4tag                                                       | heap-overflow            | asan      | issue_677   | bug-only       | MOpt         |
| Bento4        | mp42hevc                                                     | heap-overflow            | asan      | issue_678   | CVE-2022-27607 | MOpt         |
| Bento4        | mp4fragment                                                  | null pointer dereference | asan      | issue_767   | CVE-2022-41423 | MOpt         |
| Bento4        | mp4decrypt                                                   | out-of-bound read        | asan      | issue_772   | CVE-2022-41425 | MOpt         |
| Bento4        | mp4mux                                                       | heap-overflow            | asan      | issue_773-2 | CVE-2022-41428 | MOpt         |
| Bento4        | mp4mux                                                       | heap-overflow            | asan      | issue_773-3 | CVE-2022-41430 | MOpt         |
| Bento4        | mp4tag                                                       | null pointer dereference | asan      | issue_779   | CVE-2022-41841 | MOpt         |
| Bento4        | mp4tag                                                       | out of memory            | asan      | issue_770-1 | CVE-2022-41845 | MOpt         |
| Bento4        | mp4tag                                                       | out of memory            | asan      | issue_770-2 | CVE-2022-41846 | MOpt         |
| Bento4        | mp4split                                                     | out of memory            | asan      | issue_775-2 | CVE-2022-41847 | MOpt         |
| binutils      | nm-new                                                       | stack overflow           | asan      | 28995       | CVE-2022-27943 | SAVIOR       |
| jasper        | jasper                                                       | shift exponent exceed    | ubsan     | issue_311   | bug-only       | SAVIOR       |
| jasper        | imginfo                                                      | reachable assertion      | asan      | issue_338   | CVE-2022-40755 | SAVIOR       |
| mujs          | mujs-pp                                                      | null pointer dereference | asan      | issue_161-1 | bug-only       | EMS          |
| mujs          | mujs-pp                                                      | null pointer dereference | asan      | issue_161-2 | CVE-2022-30975 | EMS          |
| mujs          | mujs                                                         | stack overflow           | asan      | issue_162   | CVE-2022-30974 | EMS          |
| sox           | sox                                                          | reachable assertion      | ubsan     | issue_360-1 | CVE-2022-31651 | MoonLight    |
| sox           | sox                                                          | float pointer exception  | ubsan     | issue_360-2 | CVE-2022-31650 | MoonLight    |
| fig2dev       | fig2dev                                                      | null pointer dereference | ubsan     | issue_145   | bug-only       | GREYONE      |
| fig2dev       | fig2dev                                                      | null pointer dereference | ubsan     | issue_147   | bug-only       | GREYONE      |
| fig2dev       | fig2dev                                                      | null pointer dereference | ubsan     | issue_148-1 | bug-only       | GREYONE      |
| fig2dev       | fig2dev                                                      | null pointer dereference | ubsan     | issue_148-2 | bug-only       | GREYONE      |
| fig2dev       | fig2dev                                                      | stack buffer overflow    | ubsan     | issue_146   | bug-only       | GREYONE      |
| w3m           | w3m                                                          | out-of-bound write       | asan      | issue_242   | CVE-2022-38223 | EMS          |
| xpdf          | pdftoimages                                                  | use-after-free           | asan      | forum       | CVE-2022-38222 | EMS          |
| xpdf          | pdftoimages                                                  | stack buffer overflow    | asan      | forum       | CVE-2022-41842 | EMS          |
| xpdf          | pdftoimages                                                  | stack buffer overflow    | asan      | forum       | CVE-2022-41843 | EMS          |
| xpdf          | pdftoimages                                                  | stack buffer overflow    | asan      | forum       | CVE-2022-41844 | EMS          |
| nasm          | nasm                                                         | stack overflow           | asan      | 3392810     | CVE-2022-41420 | TortoiseFuzz |
| catdoc        | catdoc                                                       | null pointer dereference | asan      | issue_8     | bug-only       | TortoiseFuzz |
| dwarfdump     | libdwarf                                                     | double free              | asan      | issue_132   | CVE-2022-39170 | CollAFL      |
| pspp-dump-sav | libpspp                                                      | heap-overflow            | asan      | #62977      | CVE-2022-39831 | CollAFL      |
| pspp-dump-sav | libpspp                                                      | reachable assertion      | asan      | #62980      | bug-only       | CollAFL      |
| pspp-dump-sav | libpspp                                                      | divide by zero           | asan      | #62981      | bug-only       | CollAFL      |
| pspp-dump-sav | libpspp                                                      | heap-overflow            | asan      | #62986      | bug-only       | CollAFL      |
| pspp-dump-sav | libpspp                                                      | heap-overflow            | asan      | #63000      | CVE-2022-39832 | CollAFL      |
| libraw_fuzzer | libraw                                                       | heap-overflow            | asan      | issue_489   | bug-only       | CollAFL      |
| libconfuse    | cfgtest                                                      | heap-overflow            | asan      | issue_163   | CVE-2022-40320 | CollAFL      |
| bison         | bison                                                        | reachable assertion      | asan      | issue_91    | bug-only       | CollAFL      |
| bison         | bison                                                        | unexpected behavior      | ubsan     | issue_92    | bug-only       | CollAFL      |
| sum           | 38 new CVEs, 1 pendings, 17 bug-only / 56 new 0-day in total |