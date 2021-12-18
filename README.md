# find_log4j

Locate vunerable log4j files.
The current advice is to upgrade for log4j v2.17.0, this script can help find older versions.

## Description 

The script tries to find log4j jar files and match their filenames, if found it checks the sha256 hash to compare.
If the filename is log4j-core.jar or log4j-api.jar, then it gets the hash and tries to match hash instead of filename.

Added a SHA256 checksum file of potentially vunerable log4j versions (obtained via maven).

Feel free to do whatever you like with this, it's just for Python learning.

Comments welcomed.

## Usage

```
$ python3 find_logj4.py -d . -c logj4_sha256sums.txt

./lib/log4j-api.jar  matches vulnerable  log4j-api-2.6.2.jar
./lib/log4j-api-2.14.1.jar     MATCH, vulnerable file detected
```

## Links

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046

https://www.lunasec.io/docs/blog/log4j-zero-day/

https://github.com/NCSC-NL/log4shell/blob/main/software/README.md

https://www.truesec.com/hub/blog/apache-log4j-injection-vulnerability-cve-2021-44228-impact-and-response

https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/


