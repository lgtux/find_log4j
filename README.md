# FIND_LOG4J SCRIPT

## Locate vunerable log4j files.

It tries to find log4j jar files and match their filenames, if found it checks the sha256 hash to compare.
If the filename is log4j-core.jar or log4j-api.jar, then it gets the hash and tries to match hash instead of filename.

Note: _Checksum files of potentially vunerable log4j versions obtained via Maven._ 

## Usage: 

```
$ python3 log4j_finder.py
Enter full path you want to scan here:  /some/path/here/
```


## Results are listed from the search:
```
./lib/log4j-api.jar  matches vulnerable  log4j-api-2.6.2.jar
./lib/log4j-api-2.14.1.jar     MATCH, vulnerable file detected
```

### Original Source: https://github.com/lgtux/find_log4j
