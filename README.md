# find_log4j
Locate vunerable log4j files.

Added a checksum files of potentially vunerable log4j versions (obtained via maven).

Feel free to do whatever you like with this, it's just for Python learning.

It tries to find log4j jar files and match their filenames, if found it checks the sha256 hash to compare.
If the filename is log4j-core.jar or log4j-api.jar, then it gets the hash and tries to match hash instead of filename.

Comments welcomed.

Usage: python3 find_log4j.py [optional sha256 filename]  
   - if no option used, it tries to load the sha256 list from the current directory

it just searches the current directory tree.

e.g.

./lib/log4j-api.jar  matches vulnerable  log4j-api-2.6.2.jar
./lib/log4j-api-2.14.1.jar     MATCH, vulnerable file detected

