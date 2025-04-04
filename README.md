# shellpeek

shellpeek allows you to peek at variables and stacktraces from a remote Bash
process. It may be useful in debugging scenarios. It's inspired by tools like
[phpspy](https://github.com/adsr/phpspy) and [rbspy](https://rbspy.github.io/).

Tested on x86_64-bit Linux with Bash 5.2.37.

### Build

```
$ make
```

### Synopsis

```console
$ cat -n test.sh
     1    #!/bin/bash
     2
     3    f1() {
     4        f2
     5    }
     6
     7    f2() {
     8        my_var='global in f2'
     9        f3
    10    }
    11
    12    f3() {
    13        local my_var='local in f3'
    14        f4
    15    }
    16
    17    f4() {
    18        declare -a my_arr=(apple banana carrot)
    19        declare -A my_assoc=([key1]=42 [key2]=43)
    20        declare -i my_int=43
    21        sleep 9999
    22    }
    23
    24    f1
$ ./test.sh &
[1] 340448
$ 
$ # Peek stacktrace
$ 
$ shellpeek -p 340448
frame   0 ./test.sh:24 main
frame   1 ./test.sh:4 f1
frame   2 ./test.sh:9 f2
frame   3 ./test.sh:14 f3
frame   4 ./test.sh:17 f4

$ 
$ # Peek at a variable
$ 
$ shellpeek -p 340448 -a my_var
frame   0 ./test.sh:24 main
  var   0 my_var=$'global in f2'
frame   1 ./test.sh:4 f1
frame   2 ./test.sh:9 f2
frame   3 ./test.sh:14 f3
  var   3 my_var=$'local in f3'
frame   4 ./test.sh:17 f4

$ 
$ # Peek at variables matching regex
$ 
$ shellpeek -p 340448 -r ^my_
frame   0 ./test.sh:24 main
  var   0 my_var=$'global in f2'
frame   1 ./test.sh:4 f1
frame   2 ./test.sh:9 f2
frame   3 ./test.sh:14 f3
  var   3 my_var=$'local in f3'
frame   4 ./test.sh:17 f4
  var   4 my_int=$'43'
  var   4 my_assoc=([$'key2']=$'43' [$'key1']=$'42')
  var   4 my_arr=($'apple' $'banana' $'carrot')

$ 
$ # Peek at all variables
$ 
$ shellpeek -p 340448 -x
frame   0 ./test.sh:24 main
  var   0 SHELL=$'/bin/bash'
  var   0 COLORTERM=$'truecolor'
  var   0 HISTSIZE=$'1048576'
  var   0 LANGUAGE=$'en_US.UTF-8'
  var   0 FUNCNAME=($'f4' $'f3' $'f2' $'f1' $'main')
  var   0 OPTIND=$'1'
  var   0 BASH_VERSION=$'5.2.37(1)-release'
  ...
frame   1 ./test.sh:4 f1
frame   2 ./test.sh:9 f2
frame   3 ./test.sh:14 f3
  var   3 my_var=$'local in f3'
frame   4 ./test.sh:17 f4
  var   4 my_int=$'43'
  var   4 my_assoc=([$'key2']=$'43' [$'key1']=$'42')
  var   4 my_arr=($'apple' $'banana' $'carrot')
$ 
```
