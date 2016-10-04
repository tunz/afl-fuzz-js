This is a custom version of [afl-fuzz](http://lcamtuf.coredump.cx/afl/).

Now, only support x86_64.

What's new in this custom fuzzer?
---------------------------------

1. **Comment method**

  The original fuzzer is only targeting javascript. 
  So, we can extract keywords using comment.

  For example, If we test this one,

  ```js
  function abc() { print(1); }
  ```

  then, comment method will check examples like this.
  ```js
  /**/f/*unction abc() { print(1); }*/
  ```
  ```js
  /**/fu/*nction abc() { print(1); }*/
  ```
  ```js
  /**/fun/*ction abc() { print(1); }*/
  ```

  At this point, the program flow will be changed.

  ```js
  /**/function/* abc() { print(1); }*/
  ```
  now, it saves 'function' as dictionary.

2. **Threshold model**

  If the program is using thread, then execution path will be changed.

  So, we ignore small change in execution path which can be caused by thread.

  But, disadvantage of this model is that we cannot detect real small flow changes.

  We can only detect huge flow changes.

3. **Speed improvement using ptrace**

  The idea is come from Michal Zalewski's todo list.

  If we can make fork server after skipping the initialization process, 
  speed of fuzzer will be improved.

  I tried this idea using ptrace.

  First, find the first read or open point, which reads our input.
  After remembering the latest point before reading,
  restart application, and then make forkserver at the found point.

  This method works pretty well in JavaScriptCore.
  Performance increases 2.5x

  But in case of v8, it is not stable.
  I'm finding what the problem is.

Usage for Webkit JSC
--------------------

It is almost same with original AFL.

**Download afl-fuzz-js**
```
$ git clone https://github.com/tunz/afl-fuzz-js.git
$ cd afl-fuzz-js
$ make
```
you can configure through the config.h file before compile the afl-fuzz-js.

**Download Webkit**
```
$ cd ~
$ svn checkout https://svn.webkit.org/repository/webkit/trunk webkit
$ cd webkit
```

**Build with afl-fuzz-js**
```
$ export AFL_HARDEN=1
$ export AFL_INST_RATIO=30
$ export CC=/path/to/afl-gcc
$ export CXX=/path/to/afl-g++
$ ./Tools/Scripts/build-jsc --gtk --makeargs="-j4"
```
You can remove gtk option, or change makeargs arguments.
You can also compile with address santinizer. I think it would be very efficient, but I didn't tried yet.
The value of AFL_HARDEN , AFL_INST_RATIO, CC, or CXX also can be changed by you.
It depends on your choice and situation.

**Fuzz with afl-fuzz-js**
```
$ cd ~
$ mkdir fuzz
$ cd fuzz
$ cp ~/webkit/WebKitBuild/Release/bin/jsc ./jsc
$ /path/to/afl-fuzz -i [input directory] -o [output directory] -x [dictionary directory] -m 8G ./jsc @@
```
-m option also depends on your situation.
You can parallelize it using -M and -S option.
If you add more samples to input directory, it would be more efficient.

**(If there is error that can't find start position, or there is crash)**

Sometimes, there would be some problem (e.g. v8). Temporarily, use user defined start address.
  
Add
```C
asm(".string \"[start]\"");
```
to what you want to start from. it specify the start position by user, not automatically.

Add -U option when you start afl-fuzz. 
```
$ /path/to/afl-fuzz -i [input directory] -o [output directory] -x [dictionary directory] -m 8G -U ./jsc @@
```
Then, It will start from that line.
