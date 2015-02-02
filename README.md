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

  then, comment method will check exammples like this.
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

  **(Temporarily, use user defined start address)**
  
  Add
  ```C
  asm(".string \"[start]\"");
  ```
  to what you want to start from.

  Add -U option for afl-fuzz. 

  Then, It will start from that line.
