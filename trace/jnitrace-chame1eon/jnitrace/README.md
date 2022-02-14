# jnitrace

_A Frida based tool to trace use of the JNI API in Android apps._

Native libraries contained within Android Apps often make use of the JNI API to
utilize the Android Runtime. Tracking those calls through
manual reverse engineering can be a slow and painful process. `jnitrace` works
as a dynamic analysis tracing tool similar to frida-trace or strace but for
the JNI.

![JNITrace Output](https://i.ibb.co/ZJ04cBB/jnitrace-1.png)

## Installation:

The easiest way to get running with `jnitrace` is to install using pip:

`pip install jnitrace`

###### Dependencies:
* arm, arm64, x86, or x64 Android device
* Frida installed on the Android device
* Frida support > 12
* Linux, Mac, or Windows Host with Python 3 and pip

## Running:

After a pip install it is easy to run `jnitrace`:

`jnitrace -l libnative-lib.so com.example.myapplication`

`jnitrace` requires a minimum of two parameters to run a trace:
* `-l libnative-lib.so` - is used to specify the libraries to trace. This argument can be used multiple times or `*` can be used to track all libraries. For example, `-l libnative-lib.so -l libanother-lib.so` or `-l *`.
* `com.example.myapplication` - is the Android package to trace. This package must already be installed on the device.

Optional arguments are listed below:
* `-R <host>:<port>` - is used to specify the network location of the remote Frida server. If a <host>:<port> is unspecified, localhost:27042 is used by deafult.
* `-m <spawn|attach>` - is used to specify the Frida attach mechanism to use. It can either be spawn or attach. Spawn is the default and recommended option.
* `-b <fuzzy|accurate|none>` - is used to control backtrace output. By default `jnitrace` will run the
backtracer in `accurate` mode. This option can be changed to `fuzzy` mode or used to stop the backtrace
by using the `none` option. See the Frida docs for an explanation on the differences.
* `-i <regex>` - is used to specify the method names that should be traced. This can be helpful for reducing the noise in particularly large JNI apps. The option can be supplied multiple times. For example, `-i Get -i RegisterNatives` would include
only JNI methods that contain Get or RegisterNatives in their name.
* `-e <regex>` - is used to specify the method names that should be ignored in the trace. This can be helpful for reducing the noise in particularly large JNI apps. The option can be supplied multiple times. For example, `-e ^Find -e GetEnv` would exclude from
the results all JNI method names that begin Find or contain GetEnv.
* `-I <string>` - is used to specify the exports from a library that should be traced. This is useful for libraries where you only
want to trace a small number of methods. The functions jnitrace considers exported are any functions that are directly callable
from the Java side, as such, that includes methods bound using RegisterNatives. The option can be supplied multiple times. For example,
`-I stringFromJNI -I nativeMethod([B)V` could be used to include an export from the library called `Java_com_nativetest_MainActivity_stringFromJNI` and a method bound using RegisterNames with the signature of `nativeMethod([B)V`.
* `-E <string>` is used to specify the exports from a library that should not be traced. This is useful for libraries where you
have a group of busy native calls that you want to ignore. The functions jnitrace considers exported are any functions that are directly callable from the Java side, as such, that includes methods bound using RegisterNatives. The option can be supplied multiple times. For example, `-E JNI_OnLoad -E nativeMethod` would exclude from the trace the `JNI_OnLoad` function call and any methods
with the name `nativeMethod`.
* `-o path/output.json` - is used to specify an output path where `jnitrace` will store all traced data. The information is stored in JSON format to allow later post-processing of the trace data.
* `-p path/to/script.js` - the path provided is used to load a Frida script into the target process before the `jnitrace` script has loaded. This can be used for defeating anti-frida or anti-debugging code before `jnitrace` starts.
* `-a path/to/script.js` - the path provided is used to load Frida script into the target process after `jnitrace` has been loaded.
* `--hide-data` - used to reduce the quantity of output displayed in the console. This option will hide additional data that is displayed as hexdumps or as string de-references.
* `--ignore-env` - using this option will hide all calls the app is making using the JNIEnv struct.
* `--ignore-vm` - using this option will hide all calls the app is making using the JavaVM struct.
* `--aux <name=(string|bool|int)value>` - used to pass custom parameters when spawning an application. For example `--aux='uid=(int)10'` will spawn the application for user 10 instead of default user 0.

***Note***

Remember frida-server must be running before running `jnitrace`. If the default
instructions for installing frida have been followed, the following command will start the server ready for `jnitrace`:

`adb shell /data/local/tmp/frida-server`

## API:
The engine that powers jnitrace is available as a separate project. That project allows you to import jnitrace to track individual JNI API calls, in a method familiar to using the Frida `Interceptor` to attach to functions and addresses.

```javascript
import { JNIInterceptor } from "jnitrace-engine";

JNIInterceptor.attach("FindClass", {
    onEnter(args) {
        console.log("FindClass method called");
        this.className = Memory.readCString(args[1]);
    },
    onLeave(retval) {
        console.log("\tLoading Class:", this.className);
        console.log("\tClass ID:", retval.get());
    }
});

```

More information: https://github.com/chame1eon/jnitrace-engine

## Building:

Building `jnitrace` from source requires that `node` first be installed.
After installing `node`, the following commands need to be run:

* `npm install`
* `npm run watch`

`npm run watch` will run `frida-compile` in the background compiling the source to the output
file, `build/jnitrace.js`. `jnitrace.py` loads from `build/jnitrace.js` by default, so no other
changes are required to run the updates.

## Output:
![JNITrace Output](https://i.ibb.co/WfDq1cy/jnitrace-2.png)

Like frida-trace, output is colored based on the API call thread.

Immediately below the thread ID in the display is the JNI API method name.
Method names match exactly with those seen in the `jni.h` header file.

Subsequent lines contain a list of arguments indicated by a `|-`. After the
`|-` characters are the argument type followed by the argument value. For
jmethods, jfields and jclasses the Java type will be displayed in curly
braces. This is dependent on `jnitrace` having seen the original method,
field, or class lookup. For any methods passing buffers, `jnitrace` will
extract the buffers from the arguments and display it as a hexdump below the
argument value.

Return values are displayed at the bottom of the list as `|=` and will not
be present for void methods.

If the backtrace is enabled, a Frida backtrace will be displayed below the
method call. Please be aware, as per the Frida docs, the fuzzy backtrace is
not always accurate and the accurate backtrace may provide limited results.

## Details:
The goal of this project was to create a tool that could trace JNI API calls
efficiently for most Android applications.

Unfortunately, the simplest approach of attaching to all function pointers in
the JNIEnv structure overloads the application. It causes a crash based on the
sheer number of function calls made by other unrelated libraries also using
the same functions in `libart.so`.

To deal with that performance barrier, `jnitrace` creates a shadow JNIEnv that
it can supply to libraries it wants to track. That JNIEnv contains a series
of function trampolines that bounce the JNI API calls through some custom
Frida NativeCallbacks to track the input and output of those functions.

The generic Frida API does a great job of providing a platform to build
those function trampolines with minimal effort. However, that simple approach
does not work for all of the JNIEnv API. The key problem with tracing all of
the methods is the use of variadic arguments in the API. It is not possible to
create the NativeCallback for these functions ahead of time, as it is not known
beforehand all the different combinations of Java methods that will be called.

The solution is to monitor the process for calls to `GetMethodID` or
`GetStaticMethodID`, used to look up method identifiers from the runtime.
Once `jnitrace` sees a `jmethodID` lookup it has a known mapping of
ID to method signature. Later, when a JNI Java method call is made, an initial
NativeCallback is used to extract the method ID in the call. That method
signature is then parsed to extract the method arguments. Once `jnitrace` has
extracted the arguments in the method, it can dynamically create a
NativeCallback for that method. That new NativeCallback is returned and a
little bit of architecture specific shellcode deals with setting up the stack
and registers to allow that call to run successfully. Those NativeCallbacks
for specific methods are cached to allow the callback to run more efficiently
if a method if called multiple times.

The other place where a simple NativeCallback is not sufficient for
extracting the arguments from a method call, is for calls using a
va_args pointer as the final argument. In this case `jnitrace` uses some code
to extract the arguments from the pointer provided. Again this is architecture
specific.

All data traced in these function calls is sent to the python console
application that formats and displays it to the user.

## Recommendations:
Most testing of this tool has been done on an Android x86_64 emulator running
Marshmallow. Any issues experienced running on another device, please file an
issue, but also, if possible, it is recommended to try running on a similar
emulator.

## Issues:
For any issues experienced running `jnitrace` please create an issue on
GitHub. Please include the following information in the filed issue:
* Device you were running on
* Version of Frida you were using
* Application you were running against
* Any displayed error messages
