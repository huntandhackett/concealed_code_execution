# Concealed Code Execution

**[Hunt & Hackett](https://www.huntandhackett.com/)** presents a set of tools and technical write-ups describing attacking techniques that rely on concealing code execution on Windows. Here you will find explanations of how these techniques work, receive advice on detection, and get sample source code for testing your detection coverage.

## Content

This repository covers two classes of attacking techniques that extensively use internal Windows mechanisms plus provides suggestions and tools for detecting them:
 - **[Process Tampering](Tampering)** - a set of techniques that conceal the code on the scale of an entire process.
 - **[Code Injection](Injection)** - a collection of tricks that allow executing code as part of other processes without interfering with their functionality.
 - **[Detection](Detection)** - a compilation of recommendations for defending against various techniques for concealing code execution.

The core values of the project:
- **The systematic approach**. This repository includes more than just a collection of tools or links to external resources. Each subject receives a detailed explanation of the underlying concepts; each specific case gets classified into generic categories. 
- **Proof-of-concept tooling**. The write-ups are accompanied by example projects in C that demonstrate the use of the described facilities in practice.
- **Beginner to professional**. You don't need to be a cybersecurity expert to understand the concepts we describe. Yet, even professionals in the corresponding domain should find the content valuable and educational because of the attention to detail and pitfalls.

## Implementation

One final distinctive feature of this project is the extensive use of **Native API** throughout the samples. Here is the motivation for this choice:
1. **Functionality**. Some operations required for the most advanced techniques (such as Process Tampering) are not exposed via other APIs.
2. **Control**. Being the lowest level of interaction with the operating system, it provides the most control over its behavior. The Win32 API is implemented on top of Native API, so whatever is possible to achieve with the former is also possible with the latter.
3. **Availability**. Being exposed by ntdll.dll, Native API is available in all processes, including the system ones.
4. **Consistency**. The interfaces exposed by this API are remarkably consistent. After learning the fundamental design choices, it becomes possible to correctly predict the majority of function prototypes just from the API's name.
5. **Resistance to hooking**. It is substantially easier to remove or bypass user-mode hooks when using Native API, partially blinding security software. There are no lower-level libraries that might be patched, so unhooking becomes as simple as loading a second instance of ntdll.dll and redirecting the calls there.

## Compiling Remarks

The sample code uses the Native API headers provided by the [PHNT](https://github.com/processhacker/phnt) project. Make sure to clone the repository using the `git clone --recurse-submodules` command to fetch this dependency. Alternatively, you can use `git submodule update --init` after cloning the repository.

To build the projects included with the repository, you will need a recent version of [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/). If you use [Visual Studio](https://visualstudio.microsoft.com), please refer to the built-in SDK installation. Alternatively, you can also use the standalone build environment of [EWDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk#enterprise-wdk-ewdk). To compile all tools at once, use `MSBuild AllTools.sln /t:build /p:configuration=Release /p:platform=x64`.
