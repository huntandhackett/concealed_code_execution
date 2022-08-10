# Sample DLLs

Here you can find sample DLLs to use for testing injection. They all behave identically by spawning a Command Prompt from their [DllMain function](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) but represent various coding styles:

1. The **[CreateProcess DLL](1.CreateProcess)** uses only documented Win32 API functions and illustrates a typical lightweight library. It doesn't require any runtime redistributables and links against kernel32.dll.

2. The **[RtlCreateUserProcess DLL](2.RtlCreateUserProcess)** belongs to the Native subsystem and, thus, depends solely on the functions from ntdll.dll. Because ntdll is a unique library, always available in all processes from their very creation, this sample DLL can be used against any application, including system components that run at boot.

3. The **[NoDependencies DLL](3.NoDependencies)** takes this motive of going low-level to the extreme. The library does not import any functions but resolves them from ntdll at runtime. Effectively, it relies on the same approach as a typical shellcode would but is still written in C and has a shape of a DLL file, not just a sequence of machine instructions. This option is perfect for testing partially implemented manual mappers because writing it with the correct memory layout is enough to make it work.

Finally, each DLL comes in two flavors: the one that succeeds its loading and, thus, stays in memory indefinitely, and the one that fails and unloads immediately. Each pair shares the source code except for returning `TRUE` or `FALSE`, respectively. As you can see in the corresponding writeup, it changes how we should approach their post-exploitation detection.
