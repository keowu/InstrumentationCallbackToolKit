# Instrumentation Callback ToolKit
 
 <p> A fast method to intercept syscalls from any user-mode process using InstrumentationCallback and detect any process using InstrumentationCallback. </p>


[<img src="https://img.youtube.com/vi/LHb-fx-fKCA/hqdefault.jpg" width="600" height="300"/>](https://www.youtube.com/embed/LHb-fx-fKCA)

##### The project is divided into two parts:

SmellsLikeKernelSpirit - It is responsible for installing an instrumentation callback in the target process through DLL injection (usually from the currently running main thread).

DetectProcessContainerNirvaned - It is responsible for detecting a process container with an instrumentation callback installed in any operating system process.

#### Using DetectProcessContainerInstrumented:

You can compile and use it in your heuristics to detect whether your user-land process or which user-land processes are using the resource.

<p align="center">
 <img src="images/DetectProcessContainerInstrumented.png" />
</p>

#### Using SmellsLikeKernelSpirit(x86 and x64):

You can download precompiled binaries and their respective debug files from the 'release' tab of this repository to avoid the need for compilation (and directly intercept).

When injecting, a console will be allocated for the process and will capture any of the system calls used by it.

Exemple:

<p align="center">
 <img src="images/SmellsLikeKernelSpirit.png" />
</p>
