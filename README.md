# hvftool
Lightweight Virtual Machine Monitor for HVF/MacOS

I make this repo public but this is not open source in the sense that I don't intend to explain or support the project.
Developpers interested in HVF and virtualization may find some responses to their questions by analyzing code.

It is a vehicle for me to explore may topics like:
- HVF itself
- VMM
- Debugging tools for guest payloads
- Design patterns
- Emulation of SoC
    - FDT generation based on a selection of HW
    - GIC emulation
- Arm system architecture

In Theory, the Linux "execution scheme" works if you supply a Linux image.
To debug the payload, you will need to reroute input to a pipe pair (see alternative PL011 backend).
You may want to use pipeterm (another repo) as the tool to connect to the pipe pair.

There is a dependency on https://github.com/dgibson/dtc.git

