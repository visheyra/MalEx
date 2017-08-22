# MalEx

## What is MalEx

MalEx is tool which aim to translate a binary to an abstract representation which will be used for further processing and perform naive isomorphism detection.

## How does it works

MalEx extracts the following information from binaries:

1. Function Calling Graph of the whole program
2. Control Flow Graph of each function defined in the binary
3. Value set of each register for each logic block in a function
4. Assembly instructions
5. Assembly instructions translated to the Vex language

Once these informations has been extracted, the data is structured in a yaml file which can later be analysed by other solutions.
