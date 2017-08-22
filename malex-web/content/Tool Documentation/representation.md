---
title: "Representation"
date: 2017-08-22T18:04:08+02:00
draft: true
---

## What's inside

`l8r`

## How the dependancies works.

This tool generate representation of binaries using YAML meta language. Three type of assets can be generated.

#### The header file

File containing all the resources that can be loaded for a particular binary.

**example**:

```yaml
file: binary_test
arch: AMD64
metas:
  - something
  - something_else
artefacts:
  -
    name: main
    filename: main.yaml
    symbol_name: main
  -
    name: call
    filename: call.yaml
    symbol_name: main
```

#### The function file

File containing all the informations that belongs to a particular symbol within a binary.

```yaml
main:
  metas:
    start: 0x4006ae # offset of the function
    size: 2 # number of nodes in the graph
  nodes: # list of the logic blocks of the function
    -
      step: 0 # ofsset in byte to the entry of the function
      links: # list of the call targets of the logic block call target as expressed as labeled func in header file
        - call
      instructions: # instructions in the logic block
        - PUSH RBP
        - MOV RBP, RSP
      regs: # VSA of the logic block (link for VSA below)
        -
          name: RAX
          set:
              min: 0
              max: 7
        -
          name: RDI
          set:
              min: 14
              max: 28

    -
      step: 11
      instructions:
        - POP RDI
        - RET
      regs:
        -
          name: RDI
          set:
            min: -4
            max: 13

```

#### The function calling graph file

File containing a finite automata which represents the Function Calling Graph of a program

```yaml
file: binary_test_other
graph:
  -
    name: func1
    offset: 0xDEADC0DE
    callers:
      - func1
      - func3
    callees:
      - func2
  -
    name: func2
    offset: 0xBADBEEF
    callers:
      - func1
  -
    name: func3
    offset: 0xBADC0FFEE
    callees:
      - func1
```
