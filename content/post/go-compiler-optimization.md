---
title: "My journey optimizing the Go Compiler"
date: 2020-04-28T13:20:28+01:00
comments: true
tags: ["Go", "compiler", "AST"]
categories: ["Go"]
draft: false
---

At [EDGE](https://edge.network/) we write a lot of Go, and we love it for various reasons, one of them being speed. One day I got into a situation where I need to assign an `int` to a variable based on another string value. 

Sounds easy right? well yes, but this particular use case awakened the beast in me and made me think what's the **best** way to do it. 

The journey finished by me contributing to the language compiler and make `map` lookups faster.

<!--more-->

## Situation
Our binaries can be found in 3 flavors, `amd64`, `arm64`, and `arm`. Sometimes a running binary needs to know what is its architecture, for example when pulling images/other binaries if the current running binary is an `amd64` binary then we should use the `amd64` repository or registry.

In Go that's easy. The [constant](https://golang.org/pkg/runtime/#pkg-constants) `runtime.GOARCH` gives us the running program's architecture.

In one case, I needed to assign an `int` to a variable based on the value of `runtime.GOARCH`. And the code below does exactly that:
```go 
var archIndex int
switch runtime.GOARCH {
    case "amd64": 
        archIndex = 0
    case "arm64": 
        archIndex = 1
    case "arm": 
        archIndex = 2
}
```

But I didn't want it to be that way because the day we support another architecture I need to add another `case` clause and that didn't feel right to me. 

It's a simple value mapping and I though using a `map` followed by a lookup would be better. Below was the `map` based solution:

```go
archIndex := map[string]int{
        "amd64": 0,
        "arm":   1,
        "arm64": 2,
}[runtime.GOARCH]
```

## Problem

The `map` based solution felt more readable and maintainable to me but I was curious which solution was faster? 

*The code is not in a hot path, and micro-optimizing it is not needed. But still wanted to know what's faster.*

To satisfy my curiosity, I benchmarked both approaches.

{{< gist segflow 431dd47770de0bbcfec6d0f0bcb912b5 >}}

```
goos: darwin
goarch: amd64
BenchmarkMapImpl-4     19503195       58.0 ns/op
BenchmarkSwitchImpl-4  1000000000     0.648 ns/op
```

Turns out the `map` based solution is 96 times slower than the `switch` based one. To understand why it's the case I start analyzing the generated code for both approaches.

## Compiler generated code

Like any other language compiler, to generate the final output the Go compiler will pass through various phases:

- **Scanning**: Scans the source code and split it into **tokens**
- **Parsing**: Parses those **tokens** and build the Abstract Syntax Tree (AST). Also checks that the code is a valid Go code (type checking etc..)
- **Code generating**: convert the **AST** to a lower-level representation of the program, specifically into a Static Single Assignment (SSA) form

At the end of the **parsing** phase, we are certain the program is valid Go code. The interesting phase for our case is the last one. 

The code generation phase takes the **AST**, applies some optimization to the **AST** itself by re-writing it, and then convert it into an **SSA** form. After the initial version of the **SSA** has been generated, several optimization passes will be applied like "dead code elimination", "constant propagation" and "bound check elimination"

We can see the work of each optimizer and the final **SSA** for our function by running this command
```
GOSSAFUNC=switchImplementation go tool compile benchmark_test.go
```

The command generates a html file [ssa.html](/code/go-compiler-optimization/switch-ssa.html) showing the generated **SSA** for the function `switchImplementation`. 

### switch based implementation

The final SSA form for our `switchImplementation` function looks like this: 
```
00000 (8) TEXT "".switchImplementation(SB), ABIInternal
00001 (8) FUNCDATA $0, gclocals·33cdeccccebe80329f1fdbee7f5874cb(SB)
00002 (8) FUNCDATA $1, gclocals·33cdeccccebe80329f1fdbee7f5874cb(SB)
00003 (8) FUNCDATA $2, gclocals·33cdeccccebe80329f1fdbee7f5874cb(SB)
00004 (+11) PCDATA $0, $0
00005 (+11) PCDATA $1, $0

00006 (+11) MOVQ $0, "".~r0(SP)

00007 (11) RET
00008 (?) END
```

The first block is the function epilogue where mainly a stack frame needs to be allocated. The second one is the body, and the final block is the function prologue where the functions need to return to its caller. 

The function body in our case is a simple move instruction which moves 0 to the ~`r0` registry. So the function is only returning 0 immediately there is nothing else. To confirm this I generated the SSA for the following function:
```
func return0() int {
    return 0
}
```

And the final generated code is exactly the same as you can see it [here](/code/go-compiler-optimization/return0-ssa.html). And that's why it's so fast.

### map based implementation

As for the SSA form of the `mapImplementation` function, it's longer, I annotated it so it's easier to understand what's happening.

```
00000 (31) TEXT "".mapImplementation(SB), ABIInternal
00001 (31) FUNCDATA $0, gclocals·7d2d5fca80364273fb07d5820a76fef4(SB)
00002 (31) FUNCDATA $1, gclocals·b9237f7ca55cc8bf6e05646631ad00ce(SB)
00003 (31) FUNCDATA $2, gclocals·a5ed3e65458aadaa1d48863859d2a323(SB)
00004 (31) FUNCDATA $3, "".mapImplementation.stkobj(SB)
00005 (+32) PCDATA $0, $0
00006 (+32) PCDATA $1, $1
00007 (+32) XORPS X0, X0
00008 (32) MOVUPS X0, ""..autotmp_2-256(SP)
00009 (32) MOVUPS X0, ""..autotmp_2-240(SP)
00010 (32) MOVUPS X0, ""..autotmp_2-224(SP)
00011 (32) PCDATA $0, $1
00012 (32) PCDATA $1, $2
00013 (32) LEAQ ""..autotmp_3-208(SP), DI
00014 (32) PCDATA $0, $0
00015 (32) LEAQ -48(DI), DI
00016 (32) DUFFZERO $239
00017 (32) PCDATA $0, $2
00018 (32) PCDATA $1, $1
00019 (32) LEAQ ""..autotmp_3-208(SP), AX
00020 (32) PCDATA $0, $0
00021 (32) MOVQ AX, ""..autotmp_2-240(SP)
00022 (32) CALL runtime.fastrand(SB)
00023 (32) MOVL (SP), AX
00024 (32) MOVL AX, ""..autotmp_2-244(SP)
00025 (33) PCDATA $0, $2
00026 (+33) LEAQ type.map[string]int(SB), AX
00027 (33) PCDATA $0, $0
00028 (33) MOVQ AX, (SP)
00029 (33) PCDATA $0, $3
00030 (33) LEAQ ""..autotmp_2-256(SP), CX
00031 (33) PCDATA $0, $0
00032 (33) MOVQ CX, 8(SP)
00033 (33) PCDATA $0, $4
00034 (33) LEAQ go.string."amd64"(SB), DX
00035 (33) PCDATA $0, $0
00036 (33) MOVQ DX, 16(SP)
00037 (33) MOVQ $5, 24(SP)
00038 (+33) CALL runtime.mapassign_faststr(SB)    // assign "amd64" key
00039 (33) PCDATA $0, $2
00040 (33) MOVQ 32(SP), AX
00041 (33) PCDATA $0, $0
00042 (33) MOVQ $0, (AX)                          // assign "0" value
00043 (34) PCDATA $0, $2
00044 (+34) LEAQ type.map[string]int(SB), AX
00045 (34) PCDATA $0, $0
00046 (34) MOVQ AX, (SP)
00047 (34) PCDATA $0, $3
00048 (34) LEAQ ""..autotmp_2-256(SP), CX
00049 (34) PCDATA $0, $0
00050 (34) MOVQ CX, 8(SP)
00051 (34) PCDATA $0, $4
00052 (34) LEAQ go.string."arm"(SB), DX
00053 (34) PCDATA $0, $0
00054 (34) MOVQ DX, 16(SP)
00055 (34) MOVQ $3, 24(SP)
00056 (+34) CALL runtime.mapassign_faststr(SB)    // assign "arm" key
00057 (34) PCDATA $0, $2
00058 (34) MOVQ 32(SP), AX
00059 (34) PCDATA $0, $0
00060 (34) MOVQ $1, (AX)                          // assign "1" value
00061 (35) PCDATA $0, $2
00062 (+35) LEAQ type.map[string]int(SB), AX
00063 (35) PCDATA $0, $0
00064 (35) MOVQ AX, (SP)
00065 (35) PCDATA $0, $3
00066 (35) LEAQ ""..autotmp_2-256(SP), CX
00067 (35) PCDATA $0, $0
00068 (35) MOVQ CX, 8(SP)
00069 (35) PCDATA $0, $4
00070 (35) LEAQ go.string."arm64"(SB), DX
00071 (35) PCDATA $0, $0
00072 (35) MOVQ DX, 16(SP)
00073 (35) MOVQ $5, 24(SP)
00074 (+35) CALL runtime.mapassign_faststr(SB)    // assign "arm64" key
00075 (35) PCDATA $0, $2
00076 (35) MOVQ 32(SP), AX
00077 (35) PCDATA $0, $0
00078 (35) MOVQ $2, (AX)                          // assign "2" value
00079 (36) PCDATA $0, $2
00080 (+36) LEAQ type.map[string]int(SB), AX
00081 (36) PCDATA $0, $0
00082 (36) MOVQ AX, (SP)
00083 (36) PCDATA $0, $2
00084 (36) PCDATA $1, $0
00085 (36) LEAQ ""..autotmp_2-256(SP), AX
00086 (36) PCDATA $0, $0
00087 (36) MOVQ AX, 8(SP)
00088 (36) PCDATA $0, $2
00089 (36) LEAQ go.string."amd64"(SB), AX
00090 (36) PCDATA $0, $0
00091 (36) MOVQ AX, 16(SP)
00092 (36) MOVQ $5, 24(SP)
00093 (+36) CALL runtime.mapaccess1_faststr(SB)  // perform the map lookup
00094 (36) PCDATA $0, $2
00095 (36) MOVQ 32(SP), AX
00096 (36) PCDATA $0, $0
00097 (36) MOVQ (AX), AX
00098 (+32) MOVQ AX, "".~r0(SP)
00099 (+36) RET
00100 (?) END
```

The reason behind this is the fact that the generated code is building the map which requires allocating it, assign the different values, and then doing a lookup. 

## Constant folding

The reason why the switch implementation is similar to a `return 0` is something called `constant folding`. 

> Constant folding is the process of recognizing and evaluating constant expressions at compile time rather than computing them at runtime - Wikipedia

We know that `runtime.GOARCH` is a constant, so not only its value cannot change but also it's known at compile time. The compiler can use this two properties to evaluate constant expression at compile time instead of doing that when running, in our case the compiler knew which of the `case` clauses is true so it deleted the conditional structure and replaced it with a naked `return 0`.

This was not the case on the `map` based implementation.

## Implement the optimization

Our map lookup looks like this:

```go
map[string]int{
        "amd64": 0,
        "arm":   1,
        "arm64": 2,
}[runtime.GOARCH]
```

This is represented in the AST using an `INDEXMAP` node. The `INDEXMAP` has two childs `left` and `right` (remember it's a tree).

The `left` child is the map we will lookup from, and the `right` child is the key we are looking for. Both childs are also nodes, for example the `right` node can be a `FUNCCALL` node for a lookup like this:

```go
map[string]int{
        "amd64": 0,
        "arm":   1,
        "arm64": 2,
}[aRandomFunc()]
```

At compile time, we can check if both `right` and `left` nodes are constant, if they are, we see if what are we looking for (the key), is defined in the constant map, and if it's the case we replace the `INDEXMAP` node in the AST by the value of that key. This will replace all lookups on maps where the map is an `OMAPLIT` and the key is a constant with a constant if possible.

This optimization is applied directly to the AST and not the SSA form. This type of AST optimization is implemented inside the `walk` function. 

The PR with this optimization can be seen here: https://go-review.googlesource.com/c/go/+/208323

The new generated SSA with that optimization can be found [here](/code/go-compiler-optimization/optimized-map-ssa.html)

Now if we benchmark both implementations using the Go compiler from that branch we see that both are similar. They are both similar to our `return 0` function. 

```
BenchmarkSwitchImpl-4           1000000000               0.599 ns/op           0 B/op          0 allocs/op
BenchmarkMapImpl-4              1000000000               0.612 ns/op           0 B/op          0 allocs/op
```

## Conclusion

The PR is not merged yet, hopefully soon, it got added to Go 1.15 milestone which should be released in a month.

Huge thanks to everyone in the #compilers channel in [Gophers](https://invite.slack.golangbridge.org/) slack