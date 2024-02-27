# Vyper - Compiler - Findings Report

# Table of contents
- ### [Contest Summary](#contest-summary)
- ### [Results Summary](#results-summary)
- ## High Risk Findings
    - [H-01. integer overflow in slice()](#H-01)
    - [H-02. concat built-in can corrupt memory](#H-02)
- ## Medium Risk Findings
    - [M-01. vyper-serve unable to compile bytecode due to changes in vyper_compile.py's compile_files function definition](#M-01)
    - [M-02. SHA3_64 Vulnerability in compile_ir.py](#M-02)
    - [M-03. `RawCall` builtin function allows passing a value in unsupported calls](#M-03)
    - [M-04. Contract interfaces allow nonpayable implementations of payable functions](#M-04)
    - [M-05. Slice bounds check can be overflowed to access unrelated data](#M-05)
    - [M-06. External calls can overflow return data to return input buffer](#M-06)
    - [M-07. Array signed int access](#M-07)
- ## Low Risk Findings
    - [L-01. [M-01] Compiler fails to revert if a negative integer is passed as a uint datatype.](#L-01)
    - [L-02. Builtins that access literal lists cannot be compiled](#L-02)
    - [L-03. ContractFunctionT.from_abi fails to gracefully handle a valid JSON ABI interface that represents `__default__` and/or `__init__` function](#L-03)
    - [L-04. Useless memory allocation bug in RawCall](#L-04)
    - [L-05. compiler crash during assert codegen](#L-05)
    - [L-06.  compiler crash during raise codegen](#L-06)
    - [L-07. vyper can accept conflicting optimization options from cli](#L-07)
    - [L-08. crash due to shadowing iterator vars](#L-08)
    - [L-09. crash due to missing var_info in struct attribute](#L-09)
    - [L-10. single exit point not check for for loop](#L-10)
    - [L-11. compiler crash du to ASTTokens instantiation](#L-11)
    - [L-12. Tuple constants are deleted during folding, breaking compilation](#L-12)
    - [L-13. Gas cost estimates incorrect due to rounding in `calc_mem_gas()`](#L-13)
    - [L-14. Incorrect gas estimate for BALANCE opcode](#L-14)
    - [L-15. SHA256 built-in will return input value on chains without SHA256 precompile](#L-15)
    - [L-16. Fang optimization options broken](#L-16)
    - [L-17. `_bytes_to_num()` skips `ensure_in_memory()` check, which can lead to compilation failure](#L-17)
    - [L-18. Built-in `shift()` function will fail if passed a negative integer at compile time](#L-18)
    - [L-19. Compiled opcodes will return wrong values for PUSH instructions due to incorrect padding](#L-19)
    - [L-20. Wrong denominations included in reserved keywords](#L-20)
    - [L-21. Pure functions can emit logs](#L-21)
    - [L-22. Compile-time division for signed integer edge case](#L-22)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: Vyper

### Dates: Sep 14th, 2023 - Nov 4th, 2023

[See more contest details here](https://www.codehawks.com/contests/cll5rujmw0001js08menkj7hc)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 2
   - Medium: 7
   - Low: 22


# High Risk Findings

## <a id='H-01'></a>H-01. integer overflow in slice()

_Submitted by [KuroHashDit](/profile/cln6wuqc6000ol808dd8imjox), [obront](/profile/clnxz4xdc000cl908cj3yirf0). Selected submission by: [KuroHashDit](/profile/cln6wuqc6000ol808dd8imjox)._      
				


## Summary
There is an integer overflow in the slice() code, which will cause memory corruption.

## Vulnerability Details
POC:

	d: public(Bytes[256])
		
	@external
	def test():
		x : uint256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935 # 2**256-1
		self.d = b"\x01\x02\x03\x04\x05\x06"
		# s : Bytes[256] = slice(self.d, 1, x)
		assert len(slice(self.d, 1, x))==115792089237316195423570985008687907853269984665640564039457584007913129639935

Since x is a variable, slice(self.d, 1, x) will return a Bytes[256] object. However, due to an integer overflow, the length of this Bytes[256] object will be written to 2**256-1, and accessing this object may cause memory corruption.

ROOT CAUSE:

line 348 in vyper/builtins/functions.py

    @process_inputs
    def build_IR(self, expr, args, kwargs, context):
        src, start, length = args

        # Handle `msg.data`, `self.code`, and `<address>.code`
        if src.value in ADHOC_SLICE_NODE_MACROS:
            return _build_adhoc_slice_node(src, start, length, context)

        is_bytes32 = src.typ == BYTES32_T
        if src.location is None:
            # it's not a pointer; force it to be one since
            # copy_bytes works on pointers.
            assert is_bytes32, src
            src = ensure_in_memory(src, context)

        with src.cache_when_complex("src") as (b1, src), start.cache_when_complex("start") as (
            b2,
            start,
        ), length.cache_when_complex("length") as (b3, length):
            if is_bytes32:
                src_maxlen = 32
            else:
                src_maxlen = src.typ.maxlen

            dst_maxlen = length.value if length.is_literal else src_maxlen

            buflen = dst_maxlen

            # add 32 bytes to the buffer size bc word access might
            # be unaligned (see below)
            if src.location == STORAGE:
                buflen += 32

            # Get returntype string or bytes
            assert isinstance(src.typ, _BytestringT) or is_bytes32
            # TODO: try to get dst_typ from semantic analysis
            if isinstance(src.typ, StringT):
                dst_typ = StringT(dst_maxlen)
            else:
                dst_typ = BytesT(dst_maxlen)

            # allocate a buffer for the return value
            buf = context.new_internal_variable(BytesT(buflen))
            # assign it the correct return type.
            # (note mismatch between dst_maxlen and buflen)
            dst = IRnode.from_list(buf, typ=dst_typ, location=MEMORY)

            dst_data = bytes_data_ptr(dst)

            if is_bytes32:
                src_len = 32
                src_data = src
            else:
                src_len = get_bytearray_length(src)
                src_data = bytes_data_ptr(src)

            # general case. byte-for-byte copy
            if src.location == STORAGE:
                # because slice uses byte-addressing but storage
                # is word-aligned, this algorithm starts at some number
                # of bytes before the data section starts, and might copy
                # an extra word. the pseudocode is:
                #   dst_data = dst + 32
                #   copy_dst = dst_data - start % 32
                #   src_data = src + 32
                #   copy_src = src_data + (start - start % 32) / 32
                #            = src_data + (start // 32)
                #   copy_bytes(copy_dst, copy_src, length)
                #   //set length AFTER copy because the length word has been clobbered!
                #   mstore(src, length)

                # start at the first word-aligned address before `start`
                # e.g. start == byte 7 -> we start copying from byte 0
                #      start == byte 32 -> we start copying from byte 32
                copy_src = IRnode.from_list(
                    ["add", src_data, ["div", start, 32]], location=src.location
                )

                # e.g. start == byte 0 -> we copy to dst_data + 0
                #      start == byte 7 -> we copy to dst_data - 7
                #      start == byte 33 -> we copy to dst_data - 1
                copy_dst = IRnode.from_list(
                    ["sub", dst_data, ["mod", start, 32]], location=dst.location
                )

                # len + (32 if start % 32 > 0 else 0)
                copy_len = ["add", length, ["mul", 32, ["iszero", ["iszero", ["mod", start, 32]]]]]
                copy_maxlen = buflen

            else:
                # all other address spaces (mem, calldata, code) we have
                # byte-aligned access so we can just do the easy thing,
                # memcopy(dst_data, src_data + dst_data)

                copy_src = add_ofst(src_data, start)
                copy_dst = dst_data
                copy_len = length
                copy_maxlen = buflen

            do_copy = copy_bytes(copy_dst, copy_src, copy_len, copy_maxlen)

            ret = [
                "seq",
                # make sure we don't overrun the source buffer
                ["assert", ["le", ["add", start, length], src_len]],  # bounds check  #BUG CODE IS HERE start + length might overflow
                do_copy,
                ["mstore", dst, length],  # set length
                dst,  # return pointer to dst
            ]
            ret = IRnode.from_list(ret, typ=dst_typ, location=MEMORY)
            return b1.resolve(b2.resolve(b3.resolve(ret)))


["assert", ["le", ["add", start, length], src_len]] may have integer overflow, bypassing the assert here, and finally writing the wrong length to dst.

## Impact

Medium Risk

## Recommendations

Fix integer overflow here
## <a id='H-02'></a>H-02. concat built-in can corrupt memory

_Submitted by [cyberthirst](/profile/cln69xxib000gjt08n37hic1g), [KuroHashDit](/profile/cln6wuqc6000ol808dd8imjox). Selected submission by: [cyberthirst](/profile/cln69xxib000gjt08n37hic1g)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/builtins/functions.py#L534-L550

https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/builtins/functions.py#L569-L572

https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L270-L273

https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L245-L247

https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L301-L320

## Summary
`concat` built-in can write over the bounds of the memory buffer that was allocated for it and thus overwrite existing valid data. The root cause, at least for `v0.3.10rc3*`, is that the `build_IR` for `concat` doesn't properly adhere to the API of `copy_bytes`.

## Vulnerability Details
The `build_IR` allocates a new internal variable for the concatenation: https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/builtins/functions.py#L534-L550

Notice that the buffer is allocated for the `maxlen` + 1 word to actually hold the length of the array.

Later the `copy_bytes` function is used to copy the actual source arguments to the destination: https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/builtins/functions.py#L569-L572

The `dst_data` is defined as:
- data ptr - to skip the 1 word that holds the length
- offset  - to skip the source arguments that were already written to the buffer
  - the offset is increased via: `["set", ofst, ["add", ofst, arglen]]`, ie it is increased by the length of the source argument

Now, the `copy_bytes` function has multiple control flow paths, the following ones are the interesting ones:
1st: https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L270-L273
2nd: https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L301-L320

It can be seen that in both paths a word from source can be copied to the destination.

Note that the function itself contains the following note: 
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L245-L247

That is we can ask for a copy of `1B` yet a whole word is copied.

Now, if the `dst_data`'s distance to the end of the concat data buffer is `< 32B`, the `copy_op = STORE(dst, LOAD(src))` from `copy_bytes` will result in buffer overflow as it essentially will `mstore` to `dst_data` the `mload` of the source (mload will load whole word and the distance of the `dst_data` to the word boundary is `<32B`). The argumentation for the 2nd path in `copy_bytes` is analogical.

### PoC
The main attack vector that was found was when the `concat` is inside an `internal` function or in `__init__()`.  Suppose we have an `external` function that calls `internal` one. In such case the address space is divided such that the memory for the internal function is in _lower_  portion of the adr space. As such the buffer overflow can overwrite _valid_ data of the caller.

Here is a simple example:
```python
#@version ^0.3.9

@internal
def bar() -> uint256:
    sss: String[2] = concat("a", "b") 
    return 1


@external
def foo() -> int256:
    a: int256 = -1
    b: uint256 = self.bar()
    return a 
```

`foo` should clearly return `-1`, but it returns `452312848583266388373324160190187140051835877600158453279131187530910662655`

`-1` was used intentionally due to its bit structure but the value here is fairly irelevant. In this example during the second iteration of the for loop in the `build_IR` `mload` to `dst+1` will be executed (because len('a') == 1), thus the function will write `1B` over the bounds of the buffer. The string 'b' is stored such that the right-most byte of the word is a zero byte. So,a zero byte will be written over the bounds. So when `-1` is considered, it's left-most byte will be overwritten to all 0. Therefore it can be seen that: `452312848583266388373324160190187140051835877600158453279131187530910662655 == (2**248-1)` will output `True`.

#### Analysis of IR
If we look at the contract's IR (vyper --no-optimize -f it) we see:
```
# Line 30
                          /* a: int256 = -1 */ [mstore, 320, -1 <-1>],
```
And for the second iteration of the loop in concat:
```
 len,
                        [mload, arg],
                        [seq,
                          [with,
                            src,
                            [add, arg, 32],
                            [with,
                              dst,
                              [add, [add, 256 <concat destination>, 32], concat_ofst],
                              [mstore, dst, [mload, src]]]],
                          [set, concat_ofst, [add, concat_ofst, len]]]]],
                    [mstore, 256 <concat destination>, concat_ofst],
                    256 <concat destination>]],
```
So the address of the `int` is 320. 

The `dst` is defined as: `[add, [add, 256 <concat destination>, 32], concat_ofst],`.
In the second iteration the `concat_ofst` will be 1 because `len('a)==1` so `256+32+1 = 289`. Now this address will be `mstored` to - so the last mstored B will have the address `289+32=321` which clearly overlaps with the address of the `int a`.

#### 2nd path and `__init__()`

To demonstrate the vulnerability in the second mentioned path (longer `length_bound` - the general case):
```python
#@version ^0.3.9

s: String[1]
s2: String[33]
s3: String[34]


@external
def __init__():
    self.s = "a"
    self.s2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" # 33*'a'
    

@internal
def bar() -> uint256:
    self.s3 = concat(self.s, self.s2)
    return 1


@external
def foo() -> int256:
    i: int256 = -1
    b: uint256 = self.bar()
    return i
```
Output of calling `foo() is `452312848583266388373324160190187140051835877600158453279131187530910662655`.

And lastly, a PoC for the `__init__()` function, in such case the `immutables` can be overwritten:
```python
#@version ^0.3.9

i: immutable(int256)

@external
def __init__():
    i = -1
    s: String[2] = concat("a", "b")

@external
def foo() -> int256:
    return i
```

Output of calling `foo()` is `452312848583266388373324160190187140051835877600158453279131187530910662655`.

## Impact
The buffer overflow can result in a _complete_ change of *semantics* of the contract, which is even worse if an attacker controls the inputs to the function. Because the overflow doesn't have to happen each time it might go unnoticed during contract testing and vulnerable code can be deployed on chain.

However, not all usages of `concat` will result in overwriting valid data as we require it to be in an `internal` function and close to the `return` statement where other memory allocations don't occur. As such the likelihood is considered medium.

It seems that the bug was introduced in: `548d35d720fb6fd8efbdc0ce525bed259a73f0b9`. `git bisect` was used between `v0.3.1` (which seems to be good) and `v0.3.2` (which was already bad) and `forge test` was run and the test asserted that the function indeed returns -1. So contracts deployed with `vyper` after this commit might be affected.

## Tools Used
Manual review to find the bug. boa + forge + git bisect for testing.

## Recommendations
One possible solution would be overallocate the buffer used for the concatenation. It must be ensured that even if the source arguments are copied to the destination when the destination is close to the buffer end (ie distance is <32B), it will not result in a buffer overflow.

# Medium Risk Findings

## <a id='M-01'></a>M-01. vyper-serve unable to compile bytecode due to changes in vyper_compile.py's compile_files function definition

_Submitted by [cryptonoob](/profile/clmo2h6lp0000ky089r3nlixn)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/0b740280c1e3c5528a20d47b29831948ddcc6d83/vyper/cli/vyper_compile.py#L279-L287

https://github.com/vyperlang/vyper/blob/0b740280c1e3c5528a20d47b29831948ddcc6d83/vyper/cli/vyper_serve.py#L85-L97

## Summary

In vyper's version 0.3.10 vyper-serve is unable to compile bytecode HTTP requests due to changes made on cli/vyper_compile.py's compile_files function parameters definitions as shown below.  
This made unable to use vyper-serve to compile contracts via HTTP

## Vulnerability Details

On vyper's 0.3.9 version the cli/vyper_compile.py's compiles_files function declaration is the following:  
```
# cli/vyper_compile.py version 0.3.9
def compile_files(
    input_files: Iterable[str],
    output_formats: OutputFormats,
    root_folder: str = ".",
    show_gas_estimates: bool = False,
    evm_version: str = DEFAULT_EVM_VERSION,
    no_optimize: bool = False,
    storage_layout: Iterable[str] = None,
    no_bytecode_metadata: bool = False,
) -> OrderedDict:
	# ...
```
However, vyper's cli/vyper_compile.py's compile_files 0.3.10rc3 version removes EVM_VERSION_FIELD paramater:  
```
# cli/vyper_compile.py version 0.3.10rc3  
def compile_files(
    input_files: Iterable[str],
    output_formats: OutputFormats,
    root_folder: str = ".",
    show_gas_estimates: bool = False,
    settings: Optional[Settings] = None,
    storage_layout: Optional[Iterable[str]] = None,
    no_bytecode_metadata: bool = False,
) -> OrderedDict:
	# ... 
```
compile_files is called on vyper_serve.py with evm_version as an argument:  
```
# vyper_serve.py
def _compile(self, data):
        code = data.get("code")
        # ... 
        try:
            code = data["code"]
            out_dict = vyper.compile_codes(
                {"": code},
                list(vyper.compiler.OUTPUT_FORMATS.keys()),
                evm_version=data.get("evm_version", DEFAULT_EVM_VERSION),	# <<== EVM_VERSION 
            )[""]
```
So, now the arguments passed to cli/vyper_compile.py aren't valid and vyper_serve.py is not able to produce bytecode anymore.  

An easy way to comprobe this vulnerability is installing both versions (0.3.9 and 0.3.10rc3) as shown next:  
- Step 1 Install 0.3.9 and launch vyper-serve:  
In one terminal install 0.3.9 version:  
```
cd /tmp/
virtualenv vyper_venv9
source vyper_venv9/bin/activate
pip install vyper==0.3.9
vyper --version
```
Start vyper-serve:  
```
vyper-serve
```
Using an http request compile a contract:  
```
curl -X POST localhost:8000/compile -H "Content-Type: application/json" -d '{"code": "\n\n# @version ^0.3.7\n\n@external\ndef foo():\n    pass\n"}'
```
Observe the successful response:  
```
{
  "ast_dict": {
    "contract_name": "",
    "ast": {
      "ast_type": "Module",
      "src": "0:50:0",
      "end_col_offset": 8,
      "doc_string": null,
      "node_id": 0,
      "lineno": 1,
      "body": [
        {
          "args": {
            "args": ...
		}
	...
}
```
Stop the vyper-serve using `Ctrl-C`  

- Step 2 Observe vyper-serve 0.3.10 is unable to compile bytecode  
Install 0.3.10 version:  
```
cd /tmp/
virtualenv vyper_venv10
source vyper_venv10/bin/activate
pip install vyper==0.3.10rc3
vyper --version
```
Start vyper-serve:  
```
vyper-serve
```
Using an http request try to compile the same contract:  
```
curl -X POST localhost:8000/compile -H "Content-Type: application/json" -d '{"code": "\n\n# @version ^0.3.7\n\n@external\ndef foo():\n    pass\n"}'
```
Observe the response:  
```
curl: (52) Empty reply from server
```
And the stack trace from vyper-serve console:  
```
----------------------------------------
Exception occurred during processing of request from ('127.0.0.1', 44642)
Traceback (most recent call last):
  File "/usr/lib/python3.10/socketserver.py", line 683, in process_request_thread
    self.finish_request(request, client_address)
  File "/usr/lib/python3.10/socketserver.py", line 360, in finish_request
    self.RequestHandlerClass(request, client_address, self)
  File "/usr/lib/python3.10/socketserver.py", line 747, in __init__
    self.handle()
  File "/usr/lib/python3.10/http/server.py", line 433, in handle
    self.handle_one_request()
  File "/usr/lib/python3.10/http/server.py", line 421, in handle_one_request
    method()
  File "/tmp/vyper_venv10/lib/python3.10/site-packages/vyper/cli/vyper_serve.py", line 72, in do_POST
    response, status_code = self._compile(data)
  File "/tmp/vyper_venv10/lib/python3.10/site-packages/vyper/cli/vyper_serve.py", line 94, in _compile
    out_dict = vyper.compile_codes(
TypeError: compile_codes() got an unexpected keyword argument 'evm_version'
----------------------------------------
```
This is due to the change made on compile_files explained above.  

## Impact

Users can't use vyper-serve to compile bytecode leading to a loss of functionality / denial of service    

Impact: Low  
Likehood: High  

CVSS Medium - 4.3  
AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L

## Tools Used 

Manual analysis

## Recommended Mitigation

Change cli/vyper_compile.py compile_files function definition to take into account the evm_version argument from `vyper_serve.py@_compile` function (for example in version 0.3.9)

## <a id='M-02'></a>M-02. SHA3_64 Vulnerability in compile_ir.py

_Submitted by [KuroHashDit](/profile/cln6wuqc6000ol808dd8imjox)._      
				


## Summary

There is an error in the calculation of SHA3_64, which will produce wrong hash results and may affect the access of HashMap objects.

## Vulnerability Details
line 583 in compile_ir.py

	# SHA3 a 64 byte value
	elif code.value == "sha3_64":
		o = _compile_to_assembly(code.args[0], withargs, existing_labels, break_dest, height)
		o.extend(_compile_to_assembly(code.args[1], withargs, existing_labels, break_dest, height))
		o.extend(
			[
				*PUSH(MemoryPositions.FREE_VAR_SPACE2),
				"MSTORE",
				*PUSH(MemoryPositions.FREE_VAR_SPACE),
				"MSTORE",
				*PUSH(64),
				*PUSH(MemoryPositions.FREE_VAR_SPACE),
				"SHA3",
			]
		)
		return o

o.extend(_compile_to_assembly(code.args[1], withargs, existing_labels, break_dest, height)) should be on height+1. This code will affect the correct access of the withargs variable.

## Impact

Because SHA3_64 is related to the reading and writing of HashMap objects, it has an important impact on the data on the contract chain. The overall impact should be high level.

POC Code:

	(with _loc
		(with val 1 
			(with key 2 
				(sha3_64 val key))) 
					(seq 
						(sstore _loc 
						(with x (sload _loc) 
							(with ans (add x 1) (seq (assert (ge ans x)) ans))))))

python -m vyper --vyper-ir bug.ir

the generated bytecode: 6001600281806020525f5260405f2090509050805460018101818110610026579050815550005b5f80fd

	0000    60  PUSH1 0x01
	0002    60  PUSH1 0x02
	0004    81  DUP2
	0005    80  DUP1       *********** bad code here!!!!!!
	0006    60  PUSH1 0x20
	0008    52  MSTORE
## <a id='M-03'></a>M-03. `RawCall` builtin function allows passing a value in unsupported calls

_Submitted by [pcaversaccio](/profile/clnokqa930000kz08em1nx9xo), [0xdeadbeef](/profile/clke8rp1x0004jy08e1ddz8s0). Selected submission by: [0xdeadbeef](/profile/clke8rp1x0004jy08e1ddz8s0)._      
				
### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-09-vyper-compiler/blob/main/vyper/builtins/functions.py#L1100

## Summary

Vyper compiler allows passing a value in builtin `raw_call` even if the call is a delegatecall or staticcall.
This is very dangerous in implementations such as multicall.
As a real world example, the popular `snekmate` library multicall util is vulnerable due to the insufficient checks in the vyper compiler 

## Vulnerability Details

The `RawCall` handler of the builtin function does not check that if `value` is passed to the builtin function and `is_delegate_call` or `is_static_call` is true:
https://github.com/Cyfrin/2023-09-vyper-compiler/blob/main/vyper/builtins/functions.py#L1100
```python
class RawCall(BuiltinFunction):
---------
    def build_IR(self, expr, args, kwargs, context):
---------
        gas, value, outsize, delegate_call, static_call, revert_on_failure = (
            kwargs["gas"],
            kwargs["value"],
            kwargs["max_outsize"],
            kwargs["is_delegate_call"],
            kwargs["is_static_call"],
            kwargs["revert_on_failure"],
        )
---------
        if delegate_call:
            call_op = ["delegatecall", gas, to, *common_call_args] # @audit should check that if is_delegate_call then value == 0 
        elif static_call:
            call_op = ["staticcall", gas, to, *common_call_args] # @audit should check that if is_static_call then value == 0 
        call_ir += [call_op]
---------
            return IRnode.from_list(call_ir, typ=typ)
```

Here is an example implementation in vyper that will be successfully compiled and deployed:
```python
event logUint256:
    logged_uint256: indexed(uint256)

@external
@payable
def delegatedTo1():
    log logUint256(msg.value)

@external
@payable
def delegatedTo2():
    log logUint256(msg.value)

@external
@payable
def delegateToSelf():
    return_data: Bytes[300] = b""
    call_data1: Bytes[100] = _abi_encode(b"",method_id=method_id("delegatedTo1()"))
    call_data2: Bytes[100] = _abi_encode(b"",method_id=method_id("delegatedTo2()"))

    return_data = raw_call(self, call_data1, max_outsize=255, is_delegate_call=True, value=msg.value/2)
    return_data = raw_call(self, call_data2, max_outsize=255, is_delegate_call=True, value=msg.value/2)
``` 

In the above example, the developer would expect to receive the passed `msg.value/2` in delegatedTo1/2 however they would receive the full `msg.value`

Transaction trace when sending `100` to `delegateToSelf` shows that both delegatecalls output `100(0x64)` instead of `50`:
```
    function test_incorrectMsgValueDelegatecall() external {
        address vyper = address(0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0);
        vyper.call{value: 100}(abi.encodeWithSignature("delegateToSelf()"));
    }

--------

Running 1 test for test/Counter.t.sol:CounterTest
[PASS] test_incorrectMsgValueDelegatecall() (gas: 13858)
Traces:
  [13858] CounterTest::test_incorrectMsgValueDelegatecall() 
    ├─ [3956] 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0::delegateToSelf{value: 100}() 
    │   ├─ [27] PRECOMPILE::identity(0x) [staticcall]
    │   │   └─ ← 0x
    │   ├─ [27] PRECOMPILE::identity(0x) [staticcall]
    │   │   └─ ← 0x
    │   ├─ [1221] 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0::541c930c(00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000) [delegatecall]
    │   │   ├─  emit topic 0: 0xd74736c81b9d709d9d3cc16b682a1075c6b99b57b848fefb07ba5368ff27827d
    │   │   │       topic 1: 0x0000000000000000000000000000000000000000000000000000000000000064
    │   │   │           data: 0x
    │   │   └─ ← ()
    │   ├─ [18] PRECOMPILE::identity(0x) [staticcall]
    │   │   └─ ← 0x
    │   ├─ [1221] 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0::f0b781bd(00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000) [delegatecall]
    │   │   ├─  emit topic 0: 0xd74736c81b9d709d9d3cc16b682a1075c6b99b57b848fefb07ba5368ff27827d
    │   │   │       topic 1: 0x0000000000000000000000000000000000000000000000000000000000000064
    │   │   │           data: 0x
    │   │   └─ ← ()
    │   ├─ [18] PRECOMPILE::identity(0x) [staticcall]
    │   │   └─ ← 0x
    │   └─ ← ()
    └─ ← ()

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 186.29ms
```
 
In solidity however this is not possible. The compiler would throw an error:
```solidity
pragma solidity 0.8.17;

contract SolidityDelegatecallValue {
    function tryMe() external {
        (bool succeess, bytes memory retVal) = address(this).delegatecall{value: 100}("");
    }

    receive() external payable {}
}
```

When compiling:
```
Error: 
Compiler run failed:
Error (6189): Cannot set option "value" for delegatecall.
 --> src/solidity_delegatecall_value.sol:5:48:
  |
5 |         (bool succeess, bytes memory retVal) = address(this).delegatecall{value: 100}("");
  |                                                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

## Impact

This allows developers to perform a delegatecall or staticcall with a value that will not be used because of the nature of delegatecall and staticcall. This can disrupt accounting and easily be missed by developers thus causing a loss of funds

This would be extremely proplematic in multicall implementations.
A real world example is the implementation of the popular `snekmate` libraries:
https://github.com/pcaversaccio/snekmate/blob/5fe40ea7376b0405244d6c3f4f4f6c7b047c146b/src/utils/Multicall.vy#L169
```python
@external
@payable
def multicall_value_self(data: DynArray[BatchValueSelf, max_value(uint8)]) -> DynArray[Result, max_value(uint8)]:
------
    value_accumulator: uint256 = empty(uint256)
    results: DynArray[Result, max_value(uint8)] = []
    return_data: Bytes[max_value(uint8)] = b""
    success: bool = empty(bool)
    for batch in data:
        msg_value: uint256 = batch.value
        value_accumulator = unsafe_add(value_accumulator, msg_value)
        if (batch.allow_failure == False):
            return_data = raw_call(self, batch.call_data, max_outsize=255, value=msg_value, is_delegate_call=True)
            success = True
            results.append(Result({success: success, return_data: return_data}))
        else:
            success, return_data = \
                raw_call(self, batch.call_data, max_outsize=255, value=msg_value, is_delegate_call=True, revert_on_failure=False)
            results.append(Result({success: success, return_data: return_data}))
    assert msg.value == value_accumulator, "Multicall: value mismatch"
    return results
```

## Tools Used

Foundry, Vyper

## Recommendations

Throw an exception `RawCall.build_ir` in `builtins/functions.py` if `value` is not `0` and `is_delegate_call` or `is_static_call` are true.
## <a id='M-04'></a>M-04. Contract interfaces allow nonpayable implementations of payable functions

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3ba14124602b673d45b86bae7ff90a01d782acb5/vyper/semantics/types/user.py#L316-L331

## Summary

When a contract interface is implemented, the compiler checks that each function in the interface has a corresponding public function in the contract. However, it does not check that the functions have the same visibility, which can lead to dangerous situations.

## Vulnerability Details

When performing semantic analysis on a contract that implements an interface, the compiler calls `type_.validate_implements(node)` to confirm that the interface is correctly implemented.

This function iterates through all public functions on the interface, checks that we have implemented a function with the same name, and then verifies that all the arguments and return types are of the same type. Finally, it checks that the state mutability of our function is not greater than the interface.
```python
def implements(self, other: "ContractFunctionT") -> bool:
    """
    Checks if this function implements the signature of another
    function.

    Used when determining if an interface has been implemented. This method
    should not be directly implemented by any inherited classes.
    """

    if not self.is_external:
        return False

    arguments, return_type = self._iface_sig
    other_arguments, other_return_type = other._iface_sig

    if len(arguments) != len(other_arguments):
        return False
    for atyp, btyp in zip(arguments, other_arguments):
        if not atyp.compare_type(btyp):
            return False

    if return_type and not return_type.compare_type(other_return_type):  # type: ignore
        return False

    if self.mutability > other.mutability:
        return False

    return True
```
If we look at the mutability enum, we can see that "greater than" represents a less restrictive mutability:
```python
class StateMutability(_StringEnum):
    PURE = _StringEnum.auto()
    VIEW = _StringEnum.auto()
    NONPAYABLE = _StringEnum.auto()
    PAYABLE = _StringEnum.auto()
```
This means that, although we cannot take a view function on the interface and implement it as a nonpayable function, we can do the inverse and implement any function as a more restrictive type.

While for some types this may make sense, it can lead to problems with payable functions.

Interfaces are intended to define the behavior that is required for a contract to perform. If an interface defines a function as payable, it is safe for interacting contracts to send ETH to that function. However, if a contract that implements that interface changes that function to nonpayable (or to view), it could cause the interacting contracts to revert.

## Impact

Contracts that Vyper considers to be correctly implementing an interface may not reflect the expectations of the interface, and interacting contracts may end up locked because they expect to be able to send ETH to a function that is not payable.

Note that Solidity has a similar check that "lower" mutabilities are acceptable when implementing an interface, but has a specific carveout for payable functions to avoid this risk. See the table below for a breakdown of the similarities and differences.

------------------------- Solidity ------------ Vyper
view => nonpayable          NO                    NO    ✓
view => payable             NO                    NO    ✓
nonpayable => view/getter   YES                   YES   ✓
nonpayable => payable       NO                    NO    ✓
payable => view/getter      NO                    YES   <== this is the issue
payable => nonpayable       NO                    YES   <== this is the issue

## Tools Used

Manual Review

## Recommendations

In the `implements()` function, check whether the mutability of the function on the interface is payable. If it is, require the implementing contract to make the function payable as well.
## <a id='M-05'></a>M-05. Slice bounds check can be overflowed to access unrelated data

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/builtins/functions.py#L404-L457

https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/builtins/functions.py#L319-L331

## Summary

The bounds check for slices does not account for the ability for `start + length` to overflow when the start value is not a literal. This creates the ability for an attacker to overflow the bounds check to use the `slice()` built-in to access either (a) an unrelated storage slot or (b) the previous word of memory.

## Vulnerability Details

When calling `slice()` there are compile time bounds checks if the `start` and `length` values are literals, but of course this cannot happen if they are passed values:
```python
if not is_adhoc_slice:
    if length_literal is not None:
        if length_literal < 1:
            raise ArgumentException("Length cannot be less than 1", length_expr)

        if length_literal > arg_type.length:
            raise ArgumentException(f"slice out of bounds for {arg_type}", length_expr)

    if start_literal is not None:
        if start_literal > arg_type.length:
            raise ArgumentException(f"slice out of bounds for {arg_type}", start_expr)
        if length_literal is not None and start_literal + length_literal > arg_type.length:
            raise ArgumentException(f"slice out of bounds for {arg_type}", node)
```

At runtime, we perform the following equivalent check, but the runtime check does not account for overflows:
```python
["assert", ["le", ["add", start, length], src_len]],  # bounds check
```

This same issue exists if the bytestring being sliced is in memory or storage:

The storage `slice()` function copies bytes directly from storage into memory and returns the memory value of the resulting slice. This means that, if a user is able to input the `start` value, they can force an overflow and access an unrelated storage slot. In most cases, this will mean they have the ability to forceably return `0` for the slice, even if this shouldn't be possible. In extreme cases, it will mean they can return another unrelated value from storage.

The memory `slice()` function returns the memory value of the resulting slice. There is a check as part of the process that `start + 32 < length`, which means that for the overflow to be possible `start` must be greater than `max uint256 - 31`. As a result, the returned slice can be any slice starting up to 32 bytes before the variable that is being sliced.

## Proof of Concept

For simplicity, take the following Vyper contract, which takes an argument to determine where in a `Bytes[64]` bytestring should be sliced. It should only accept a value of zero, and should revert in all other cases.
```python
# @version ^0.3.9

x: public(Bytes[64])
secret: uint256

@external
def __init__():
    self.x = empty(Bytes[64])
    self.secret = 42

@external
def slice_it(start: uint256) -> Bytes[64]:
    return slice(self.x, start, 64)
```
We can use the following manual storage to demonstrate the vulnerability:
```python
{"x": {"type": "bytes32", "slot": 0}, "secret": {"type": "uint256", "slot": 3618502788666131106986593281521497120414687020801267626233049500247285301248}}
```
If we run the following test, passing `max - 63` as the `start` value, we will overflow the bounds check, but access the storage slot at `1 + (2**256 - 63) / 32`, which is what was set in the above storage layout:
```solidity
function test__slice_error() public {
    c = SuperContract(deployer.deploy_with_custom_storage("src/loose/", "slice_error", "slice_error_storage"));
    bytes memory result = c.slice_it(115792089237316195423570985008687907853269984665640564039457584007913129639872); // max - 63
    console.logBytes(result);
}
```
The result is that we return the secret value from storage:
```md
Logs:
0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a
```

For a memory slice, see the following contract:
```python
# @version ^0.3.9

@external
def slice_it_mem(start: uint256) -> Bytes[32]:
    x: uint256 = 2345908340958
    y: Bytes[32] = b"\x05\x05"
    return slice(y, start, 32)
```
If we pass `max uint256 - 31` as the start, we will be returned `2` (the length of the bytestring). If we pass `max uint256 - 30`, we will be returned `205` (the length plus the first element of the left aligned bytestring). If we pass `max uint256 - 29`, we will be returned `20505`, etc.

## Impact

The built-in `slice()` method can be used to read unrelated storage slots or memory locations by abusing a bounds check overflow.

## Tools Used

Manual Review, Foundry

## Recommendations

Update the bounds check to also include a check that `start + length > start` to ensure no overflow is possible.
## <a id='M-06'></a>M-06. External calls can overflow return data to return input buffer

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/9ce56e7d8b0196a5d51d706a8d2376b98d3e8ad7/vyper/codegen/external_call.py#L33-L142

## Summary

When calls to external contracts are made, we write the calldata starting at byte 28, and allocate the return buffer to start at byte 0 (overlapping with the calldata). When checking `RETURNDATASIZE` for dynamic types, the size is compared only to the minimum allowed size for that type, and not to the returned value's `length`. As a result, malformed return data can cause the contract to mistake its own calldata for returndata.

## Vulnerability Details

When arguments are packed for an external call, we create a buffer of size `max(args, return_data) + 32`. The calldata is placed in this buffer (starting at byte 28), and the return buffer is allocated to start at byte 0. The assumption is that we can reuse the memory becase we will not be able to read past `RETURNDATASIZE`.

```python
if fn_type.return_type is not None:
    return_abi_t = calculate_type_for_external_return(fn_type.return_type).abi_type

    # we use the same buffer for args and returndata,
    # so allocate enough space here for the returndata too.
    buflen = max(args_abi_t.size_bound(), return_abi_t.size_bound())
else:
    buflen = args_abi_t.size_bound()

buflen += 32  # padding for the method id
```

When data is returned, we unpack the return data by starting at byte 0. We check that `RETURNDATASIZE` is greater than the minimum allowed for the returned type:
```python
if not call_kwargs.skip_contract_check:
    assertion = IRnode.from_list(
        ["assert", ["ge", "returndatasize", min_return_size]],
        error_msg="returndatasize too small",
    )
    unpacker.append(assertion)
```

This check ensures that any dynamic types returned will have a size of at least 64. However, it does not verify that `RETURNDATASIZE` is as large as the `length` word of the dynamic type. 

As a result, if a contract expects a dynamic type to be returned, and the part of the return data that is read as `length` includes a size that is larger than the actual `RETURNDATASIZE`, the return data read from the buffer will overrun the actual return data size and read from the calldata.

## Proof of Concept

This contract calls an external contract with two arguments. As the call is made, the buffer includes:
- byte 28: method_id
- byte 32: first argument (0)
- byte 64: second argument (hash)

The return data buffer begins at byte 0, and will return the returned bytestring, up to a maximum length of 96 bytes.

```python
interface Zero:
    def sneaky(a: uint256, b: bytes32) -> Bytes[96]: view

@external
def test_sneaky(z: address) -> Bytes[96]:
    return Zero(z).sneaky(0, keccak256("oops"))
```
On the other side, imagine a simple contract that does not, in fact, return a bytestring, but instead returns two uint256s. I've implemented it in Solidity for ease of use with Foundry:
```solidity
function sneaky(uint a, bytes32 b) external pure returns (uint, uint) {
    return (32, 32);
}
```

The return data will be parsed as a bytestring. The first 32 will point us to byte 32 to read the length. The second 32 will be perceived as the length. It will then read the next 32 bytes from the return data buffer, even though those weren't a part of the return data.

Since these bytes will come from byte 64, we can see above that the hash was placed there in the calldata.

If we run the following Foundry test, we can see that this does in fact happen:
```solidity
function test__sneakyZeroReturn() public {
    ZeroReturn z = new ZeroReturn();
    c = SuperContract(deployer.deploy("src/loose/", "ret_overflow", ""));
    console.logBytes(c.test_sneaky(address(z)));
}
```

```md
Logs:
  0xd54c03ccbc84dd6002c98c6df5a828e42272fc54b512ca20694392ca89c4d2c6
```

## Impact

Malicious or mistaken contracts returning the malformed data can result in overrunning the returned data and reading return data from the calldata buffer.

## Tools Used

Manual Review, Foundry

## Recommendations

If we want to continue to use the same buffer for calldata and return data, add an additional safety check for dynamic return types that the `RETURNDATASIZE` is checked against the bytes that will be unpacked as the length.

Alternatively, allocate the return data buffer separately in memory.
## <a id='M-07'></a>M-07. Array signed int access

_Submitted by [Franfran](/profile/clnru86oh0000lf08selovtfc)._      
				


## Summary

Arrays can be keyed by a signed integer, while they are defined for unsigned integers only.

## Vulnerability Details

Let's take a toy example:

```py
arr: public(uint256[MAX_UINT256])

@external
def set(idx: int256, num: uint256):
    self.arr[idx] = num
```

This compile, and works!

If we generate the `ir` using `vyper src/array.vy -f ir`, we get this:

```sh
[iszero, [xor, _calldata_method_id, 2720814400 <0xa22c5540: set(int256,uint256)>]],
[seq,
  [assert, [iszero, [or, callvalue, [lt, calldatasize, 68]]]],
  [seq,
    [goto, external_set__int256_uint256__common],
    # Line 4
    [seq,
      [label,
        external_set__int256_uint256__common,
        var_list,
        [seq,
          [seq,
            [unique_symbol, sstore_2],
            /* store the value at index */
            [sstore,
              [with,
                clamp_arg,
                /* load the array index */
                [calldataload, 4 <idx (4+0)>],
                /* make sure that the int is not 2**255, max is 2**255 - 1 */
                [seq,
                  [assert,
                    [ne,
                      clamp_arg,
                      115792089237316195423570985008687907853269984665640564039457584007913129639935]],
                  clamp_arg]],
              /* load the array value */
              [calldataload, 36 <num (4+32)>]]],
          [exit_to, external_set__int256_uint256__cleanup],
          pass]],
      [label, external_set__int256_uint256__cleanup, var_list, stop]]]]
```

There is a warning when compiling that says `UserWarning: Use of large arrays can be unsafe!`, but please note that this will bail out for any array length that is less than `64 bits` long. The reason this warning is up is because an arbitrary long array could give the opportunity to write already used storage slots.

We could write a code that doesn't trigger this warning, such as

```vyper
arr: public(uint256[max_value(uint32)])

@external
def set(idx: int16, num: uint256):
    self.arr[idx] = num
```

One could assume in a more tailored smart contract that any array access that is out of bound or at least less than 0 will revert but signed integer can also have an unsigned bitwise equivalent which could cause some collisions in the storage.
For instance, `0` in the signed integer representation can be expressed with either `0x000..000`, or `0x800..000` (`-0`). These two indexes will be different, so allowing to key an array from a signed integer doesn't seems to be something that we wouldn't restrict.

## Impact

This could cause sne(a)ky accesses to forbidden storage slots.

## Tools Used

Manual review

## Recommendations

Add a type check for the `Subscriptable` node and make sure that types matches.

# Low Risk Findings

## <a id='L-01'></a>L-01. [M-01] Compiler fails to revert if a negative integer is passed as a uint datatype.

_Submitted by [DarkTower ](/team/clmuj4vc00005mo08knfwx1dl)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/tree/v0.3.10rc3/vyper

## Vulnerability Details
The incorrect built-in type checker of the compiler leads a negative integer passing as a value in uint2str. This poses to be a severe issue that can go unnoticed for vyper developers.

As the vyper compiler [documentation](https://docs.vyperlang.org/en/stable/compiler-exceptions.html) lays out:
> uint2str(value: unsigned integer)→ String
> Returns an unsigned integer’s string representation.
>       - value: Unsigned integer to convert.
>       - Returns the string representation of value.


Code snippet example where the compiler fails to revert is provided below: 

```python
@external
def testFoobar():
    a: String[78] = uint2str(-12)
    pass
```

On compilation, this returns:
```python
0x61007761000f6000396100776000f36003361161000c57610062565b5f3560e01c346100665763f8a8fd6d811861006057600360c0527f2d3130000000000000000000000000000000000000000000000000000000000060e05260c0805160208201805160605250806040525050005b505b5f5ffd5b5f80fda165767970657283000309000b
```

## Impact
Misleads developers and results in an unexpected underflow.

## Tools Used
Manual Review

## Recommendations
Adding a check on the Vyper language compiler when a negative integer is passed to the `uint2str` param should render a fix to this issue.
## <a id='L-02'></a>L-02. Builtins that access literal lists cannot be compiled

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0), [Bauchibred](/profile/clk9ibj6p0002mh08c603lr2j), [DarkTower ](/team/clmuj4vc00005mo08knfwx1dl). Selected submission by: [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3ba14124602b673d45b86bae7ff90a01d782acb5/vyper/builtins/functions.py#L460-L463

https://github.com/vyperlang/vyper/blob/3ba14124602b673d45b86bae7ff90a01d782acb5/vyper/builtins/_signatures.py#L82-L103

https://github.com/vyperlang/vyper/blob/3ba14124602b673d45b86bae7ff90a01d782acb5/vyper/semantics/analysis/utils.py#L527

## Summary

When types are validated for literal lists passed to builtin functions, we perform the following check:
```python
if not isinstance(expected, (DArrayT, SArrayT)):
```
However, in this scenario, `expected` is the type class, not an instance, so it always fails. As a result, the compilation fails.

## Vulnerability Details

We will use the builtin `len()` function to demonstrate this issue.

The `len()` function accepts a single argument, which can be either a string, byte array or dynamic array:
```python
_inputs = [("b", (StringT.any(), BytesT.any(), DArrayT.any()))]
```
All builtin functions implement the `BuiltinFunction` class, which calls the `_validate_arg_types()` function, which calls `self._validate_single()` for all arguments.

In the case of the `len()` function being called with a literal list, the argument passed to `_validate_single()` is the list node, and the expected type is a tuple of the allowed type classes:
```python
(<class 'vyper.semantics.types.bytestrings.StringT'>, <class 'vyper.semantics.types.bytestrings.BytesT'>, <class 'vyper.semantics.types.subscriptable.DArrayT'>)
```

This calls the `validate_expected_type()`, where the `given_types` returns all the possible types for the literal list.

In the event that the node is a literal list, we go down this code path:
```python
# if it's a literal list, validate: expected contains array, lengths match, each item matches
if isinstance(node, vy_ast.List):
    # special case - for literal arrays we individually validate each item
    for expected in expected_type:
        if not isinstance(expected, (DArrayT, SArrayT)):
            continue
        if _validate_literal_array(node, expected):
            return
```
As we can see, this checks that `isinstance(expected, (DArrayT, SArrayT))`. Only when this is the case does it proceed to the `_validate_literal_array()` function, which allows us to return safely without an error.

Unfortunately, `isinstance()` tells us if an instance fits a given type. But `expected` is not an instance — it is the type class itself. As a result, this check will always fail, and the compilation will fail.

## Proof of Concept

The following Vyper contracts will fail to compile due to this error:
```python
# @version ^0.3.9

x: uint256

@external
def __init__():
    self.x = len([1, 2, 3])
```

```python
# @version ^0.3.9

number: public(uint256)
exampleList: constant(DynArray[uint256, 3]) = [1, 2, 3]

@external
def __init__():
    self.number = len(exampleList)
```

## Impact

Contracts that include literal lists as arguments to builtin functions will fail to compile.

## Tools Used

Manual Review

## Recommendations

In `validate_expected_type()`, adjust the check to ensure that the expected type matches with `DArrayT` or `SArrayT`, rather than requiring it to be an instance of it.

## <a id='L-03'></a>L-03. ContractFunctionT.from_abi fails to gracefully handle a valid JSON ABI interface that represents `__default__` and/or `__init__` function

_Submitted by [0xZRA](/profile/cllln8wzi000amj08ewcv68en)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/v0.3.10rc3/vyper/semantics/types/function.py#L128

## Summary
ContractFunctionT.from_abi can't handle code with __default__ and/or __init__ methods provided with the object from a valid JSON ABI interface representing a function. 

## Vulnerability Details
    Both `__init__` and `__default__` methods are missing `name` and `inputs` items respectively (although due to valid reasons) in their ABIs which leads to `ContractFunctionT.from_abi` method failure to generate a `ContractFunctionT` object.
    Steps to reproduce:
    1 - add sample `.vy` code to a standalone file
    2 - produce abi by running `vyper -f abi <path-to-the-file>`:
    root@06f545b1d4b9:/workspaces/vyper# vyper -f abi tests/sample_code_from_abi.vy         
    [{"stateMutability": "nonpayable", "type": "constructor", "inputs": [], "outputs": []}, {"stateMutability": "nonpayable", "type": "fallback"}]    
    3 - pass ABI payload to `ContractFunctionT.from_abi` method
    4 - confirm asserts fail with KeyError for both cases

Add a new test `test_init_and_default_fail_to_create_from_abi.py`:
```
import pytest
from vyper.semantics.types.function import ContractFunctionT

@pytest.mark.xfail(raises=KeyError)
def test_init_and_default_fail_to_create_from_abi():
    # content of tests/sample_code_from_abi.vy
    code = """
owner: address
last_sender: address

@external
def __init__():
    self.owner = msg.sender

@external
def __default__():
    self.last_sender = msg.sender
    """
    abi_payload = [{"stateMutability": "nonpayable", "type": "constructor", "inputs": [], "outputs": []}, {"stateMutability": "nonpayable", "type": "fallback"}]       

    init_fn_from_abi=abi_payload[0]
    #Fails with KeyError: 'name'
    init_fn_t = ContractFunctionT.from_abi(abi=init_fn_from_abi)

    default_fn_from_abi=abi_payload[1]
    #Fails with KeyError: 'inputs'
    default_fn_t = ContractFunctionT.from_abi(abi=default_fn_from_abi)
```   

## Impact
Leaving unhandled exceptions can often lead to debugging challenges, unclear behavior, and broken client code. 

## Tools Used
pytest, manual review

## Recommendations
Introduce graceful handling of missing items for these 2 built-in methods to ContractFunctionT.from_abi

## <a id='L-04'></a>L-04. Useless memory allocation bug in RawCall

_Submitted by [KuroHashDit](/profile/cln6wuqc6000ol808dd8imjox)._      
				


## Summary
RawCall has a bug that allocates useless memory.

## Vulnerability Details

prototype of raw_call:
raw_call(to: address, data: Bytes, max_outsize: uint256 = 0, gas: uint256 = gasLeft, value: uint256 = 0, is_delegate_call: bool = False, is_static_call: bool = False, revert_on_failure: bool = True)→ Bytes[max_outsize]

vyper/vyper/builtins/functions.py

    def build_IR(self, expr, args, kwargs, context):
        to, data = args
        # TODO: must compile in source code order, left-to-right
        gas, value, outsize, delegate_call, static_call, revert_on_failure = (
            kwargs["gas"],
            kwargs["value"],
            kwargs["max_outsize"],
            kwargs["is_delegate_call"],
            kwargs["is_static_call"],
            kwargs["revert_on_failure"],
        )


        ........


        output_node = IRnode.from_list(
            context.new_internal_variable(BytesT(outsize)), typ=BytesT(outsize), location=MEMORY
        )


At line 1143, when out_size is 0, a memory of type BytesT(0) will be allocated here with a size of 32 bytes and will never be used. So this should be corrected.

## Impact

Low Risk

## Tools Used

## Recommendations
## <a id='L-05'></a>L-05. compiler crash during assert codegen

_Submitted by [KuroHashDit](/profile/cln6wuqc6000ol808dd8imjox)._      
				


## Summary

There is a crash bug when vyper generates assert code.

## Vulnerability Details

Good Code:

    @external
    def __init__():
        pass

    @external
    def test():
        x: uint256 = 1
        s: String[100] = "error"
        assert x == 1, s

This code works well.

Bad Code:

    s: public(String[100])
    
    @external
    def __init__():
        self.s = "error"


    @external
    def test():
        x: uint256 = 1
        assert x == 1, self.s

This code will cause the compiler to crash.

ROOT CAUSE:

vyper/vyper/semantics/analysis/annotation.py

    class StatementAnnotationVisitor(_AnnotationVisitorBase):
    ignored_types = (vy_ast.Break, vy_ast.Continue, vy_ast.Pass, vy_ast.Raise)

    def __init__(self, fn_node: vy_ast.FunctionDef, namespace: dict) -> None:
        self.func = fn_node._metadata["type"]
        self.namespace = namespace
        self.expr_visitor = ExpressionAnnotationVisitor(self.func)

        assert self.func.n_keyword_args == len(fn_node.args.defaults)
        for kwarg in self.func.keyword_args:
            self.expr_visitor.visit(kwarg.default_value, kwarg.typ)

    def visit(self, node):
        super().visit(node)

    def visit_AnnAssign(self, node):
        type_ = get_exact_type_from_node(node.target)
        self.expr_visitor.visit(node.target, type_)
        self.expr_visitor.visit(node.value, type_)

    def visit_Assert(self, node):
        self.expr_visitor.visit(node.test)


in visit_Assert(), it doesn't visit node.msg. Then in /vyper/codegen/expr.py, Expr::parse_Attribute(self) cannot get the type of expression and then the whole compiler crashes.

## Impact
Low Risk


## Recommendations
## <a id='L-06'></a>L-06.  compiler crash during raise codegen

_Submitted by [KuroHashDit](/profile/cln6wuqc6000ol808dd8imjox)._      
				


## Summary

There is a crash bug when vyper generates raise code.

## Vulnerability Details

Good Code:

    @external
    def __init__():
        pass

    @external
    def test():
        x: uint256 = 1
        s: String[100] = "error"
        raise s

This code works well.

Bad Code:

    s: public(String[100])
    
    @external
    def __init__():
        self.s = "error"


    @external
    def test():
        x: uint256 = 1
        raise self.s

This code will cause the compiler to crash.

ROOT CAUSE:

vyper/vyper/semantics/analysis/annotation.py

    class StatementAnnotationVisitor(_AnnotationVisitorBase):
    ignored_types = (vy_ast.Break, vy_ast.Continue, vy_ast.Pass, vy_ast.Raise)

    def __init__(self, fn_node: vy_ast.FunctionDef, namespace: dict) -> None:
        self.func = fn_node._metadata["type"]
        self.namespace = namespace
        self.expr_visitor = ExpressionAnnotationVisitor(self.func)

        assert self.func.n_keyword_args == len(fn_node.args.defaults)
        for kwarg in self.func.keyword_args:
            self.expr_visitor.visit(kwarg.default_value, kwarg.typ)

    def visit(self, node):
        super().visit(node)

    def visit_AnnAssign(self, node):
        type_ = get_exact_type_from_node(node.target)
        self.expr_visitor.visit(node.target, type_)
        self.expr_visitor.visit(node.value, type_)

    def visit_Assert(self, node):
        self.expr_visitor.visit(node.test)


in StatementAnnotationVisitor class, it doesn't has visit_Raise method. Then in /vyper/codegen/expr.py, Expr::parse_Attribute(self) cannot get the type of expression and then the whole compiler crashes.

## Impact
Low Risk

## Recommendations
## <a id='L-07'></a>L-07. vyper can accept conflicting optimization options from cli

_Submitted by [cyberthirst](/profile/cln69xxib000gjt08n37hic1g)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/cli/vyper_compile.py#L174-L178

## Summary
The compiler allows for setting different optimization levels: codesize and gas. These options exclude each other. However, the compiler can be run while supplying both of them.

## Vulnerability Details
The compiler can be run as:
```
vyper --optimize gas --optimize codesize test.vy
```

These are conflicting options, and the compiler should not accept such a configuration - like in the following case:
```python
    if args.no_optimize and args.optimize:
        raise ValueError("Cannot use `--no-optimize` and `--optimize` at the same time!")
```

In the end, the latter option (codesize) is used, which can be easily verified by stopping the compiler in a debugger on the following lines:
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/cli/vyper_compile.py#L174-L178

## Impact
The compiler allows for mutually exclusive options, out of which only 1 is used. As such, the execution of the compiler is not fully predictable.

A user who doesn't realize that the options are exclusive enables both. At the same time he prefers his contracts to be rather `gas` optimized rather `codesize` optimized. Because of the untransparent configuration, his preferences aren't met.

## Tools Used
Manual review, PyCharm debugger.

## Recommendations
Make the options mutually exclusive and stop the compilation process if both are provided.
## <a id='L-08'></a>L-08. crash due to shadowing iterator vars

_Submitted by [cyberthirst](/profile/cln69xxib000gjt08n37hic1g)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/ir/compile_ir.py#L434-L436

## Summary
The compiler crashes with valid input programs containing `sqrt` due to `vyper.exceptions.CompilerPanic: shadowed loop variable range_ix0`.

## Vulnerability Details
The `sqrt` function's IR is generated via `generate_inline_function` which uses a new namespace and context. Additionally, the function's implementation contains a `for loop`.

The for loop present in the body generates a new fresh iterator variable: `range_ix0` independently of the previous contexts. As a result, if there is a call to `sqrt` inside a `for loop`, then there will be a name clash of the iterator variables.

The following assert will not pass and the compiler will crash:
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/ir/compile_ir.py#L434-L436

### PoC
Here is a simple contract triggering the bug:
```python
#@version ^0.3.9

@external
def my_little_test() -> decimal:
    j: decimal = 0.0
    for i in range(666):
        j = sqrt(2.0)
    return j
```

Also contracts like this won't compile:
```python
@external
def my_little_test() -> decimal:
    j: decimal = sqrt(sqrt(666.0))
    return j
```

## Impact
Some valid programs aren't possible to compile. As such developers are forced to code different (and maybe untransparent) contracts to avoid the bug.

## Tools Used
Manual review.

## Recommendations
Implement the `function` as other built-ins via manual `IR` construction.
## <a id='L-09'></a>L-09. crash due to missing var_info in struct attribute

_Submitted by [cyberthirst](/profile/cln69xxib000gjt08n37hic1g)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/semantics/analysis/base.py#L249-L253

## Summary
Compiler crashes due to missing var_info in struct attribute when it validates modifications for immutable variables.

## Vulnerability Details
For immutable variables, the number of modifications is tracked. If the surpasses 1, an exception is raised:
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/semantics/analysis/base.py#L249-L253

The tracking is done using the attribute `var_info`. In certain scenarios this attribute is missing and the compiler crashes.

### PoC
Suppose the following contract:
```python
#@version ^0.3.9

struct B:
    v1: int128
    v2: decimal

struct A:
    v: B

val: public(immutable(A))


@external
def __init__():
    val = A({v: B({v1: 0, v2: 0.0})})
    val.v.v1 += 666
```

When compiling the compiler crashes with:
```
AttributeError: 'NoneType' object has no attribute '_modification_count'
```

## Impact
The compiler doesn't handle the modification checks (and possibly the `var_info` assignments) correctly for all contracts, this could lead to undefined behavior. However, we didn't find such a scenario. As such, the impact is mainly a confusing error for the developer, which can slow down the development process.

## Tools Used
Manual testing.

## Recommendations
The semantic analyzer most likely doesn't properly annotate all the relevant nodes with `var_info` (or annotates them too late). Ensure that the nodes have the necessary info needed to perform all the semantic passes.
## <a id='L-10'></a>L-10. single exit point not check for for loop

_Submitted by [cyberthirst](/profile/cln69xxib000gjt08n37hic1g)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L1049-L1070

## Summary
The compiler enforces that blocks have 1 exit point. This invariant isn't checked inside `for loop`.

## Vulnerability Details
The compiler checks that function bodies and if statements have 1 exit point:
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/codegen/core.py#L1049-L1070

However, as we can see in the code the `For` node isn't validated. Thus, contract like the following one compile fine:
```python
@external
def returning_all_nigt_long() -> uint256:
    a: uint256 = 10
    for i in range(10):
        return 11
        a = 20
        return 12
    return a
```

But contracts like the following one don't compile:
```python
@external
def i_have_so_many_exit_point_omg() -> uint256:
    a: uint256 = 10
    if a < 20:
        return 0
        a = 20
        return 11111111111111
    return 101019291
```
The compilation fails with:
```
vyper.exceptions.StructureException: Too too many exit statements (return, raise or selfdestruct).
  contract "vyper_contracts/Test.vy:4", function "i_have_so_many_exit_point_omg", line 4:4 
       3     a: uint256 = 10
  ---> 4     if a < 20:
  -----------^
       5         return 0
```

## Impact
The single exit point is an invariant that is broken for for loops. This could be problematic if the later stages of the compilation relied on this invariant. However, such case wasn't discovered. As such we consider it as a confusing inconsistency.

## Tools Used
Manual review.

## Recommendations
Extend the validation for a single exit to contain also `for` loops.
## <a id='L-11'></a>L-11. compiler crash du to ASTTokens instantiation

_Submitted by [cyberthirst](/profile/cln69xxib000gjt08n37hic1g)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/ast/annotation.py#L272

## Summary
Instantiating the `asttokens.ASTTokens` class causes the compiler to crash even for a valid contract.

## Vulnerability Details
Suppose the following program:
```python
#@version ^0.3.9

import test5 as T

b: public(uint256)

event Transfer:
    random: indexed(uint256)
    shi: uint256

@external
def transfer():
   log Transfer(T(self).b(), 10)
   return
```
Compiling it causes the following error:
```
IndexError: list index out of range
```
The crash happens after executing the line:
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/ast/annotation.py#L272

## Impact
A valid program can't be compiled.

## Tools Used
Manual testing.

## Recommendations
We don't know what is the true cause of the crash and thus can't provide recommendation.
## <a id='L-12'></a>L-12. Tuple constants are deleted during folding, breaking compilation

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/master/vyper/ast/folding.py

https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/ast/expansion.py#L97-L113

## Summary

During constant folding, references to constant variables are replaced by their underlying values. After this is done, the constant variable itself is deleted. In the case of tuple constants, the first step fails. This results in references to non-existent variables, which breaks the compilation process later on, in the codegen module.

## Vulnerability Details

In the `replace_user_defined_constants()` function within the folding process, we go through all constant variables and iterate through all references to that value within the source code.

```python
for node in vyper_module.get_descendants(vy_ast.Name, {"id": id_}, reverse=True):
    ...
```
For each instance, we call `_replace()`, which attempts to create a new node with the values from the old node, but the type changed to the type of the constant and the value set to the constant's value. This call is wrapped in a try catch block, so that `UnfoldableNode` errors do not break the compilation, but instead simply remain to be returned at runtime.

```python
try:
    new_node = _replace(node, replacement_node, type_=type_)
except UnfoldableNode:
    if raise_on_error:
        raise
    continue
```

If we look at the `_replace()` function, we can see that it handles when the value is a Constant, a List, or a Call, but returns `UnfoldableNote` in all other cases.

Comparing this to the checks within the semantic analysis, we can see that semantically we allow tuples to be constants, while the the folding process this will skip the folding due to an error:
```python
def check_constant(node: vy_ast.VyperNode) -> bool:
    """
    Check if the given node is a literal or constant value.
    """
    if _check_literal(node):
        return True
    if isinstance(node, (vy_ast.Tuple, vy_ast.List)):
        return all(check_constant(item) for item in node.elements)
    if isinstance(node, vy_ast.Call):
        args = node.args
        if len(args) == 1 and isinstance(args[0], vy_ast.Dict):
            return all(check_constant(v) for v in args[0].values)

        call_type = get_exact_type_from_node(node.func)
        if getattr(call_type, "_kwargable", False):
            return True

    return False
```

After the folding is complete, the `remove_unused_statements()` function removes all nodes that represent variable declarations to constants. This assumes that these will all have been replaced in-place where they are used, but does not take into account that tuples have been skipped.

```python
def remove_unused_statements(vyper_module: vy_ast.Module) -> None:
"""
Remove statement nodes that are unused after type checking.

Once type checking is complete, we can remove now-meaningless statements to
simplify the AST prior to IR generation.

Arguments
---------
vyper_module : Module
    Top-level Vyper AST node.
"""

for node in vyper_module.get_children(vy_ast.VariableDecl, {"is_constant": True}):
    vyper_module.remove_from_body(node)

# `implements: interface` statements - validated during type checking
for node in vyper_module.get_children(vy_ast.ImplementsDecl):
    vyper_module.remove_from_body(node)
```

The result is that any tuple constants are NOT replaced in-place during folding, but DO have their nodes deleted after folding is complete. This leads to an error further along the pipeline where the codegen module tries to `parse_Name` and finds that the corresponding variable name does not exist.

## Proof of Concept

```python
# @version ^0.3.9

e: constant(uint256) = 24
f: constant((uint256, uint256)) = (e, e)

@external
def foo(x: uint256) -> uint256:
    return f[0]
```

This results in the following error:
```
vyper.exceptions.TypeCheckFailure: Name node did not produce IR.
```

## Impact

Tuple constants that are declared will not be properly handled and instead will cause compilation to fail.

Note that while I have not been able to identify any way to have the code compile despite the missed checks, if there were any edge cases where these tuple values could be used within the contract without reverting the compilation, issues could creep into compiled code that could have more serious implications.

## Tools Used

Manual Review

## Recommendations

Adjust the `_replace()` function to handle tuples properly, or explicitly disallow them from being used as constants to catch this situation in the semantic analysis.
## <a id='L-13'></a>L-13. Gas cost estimates incorrect due to rounding in `calc_mem_gas()`

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/utils.py#L191-L193

## Summary

When memory is expanded, Vyper uses the `calc_mem_gas()` util function to estimate the cost of expansion. However, this calculation should round up to the nearest word, whereas the implementation rounds down to the nearest word. Since gas costs for memory expansion increase exponentially, this can create a substantial deviation as memory sizes get larger.

## Vulnerability Details

When Vyper IR is being generated, we estimate the gas cost for all external functions, which includes a specific adjustment for the memory expansion cost:
```python
# adjust gas estimate to include cost of mem expansion
# frame_size of external function includes all private functions called
# (note: internal functions do not need to adjust gas estimate since
mem_expansion_cost = calc_mem_gas(func_t._ir_info.frame_info.mem_used)  # type: ignore
ret.common_ir.add_gas_estimate += mem_expansion_cost  # type: ignore
```

This `calc_mem_gas()` function is implemented as follows:
```python
def calc_mem_gas(memsize):
    return (memsize // 32) * 3 + (memsize // 32) ** 2 // 512
```

As we can see on [EVM.codes](https://www.evm.codes/about#memoryexpansion), the calculation should be:
```
memory_size_word = (memory_byte_size + 31) / 32
memory_cost = (memory_size_word ** 2) / 512 + (3 * memory_size_word)
```
While both implementations use the same formula, the correct implementation uses `memory_size_word` as the total number of words of memory that have been touched (ie the memsize is rounded up to the nearest word), whereas the Vyper implementation rounds down to the nearest word.

## Impact

Gas estimates will consistently underestimate the memory expansion cost of external functions.

## Tools Used

Manual Review, EVM.codes

## Recommendations

Change the `calc_mem_gas()` function to round up to correctly mirror the EVM's behavior:
```diff
def calc_mem_gas(memsize):
-   return (memsize // 32) * 3 + (memsize // 32) ** 2 // 512
+   return (memsize + 31 // 32) * 3 + (memsize + 31 // 32) ** 2 // 512
```
## <a id='L-14'></a>L-14. Incorrect gas estimate for BALANCE opcode

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/evm/opcodes.py#L55

## Summary

When gas costs are estimated, BALANCE is presumed to cost 700 gas. However, the correct gas cost for BALANCE is 2600.

## Vulnerability Details

When gas costs are estimated, we use a cost of 700 for any calls to BALANCE:
```python
"BALANCE": (0x31, 1, 1, 700),
```
However, since [EIP 2929](https://eips.ethereum.org/EIPS/eip-2929) the cost of a BALANCE read has increased to 2600.

Looking at the [opcode gas costs](https://github.com/wolflo/evm-opcodes/blob/main/gas.md#a5-balance-extcodesize-extcodehash), we can see that BALANCE is defined as follows:
```
gas_cost = 100 if target_addr in touched_addresses (warm access)
gas_cost = 2600 if target_addr not in touched_addresses (cold access)
```
Since Vyper defaults to taking the higher cost in situations that have discounts for warm addresses or storage slots (see: SSTORE, EXTCODESIZE), the gas cost for this operation should default to 2600.

## Impact

Gas prices will be underestimated because of an incorrectly priced BALANCE opcode.

## Tools Used

Manual Review, EVM.codes

## Recommendations

Adjust BALANCE to reflect EIP 2929, as you have already done for EXTCODESIZE and EXTCODEHASH:
```diff
- "BALANCE": (0x31, 1, 1, 700),
+ "BALANCE": (0x31, 1, 1, (700, 2600)),
```
## <a id='L-15'></a>L-15. SHA256 built-in will return input value on chains without SHA256 precompile

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/builtins/functions.py#L674-L689

https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/builtins/functions.py#L629-L641

## Summary

When the SHA256 built-in function is called with a bytes32 input, we use the same scratch space to save the input and return the output. If a chain does not implement the SHA256 precompile (which is a requirement for many ZK rollups), this address will be an EOA, so the call will silently fail and we'll return the input value from memory.

## Vulnerability Details

The SHA256 built-in function is a wrapper around the precompiled contract at address(0x02). In the event that it is called with a bytes32 argument, we perform the following logic:

1) Place the input argument at the 0 memory slot.
2) Call the precompile with an input of memory slots 0-31.
3) Assert that the call succeeded.
4) Ask the precompile to return the hashed value to memory slots 0-31.
5) mload the value from memory slots 0-31 to return the hashed value.

We can see this logic implemented here:
```python
sub = args[0]
# bytes32 input
if sub.typ == BYTES32_T:
    return IRnode.from_list(
        [
            "seq",
            ["mstore", MemoryPositions.FREE_VAR_SPACE, sub],
            # @ok this will return no data if not enough gas? so it'll juse use the input
            # right now this can't be exploited becuase only 72 gas, so 1/64 remaining is just 1-2, not enough for mload
            # but if precompile gas increased even slightly, there would be a problem
            # - fuck i'm an idiot, after hours realized _make_sha256_call has an assert so requires a return value
            _make_sha256_call(
                inp_start=MemoryPositions.FREE_VAR_SPACE,
                inp_len=32,
                out_start=MemoryPositions.FREE_VAR_SPACE,
                out_len=32,
            ),
            ["mload", MemoryPositions.FREE_VAR_SPACE],  # push value onto stack
        ],
        typ=BYTES32_T,
        add_gas_estimate=SHA256_BASE_GAS + 1 * SHA256_PER_WORD_GAS,
    )
```
```python
def _make_sha256_call(inp_start, inp_len, out_start, out_len):
    return [
        "assert",
        [
            "staticcall",
            ["gas"],  # gas
            SHA256_ADDRESS,  # address
            inp_start,
            inp_len,
            out_start,
            out_len,
        ],
    ]
```
In the event that the staticcall to address(0x02) succeeds (ie passes the assert) but returns no data, the input data will remain at memory slot 0 and will be returned from the function call.

In the event that a chain does not implement the SHA256 precompile, this is exactly what would happen. Because calls to EOAs always return `1` (success), such a call will pass the assert, but will return no calldata. The input data will then be returned with no error, leading to major vulnerabilities in any contract that uses this function.

Note that not implementing the SHA256 precompile is a common requirement for ZK rollups. Both ZKsync and Scroll do not implement the precompile at present. Fortunately, both currently have errors that will stop this vulnerability from being exploited, but future rollups that simply skip implementing the precompile will be vulnerable.

## Impact

Rollups that do not implement the SHA256 precompile will lead to the SHA256 built-in function returning the input (rather than no data) for all bytes32 inputs.

## Tools Used

Manual Review

## Recommendations

Because there is a risk of the call succeeding with no return value, return the data to `FREE_VAR_SPACE2` to ensure that `0` is returned in the case of no data being returned.
## <a id='L-16'></a>L-16. Fang optimization options broken

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/cli/vyper_ir.py#L47-L51

https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/cli/vyper_ir.py#L35-L38

## Summary

Fang allows users to specify whether they would like their program outputted as `ir`, `opt_ir`, `asm`, or `bytecode`. However, the actual behavior is that `ir` will return optimized IR, and `opt_ir` will not return anything.

## Vulnerability Details

When users call `fang ...`, the call is handled by `cli/vyper_ir.py`. One of the passed arguments is a list of formats to output. From the help doc:
```md
"Format to print csv list of ir,opt_ir,asm,bytecode"
```
However, if we look at the `compile_to_ir()` function, we can see that, in the event that `ir` is passed, it automatically optimizes the IR and saves it as `compiler_data["ir"]`, rather than `compiler_data["opt_ir"]`.
```python
compiler_data = {}
ir = IRnode.from_list(s_expressions[0])
ir = optimizer.optimize(ir)
if "ir" in output_formats:
    compiler_data["ir"] = ir
```
Further, we can see that if `opt_ir` is included in the list of formats, it is not processed and nothing happens. There is no way to save any value in `compiler_data["opt_ir"]`.

Later, when we process outputs, we iterate over the possible output types:
```python
for key in ("ir", "opt_ir", "asm", "bytecode"):
    if key in compiler_data:
        print(compiler_data[key])
```
Since there will never be any key called `opt_ir` in `compiler_data`, this option will be skipped.

## Impact

Fang will generate optimized IR when we request unoptimized IR. This can lead to problems for low level developers who are using Fang specifically so they can specify that their IR should remain exactly as they wrote it. This can lead to unexpected behavior, such as gas prices and codesize not being exactly as predicted.

It will skip generating the optimized IR when asked, which is less of an issue.

## Tools Used

Manual Review

## Recommendations

Split the generation of IR via Fang into two options: one for `ir` that skips the optimization step, and another for `opt_ir` that uses the current implementation.
## <a id='L-17'></a>L-17. `_bytes_to_num()` skips `ensure_in_memory()` check, which can lead to compilation failure

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/builtins/_convert.py#L76-L85

## Summary

The `_bytes_to_num()` function used in conversion assumes that any bytestring types are in memory. If they are declared from within the expression, it will try to load them from memory and panic.

## Vulnerability Details

When converting a bytestring to a number, we perform the following:
```python
if isinstance(arg.typ, _BytestringT):
    _len = get_bytearray_length(arg)
    arg = LOAD(bytes_data_ptr(arg))
    num_zero_bits = ["mul", 8, ["sub", 32, _len]]
```
The `get_bytearray_length()` function correctly handles the case when an empty bytestring is passed directly to the conversion. However, the `bytes_data_ptr()` function panics if the argument doesn't have a `location` specified:
```python
if ptr.location is None:
    raise CompilerPanic("tried to modify non-pointer type")
```

## Proof of Concept

The following Vyper contract should compile:
```python
@external
def get_empty_bytestring_as_uint() -> uint256:
    return convert(empty(Bytes[32]), uint256)
```
However, it instead returns the following:
```md
Error compiling: examples/minimal.vy
vyper.exceptions.CompilerPanic: tried to modify non-pointer type
```

## Impact

Contracts that include a conversion where an empty bytestring is declared within the expression will fail to compile.

## Tools Used

Manual Review

## Recommendations

Use something like the `ensure_in_memory()` function used elsewhere in the compiler to move empty bytestrings to memory before converting them, or create a manual override for empty strings to return the appropriate value.
## <a id='L-18'></a>L-18. Built-in `shift()` function will fail if passed a negative integer at compile time

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/b01cd686aa567b32498fefd76bd96b0597c6f099/vyper/builtins/functions.py#L1451-L1466

## Summary

The built-in `shift()` function accepts an `INT256` as an input, which are accounted for and work fine at runtime. However, there is a compile time check that causes a revert if a negative literal is passed to the function.

## Vulnerability Details

In the `evaluate()` method, which is used when `shift()` is evaluated at compile time, there is the following check:
```python
if value < 0 or value >= 2**256:
    raise InvalidLiteral("Value out of range for uint256", node.args[0])
```
However, the function is intended to accept `INT256` as an argument:
```python
_inputs = [("x", (UINT256_T, INT256_T)), ("_shift_bits", IntegerT.any())]
```

This is properly handled in the `build_IR()` method, but fails when `evaluate()` is called at compile time.

## Impact

Contracts that shift a negative literal and attempt to evaluate the expression at compile time will fail to compile.

## Tools Used

Manual Review

## Recommendations

The ideal option would be to update the `evaluate()` method to handle negative integers.

Alternatively, given the `shift()` function is deprecated and may not justify the extra work, the easiest solution is to simply `raise UnfoldableNote` for values between `type(int256).min` and `0`, which will skip evaluation and leave the function to be evaluated at runtime.
## <a id='L-19'></a>L-19. Compiled opcodes will return wrong values for PUSH instructions due to incorrect padding

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/52dc413c684532d5c4d6cdd91e3b058957cfcba0/vyper/compiler/output.py#L294-L312

## Summary

When the compiler is run in `-f opcodes` or `-f opcodes_runtime` mode, it translates the final bytecode into opcodes. However, due to incorrect padding placed on `PUSH` values, the return values will be incorrect for any bytes with leading zeros. 

## Vulnerability Details

When the compiler is run with a target output of opcodes, we run the final bytecode through the following function:
```python
def _build_opcodes(bytecode: bytes) -> str:
    bytecode_sequence = deque(bytecode)

    opcode_map = dict((v[0], k) for k, v in opcodes.get_opcodes().items())
    opcode_output = []

    while bytecode_sequence:
        op = bytecode_sequence.popleft()
        opcode_output.append(opcode_map.get(op, f"VERBATIM_{hex(op)}"))
        if "PUSH" in opcode_output[-1] and opcode_output[-1] != "PUSH0":
            push_len = int(opcode_map[op][4:])
            # we can have push_len > len(bytecode_sequence) when there is data
            # (instead of code) at end of contract
            # CMC 2023-07-13 maybe just strip known data segments?
            push_len = min(push_len, len(bytecode_sequence))
            push_values = [hex(bytecode_sequence.popleft())[2:] for i in range(push_len)]
            opcode_output.append(f"0x{''.join(push_values).upper()}")

    print(opcode_output)
    return " ".join(opcode_output)
```
This function iterates through each instruction in the bytecode and translates it to the corresponding opcode. In the case of `PUSH` instructions, it parses the number of bytes to include (let's call it `x`), and then assumes the following `x` instructions are the value passed to `PUSH`.

For each of these two byte chunks, it parses the bytes with `hex(bytecode_sequence.popleft())[2:]` and joins them together.

The problem is that for two bytes that begin with a leading `0` (such as `0x05`), this simply appends the non-zero digit to the sequence. The result is a sequence that is not as long as expected by the PUSH instruction, and therefore is prepended (or appended, depending on the type) with 0s in order to reach the expected length.

## Proof of Concept

Consider the following Vyper contract, with a single function that returns a bytes4 value of `0x350f872d`:
```python
@external
def f1() -> bytes4:
    return 0x350f872d
```

Because the second byte of the return value starts with a 0, the translation will return `0xf` instead of `0x0f`.

The result is are these incorrect opcodes returned from the compiler (see the `PUSH32` instruction in the middle):
```md
PUSH0 CALLDATALOAD PUSH1 0xE0 SHR PUSH4 0xC27FC35 DUP2 XOR PUSH2 0x03E JUMPI CALLVALUE PUSH2 0x042 JUMPI PUSH32 0x35F872D0000000000000000000000000000 PUSH1 0x40 MSTORE PUSH1 0x20 PUSH1 0x40 RETURN JUMPDEST PUSH0 PUSH0 REVERT JUMPDEST PUSH0 DUP1 REVERT
```

## Impact

The compiler will return incorrect values when run in opcode mode and there is any PUSH instruction that includes bytes with leading zeros.

## Tools Used

Manual Review

## Recommendations

Ensure that the `push_values` value is padded to be two digits before being joined into a bytestring.
## <a id='L-20'></a>L-20. Wrong denominations included in reserved keywords

_Submitted by [obront](/profile/clnxz4xdc000cl908cj3yirf0)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/semantics/namespace.py#L207-L220

## Summary

The list of `denominations` for units of ETH included in the reserved keywords list is different from the list of accepted denominations when converting between units. This leads to some reserved keywords that should not be, and some non-reserved keywords that should be.

## Vulnerability Details

The list of reserved keywords for denominations is as follows:
```python
    "ether",
    "wei",
    "finney",
    "szabo",
    "shannon",
    "lovelace",
    "ada",
    "babbage",
    "gwei",
    "kwei",
    "mwei",
    "twei",
    "pwei",
```

The list of denominations accepted when converting between values is:
```python
wei_denoms = {
    ("wei",): 1,
    ("femtoether", "kwei", "babbage"): 10**3,
    ("picoether", "mwei", "lovelace"): 10**6,
    ("nanoether", "gwei", "shannon"): 10**9,
    ("microether", "szabo"): 10**12,
    ("milliether", "finney"): 10**15,
    ("ether",): 10**18,
    ("kether", "grand"): 10**21,
}
```

Comparing the two lists:
- The following are reserved but should not be: `ada, twei, pwei`
- The following are not reserved but should be: `milliether, microether, nanoether, picoether, femtoether, grand, kether`

## Impact

Some denominations that should be reserved are not, while others that should not be reserved are.

## Tools Used

Manual Review

## Recommendations

Line up the two lists so that the reserved keywords reflects the denominations that are used for conversions.
## <a id='L-21'></a>L-21. Pure functions can emit logs

_Submitted by [Franfran](/profile/clnru86oh0000lf08selovtfc)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/issues/3141

## Summary

Pure functions are allowed to emit logs.

## Vulnerability Details

While pure functions are expected to be fully equivalent at any time, this is a false assumption that has been uncovered in the ChainSecurity review, because [`blockhash` can be used](https://github.com/vyperlang/vyper/issues/3141).
A built-in that has been forgotten is `raw_log`, which emits logs thanks to the `LOG<N>` opcode.
For instance, this compiles just fine:

```py
@external
@pure
def loggg(_topic: bytes32, _data: Bytes[100]):
    raw_log([_topic], _data)
```

This is a write operation, while pure functions should only allow read access, thus breaking assumptions with pure functions.

## Impact

This could be used maliciously for instance for implementors of pure functions.
They should be called with the `STATICCALL` opcode which should throw an exception for any executed operation including `CREATE`, `CREATE2`, `LOG0`, `LOG1`, `LOG2`, `LOG3`, `LOG4` `SSTORE` `SELFDESTRUCT`, and `CALL` with a non-zero value as described in the [EIP-214](https://eips.ethereum.org/EIPS/eip-214) (did they missed delegatecall ?).
In this case, `STATICCALL` will be used and when log is going to be emitted, the call will revert, which could freeze a contract.

## Tools Used

Manual review

## Recommendations

Ban `raw_log` from pure functions.
## <a id='L-22'></a>L-22. Compile-time division for signed integer edge case

_Submitted by [Franfran](/profile/clnru86oh0000lf08selovtfc)._      
				
### Relevant GitHub Links
	
https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/ir/optimizer.py#L54-L55

https://github.com/vyperlang/vyper/assets/51274081/3f619c79-88e0-4d15-9ace-7d9ba02d16bc

## Summary

At compile-time, division is using the same logic for both signed and unsigned integers. This is causing some corectness issues.

## Vulnerability Details

Compile time div operation for both signed and unsigned are defined by [`evm_div`](https://github.com/vyperlang/vyper/blob/3b310d5292c4d1448e673d7b3adb223f9353260e/vyper/ir/optimizer.py#L54-L55)

```python
def evm_div(x, y):
    if y == 0:
        return 0
    # NOTE: should be same as: round_towards_zero(Decimal(x)/Decimal(y))
    sign = -1 if (x * y) < 0 else 1
    return sign * (abs(x) // abs(y))  # adapted from py-evm
```

But there should be an edge case according to the Ethereum yellow paper:
![image](https://github.com/vyperlang/vyper/assets/51274081/3f619c79-88e0-4d15-9ace-7d9ba02d16bc)

As you can see, `DIV` and `SDIV` are not purely equivalent. There is an edge case when $\mu[0] = -2^{255}$ and $\mu[1] = -1$.
If we evaluate the expression with the Python engine, this is what we get for this function:
```sh
>>> def evm_div(x, y):
...     if y == 0:
...         return 0
...     # NOTE: should be same as: round_towards_zero(Decimal(x)/Decimal(y))
...     sign = -1 if (x * y) < 0 else 1
...     return sign * (abs(x) // abs(y))  # adapted from py-evm
...
>>> evm_div(-2**255, -1)
57896044618658097711785492504343953926634992332820282019728792003956564819968
>>> assert evm_div(-2**255, -1) == 2**255
```

It's `2**255`, while it should be `-2**255`.

## Impact

Here are some examples at looking how this could be exploited:

```py
@external
def div_bug() -> int256:
    return -2**255 / -1
```

Doesn't work, caught by the type checker:
```sh
vyper.exceptions.InvalidType: Expected int256 but literal can only be cast as uint256.
  contract "src/div.vy:3", function "div_bug", line 3:11
       2 def div_bug() -> int256:
  ---> 3     return -2**255 / -1
  ------------------^
       4
```

While it should compile.

But we can for instance make it compile this way, while it should revert since `as_wei_value` does not support negative values.

```py
@external
def div_bug() -> uint256:
    return as_wei_value(-2**255 / -1, "wei")
```

This compiles while the value should evaluate to a negative value, and returns `0x8000000000000000000000000000000000000000000000000000000000000000`.

Another example:

```py
@external
def div_bug() -> uint256:
    return max(-2**255 / -1, 0)
```

returns `0x8000000000000000000000000000000000000000000000000000000000000000`
because `max` is evaluated at compile-time with the wrong computation of `-2**255 / -1`. The expected result should be `0`.

```py
@external
def div_bug() -> int256:
    return min(-2**255 / -1, 0)
```

returns `0`

Other things that compile while it shouldn't:

```py
@external
def div_bug() -> String[100]:
    return uint2str(-2**255 / -1)
```

```py
@external
def div_bug() -> uint256:
    return uint256_addmod(-2**255 / -1, -2**255 / -1, -2**255 / -1)
```

```py
@external
def div_bug() -> uint256:
    return uint256_mulmod(-2**255 / -1, -2**255 / -1, -2**255 / -1)
```

```py
@external
def div_bug() -> uint256:
    return pow_mod256(-2**255 / -1, -2**255 / -1)
```

## Tools Used

Manual review

## Recommendations

```python
def evm_div(x, y):
    if y == 0:
        return 0
	elif x == -2**255 and y == -1:
		return -2**255
    sign = -1 if (x / y) < 0 else 1
    return sign * abs(x // y)
```

(might be better to create a `evm_sdiv` to make sure that it won't cause any issue in the future)




