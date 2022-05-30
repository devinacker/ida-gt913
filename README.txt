This is an IDA 7.x processor module for the Casio GT913F (aka NEC uPD913GF) keyboard SoC.

The instruction set is essentially a clone of the Hitachi H8/300 series, with several opcodes rearranged as well as some new instructions for bank-switching the region of memory at 0x8000-BFFF.

This module will automatically analyze all reset/interrupt vectors as well as automatically create data segments for the built-in RAM and memory-mapped registers. Handling of stack-based local vars and function arguments is also supported.

Currently, this module does *not* create additional segments for bank-switchable ROM. Typically, all executable code is located in the first 32kb of ROM (loaded at 0x0000-7FFF); it is recommended to just load the first 32kb of ROM at first and manually create any additional segments for additional ROM contents as needed.

Tested with IDA Pro 7.5.

Other likely supported chips (not tested):
* NEC uPD912GF
* NEC uPD915GF / Casio GT915GF
