# HyperV Research using WinDbg

A WinDbg JavaScript extension for Hyper-V research and debugging.

## Commands

| Command          | Description                                                                      |
| ---------------- | -------------------------------------------------------------------------------- |
| `!vmcs`          | Dump the current VP's Enlightened VMCS                                           |
| `!vmcslist`      | List the Virtual and Physical addresses of every VMCS across all VTLs            |
| `!vtlnumber`     | Print the current VTL (Virtual Trust Level) number                               |
| `!currentvtl`    | Print the current VTL's `HV_VTL` data structure base address                     |
| `!vtls`          | List the `HV_VTL` data structure base addresses for every VTL                    |
| `!currentvp`     | Print the current Virtual Processor's `HV_VP` data structure base address        |
| `!vps`           | List the `HV_VP` data structure base addresses for every VP under the partition  |
| `!partition`     | Print the current partition's `HV_PARTITION` data structure base address         |
| `!guest`         | Print information about the current guest VM and load its symbols                |
| `!gpa2hpa <gpa>` | Translate a Guest Physical Address to a Host Physical Address by walking the EPT |

## Setup

1. Open WinDbg and attach to a Hyper-V kernel debug session.
2. Update `SYMBOLS_FILE_PATHS` in `hv.js` to point to the absolute paths of `VMCS.h` and `EPT.h` on your machine.
3. Load the script:
   ```
   .scriptload C:\path\to\hv.js
   ```
4. The available commands will be printed on load.

## Notes

- The offsets in `hv.js` are found during a research and are compatible with Windows11 24H2 and 25H2 builds.

## References

- https://amitmoshel1.github.io/posts/virtualization-based-security-with-hyper-v-exploring-hyper-v-mechanisms-and-virtualization-based-security/
- https://github.com/tandasat/hvext
- https://hvinternals.blogspot.com/2021/01/hyper-v-debugging-for-beginners-2nd.html
- https://connormcgarr.github.io/secure-calls-and-skbridge/
