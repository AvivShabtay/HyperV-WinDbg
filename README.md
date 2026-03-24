# HyperV Research using WinDbg

A WinDbg JavaScript extension for Hyper-V research and debugging.

## Commands

| Command          | Description                                                                      |
| ---------------- | -------------------------------------------------------------------------------- |
| `!vmcs`          | Dump the current VP's Enlightened VMCS                                           |
| `!vtl`           | Print the current VTL (Virtual Trust Level) number                               |
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
