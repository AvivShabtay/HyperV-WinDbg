"use strict";

const log = (x) => host.diagnostics.debugLog(`${x}\n`);
const system = (x) => host.namespace.Debugger.Utility.Control.ExecuteCommand(x);
const asUint64 = (x) => host.evaluateExpression(`(unsigned __int64) ${x}`);

// Based on Satoshi extension.
function bits(value, offset, size) {
  let mask = host.Int64(1).bitwiseShiftLeft(size).subtract(1);
  return value.bitwiseShiftRight(offset).bitwiseAnd(mask).asNumber();
}

// Symbol Files
const SYMBOLS_FILE_PATHS = [
  "C:\\Dev\\HyperV-WinDbg\\VMCS.h",
  "C:\\Dev\\HyperV-WinDbg\\EPT.h",
];

let g_isSymbolsLoaded = false;

function loadHyperVTypes() {
  if (g_isSymbolsLoaded) {
    return;
  }

  for (let path of SYMBOLS_FILE_PATHS) {
    host.namespace.Debugger.Utility.Analysis.SyntheticTypes.ReadHeader(
      path,
      "hv",
    );
  }

  g_isSymbolsLoaded = true; // Cache
}

// GS offsets for 24H2, 25H2.
// These offset found be reverse engineering hvix64.exe.
const HV_GS_SELF_OFFSET = 0x0; // Also can be found under the current VMCS' `HostGsBase` field.
const HV_GS_CURRENT_VMCS_OFFSET = 0x2c680;
const HV_GS_CURRENT_VIRTUAL_PROCESSOR_OFFSET = 0x358;
const HV_CURRENT_CR3_OFFSET = 0x458; // Also can be found under the current VMCS' `HostCr3` field.
const HV_GS_IDT_BASE_OFFSE = 0x440;
const HV_GS_GDT_BASE_OFFSE = 0x448;

// More offsets for 24H2, 25H2
const VTL_OFFSET_FROM_VIRTUAL_PROCESSOR = 0x3c0;

// For 24H2 (Potentially also 25H2)
const VTL_ARRAY_OFFSET_FROM_VIRTUAL_PROCESSOR = 0x148;
const HV_PARTITION_OFFSET_FROM_GS_BASE = 0x360;
const VP_ARRAY_OFFSET_FROM_HV_PARTITION = 0x1e0;
const NUMBER_OF_VPS_OFFSET_FROM_HV_PARTITION = 0x1d0; // Holds the number of VPs under partition

const VTL_STATE_REGION_OFFSET_FROM_HV_VTL = 0x13c0;
const VMCS_INFO_STRUCTURE_OFFSET_FROM_VTL_STATE_REGION = 0x28;
const VMCS_VIRTUAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE = 0x180;
const VMCS_PHYSICAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE = 0x188;

// Memory constants
const PFN_MASK = 0x000fffffffff000;
const PFN_MASK_2M = 0x000ffffffe00000;
const PFN_MASK_1G = 0x000ffffffc00000;
const PAGE_SIZE = 0x1000;
const PAGE_MASK = host.Int64(PAGE_SIZE - 1).bitwiseNot();
const ONE_MB = 1 << 20;

// Read memory utilities
const u8 = (x) => host.memory.readMemoryValues(x, 1, 1)[0];
const u16 = (x) => host.memory.readMemoryValues(x, 1, 2)[0];
const u32 = (x) => host.memory.readMemoryValues(x, 1, 4)[0];
const u64 = (x) => host.memory.readMemoryValues(x, 1, 8)[0];
const u128 = (x) => host.memory.readMemoryValues(x, 1, 16)[0];

function read16(x, phy = false) {
  if (phy) {
    x = host.memory.physicalAddress(x);
  }
  return u16(x);
}

// Based on Hugsy extensions.
function read64(x, phy = false) {
  if (phy) {
    x = host.memory.physicalAddress(x);
  }
  return u64(x, 1, 8);
}

class CR4 {
  constructor(value) {
    const raw = host.Int64(value);

    this.VME = bits(raw, 0, 1) !== 0; // Virtual-8086 Mode Extensions
    this.PVI = bits(raw, 1, 1) !== 0; // Protected-mode Virtual Interrupts
    this.TSD = bits(raw, 2, 1) !== 0; // Time Stamp Disable
    this.DE = bits(raw, 3, 1) !== 0; // Debugging Extensions
    this.PSE = bits(raw, 4, 1) !== 0; // Page Size Extensions
    this.PAE = bits(raw, 5, 1) !== 0; // Physical Address Extension
    this.MCE = bits(raw, 6, 1) !== 0; // Machine-Check Enable
    this.PGE = bits(raw, 7, 1) !== 0; // Page Global Enable
    this.PCE = bits(raw, 8, 1) !== 0; // Performance Counter Enable
    this.OSFXSR = bits(raw, 9, 1) !== 0; // OS support for FXSAVE/FXRSTOR
    this.OSXMMEXCPT = bits(raw, 10, 1) !== 0; // OS support for unmasked SIMD FP exceptions
    this.UMIP = bits(raw, 11, 1) !== 0; // User-Mode Instruction Prevention
    this.LA57 = bits(raw, 12, 1) !== 0; // 5-Level Paging
    this.VMXE = bits(raw, 13, 1) !== 0; // VMX Enable
    this.SMXE = bits(raw, 14, 1) !== 0; // SMX Enable
    this.FSGSBASE = bits(raw, 16, 1) !== 0; // FSGSBASE Enable
    this.PCIDE = bits(raw, 17, 1) !== 0; // PCID Enable
    this.OSXSAVE = bits(raw, 18, 1) !== 0; // XSAVE Enable
    this.KL = bits(raw, 19, 1) !== 0; // Key Locker Enable
    this.SMEP = bits(raw, 20, 1) !== 0; // Supervisor Mode Execution Prevention
    this.SMAP = bits(raw, 21, 1) !== 0; // Supervisor Mode Access Prevention
    this.PKE = bits(raw, 22, 1) !== 0; // Protection Keys Enable
    this.CET = bits(raw, 23, 1) !== 0; // Control-flow Enforcement Technology
    this.PKS = bits(raw, 24, 1) !== 0; // Protection Keys for Supervisor pages
    this.UINTR = bits(raw, 25, 1) !== 0; // User Interrupts

    this.toString = () => {
      const enabled = Object.keys(this).filter(
        (member) => this[member] === true,
      );
      return `0x${raw.toString(16)} [${enabled.join(" ")}]`;
    };
  }
}

class CR0 {
  constructor(value) {
    const raw = host.Int64(value);

    this.PE = bits(raw, 0, 1) !== 0; // Protection Enable
    this.MP = bits(raw, 1, 1) !== 0; // Monitor Coprocessor
    this.EM = bits(raw, 2, 1) !== 0; // Emulation (FPU absent)
    this.TS = bits(raw, 3, 1) !== 0; // Task Switched
    this.ET = bits(raw, 4, 1) !== 0; // Extension Type (always 1)
    this.NE = bits(raw, 5, 1) !== 0; // Numeric Error
    this.WP = bits(raw, 16, 1) !== 0; // Write Protect (supervisor)
    this.AM = bits(raw, 18, 1) !== 0; // Alignment Mask
    this.NW = bits(raw, 29, 1) !== 0; // Not Write-through
    this.CD = bits(raw, 30, 1) !== 0; // Cache Disable
    this.PG = bits(raw, 31, 1) !== 0; // Paging Enable

    this.toString = () => {
      const enabled = Object.keys(this).filter(
        (member) => this[member] === true,
      );
      return `0x${raw.toString(16)} [${enabled.join(" ")}]`;
    };
  }
}

class DR7 {
  constructor(value) {
    const raw = host.Int64(value);

    // RW encoding: 00=exec, 01=write, 10=I/O, 11=read/write
    const RW = ["exec", "write", "io", "read/write"];

    // LEN encoding: 00=1b, 01=2b, 10=8b, 11=4b (non-obvious: 10=8, 11=4)
    const LEN = ["1b", "2b", "8b", "4b"];

    // Per-breakpoint enable flags
    this.L0 = bits(raw, 0, 1) !== 0; // Local  enable BP0
    this.G0 = bits(raw, 1, 1) !== 0; // Global enable BP0
    this.L1 = bits(raw, 2, 1) !== 0; // Local  enable BP1
    this.G1 = bits(raw, 3, 1) !== 0; // Global enable BP1
    this.L2 = bits(raw, 4, 1) !== 0; // Local  enable BP2
    this.G2 = bits(raw, 5, 1) !== 0; // Global enable BP2
    this.L3 = bits(raw, 6, 1) !== 0; // Local  enable BP3
    this.G3 = bits(raw, 7, 1) !== 0; // Global enable BP3

    this.LE = bits(raw, 8, 1) !== 0; // Local exact (obsolete, ignored by modern CPUs)
    this.GE = bits(raw, 9, 1) !== 0; // Global exact (obsolete, ignored by modern CPUs)
    this.RTM = bits(raw, 11, 1) !== 0; // Advanced debugging of RTM regions
    this.GD = bits(raw, 13, 1) !== 0; // General detect — #DB before any DR access

    // Per-breakpoint condition and length (decoded to human-readable strings)
    this.RW0 = RW[bits(raw, 16, 2)];
    this.LEN0 = LEN[bits(raw, 18, 2)];
    this.RW1 = RW[bits(raw, 20, 2)];
    this.LEN1 = LEN[bits(raw, 22, 2)];
    this.RW2 = RW[bits(raw, 24, 2)];
    this.LEN2 = LEN[bits(raw, 26, 2)];
    this.RW3 = RW[bits(raw, 28, 2)];
    this.LEN3 = LEN[bits(raw, 30, 2)];

    this.toString = () => {
      const active = [0, 1, 2, 3]
        .filter((i) => this[`L${i}`] || this[`G${i}`])
        .map((i) => `BP${i}:${this[`RW${i}`]}/${this[`LEN${i}`]}`);
      const summary = active.length ? active.join(" ") : "no breakpoints";
      return `0x${raw.toString(16)} [${summary}]`;
    };
  }
}

function getGsBase() {
  return host.parseInt64(system("dq gs:[0] L1")[0].split(" ")[2], 16);
}

function getCurrentVtlNumber() {
  const gsBase = getGsBase();
  const vp_address = u64(gsBase.add(HV_GS_CURRENT_VIRTUAL_PROCESSOR_OFFSET));
  const vtl_number = u8(vp_address.add(VTL_OFFSET_FROM_VIRTUAL_PROCESSOR));
  return vtl_number;
}

/**
  Returns a HV_VP structure representing a virtual processor.
*/
function getCurrentVirtualProcessor() {
  const gsBase = getGsBase();
  const vp_address = u64(gsBase.add(HV_GS_CURRENT_VIRTUAL_PROCESSOR_OFFSET));
  return vp_address;
}

/**
  Returns a HV_VTL structure (representing a VTL) base address.
*/
function getCurrentVtl() {
  const gsBase = getGsBase();
  const vp_address = u64(gsBase.add(HV_GS_CURRENT_VIRTUAL_PROCESSOR_OFFSET));
  const vtl = u64(vp_address.add(VTL_OFFSET_FROM_VIRTUAL_PROCESSOR));
  return vtl;
}

function getVtlsList() {
  let VirtualProcessor = getCurrentVirtualProcessor();
  let vtlsListDoublePointer = VirtualProcessor.add(
    VTL_ARRAY_OFFSET_FROM_VIRTUAL_PROCESSOR,
  );
  return vtlsListDoublePointer;
}

function printVtlsList() {
  let vtls = getVtlsList();

  // Since there are currently only 2 VTLs (VTL0 & VTL1) supported, the function will iterate only on 2 VTLs.
  // but we can get per the number of active VTLs per VP - by reading
  // HvRegisterVsmVpStatus.EnabledVtlSet bitmask field
  for (let index = 0; index < 2; index++) {
    let vtl = u64(vtls.add(8 * index));
    log(`\t[*] VTL[${index}]: 0x${vtl.toString(16)}`);
  }
}

function getCurrentPartition() {
  let gsBase = getGsBase();
  return u64(gsBase.add(HV_PARTITION_OFFSET_FROM_GS_BASE));
}

/**
  Prints a list of Virtual Processor structure's base addresses that 
  are under the current partition.
*/
function getVpsList() {
  let currentParition = getCurrentPartition();

  let numberOfVps = u32(
    currentParition.add(NUMBER_OF_VPS_OFFSET_FROM_HV_PARTITION),
  );

  let vpsListPointer = u64(
    currentParition.add(VP_ARRAY_OFFSET_FROM_HV_PARTITION),
  );

  log(`\t[*] Number Of Virtual Processors: 0x${numberOfVps.toString(8)}\n`);

  for (let index = 0; index < numberOfVps; index++) {
    let vp = u64(
      currentParition.add(VP_ARRAY_OFFSET_FROM_HV_PARTITION + 8 * index),
    );
    log(`\t[*] Virtual Processor[${index}]: 0x${vp.toString(16)}\n`);
  }
}

function getVmcsAddressesList() {
  let vtlsListDoublePointer = getVtlsList();

  // Hardcoding the number of VTLs since we know there are 2 VTLs.
  // We can get the exact number of active VTLs in 2 ways:
  //   1. Partition-wide active VTLs - by reading HvRegisterVsmPartitionStatus.EnabledVtlSet bitmask field
  //   2. Per Virtual Processor active VTLs - by reading HvRegisterVsmVpStatus.EnabledVtlSet bitmask field
  for (let index = 0; index < 2; index++) {
    let vtl = u64(vtlsListDoublePointer.add(8 * index));
    let vtlStateRegion = vtl.add(VTL_STATE_REGION_OFFSET_FROM_HV_VTL);
    let vmcsInfo = vtlStateRegion.add(
      VMCS_INFO_STRUCTURE_OFFSET_FROM_VTL_STATE_REGION,
    );

    const vmcsVirtualAddress = u64(
      u64(vmcsInfo).add(VMCS_VIRTUAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE),
    );
    const vmcsPhysicalAddress = u64(
      u64(vmcsInfo).add(VMCS_PHYSICAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE),
    );

    log(`\t[*] VTL[${index}]:`);
    log(`\t\t[*] VMCS Virtual Address = 0x${vmcsVirtualAddress.toString(16)}`);
    log(
      `\t\t[*] VMCS Physical Address = 0x${vmcsPhysicalAddress.toString(16)}\n`,
    );
  }
}

function getCurrentVmcs() {
  const gsBase = getGsBase();
  const vmcs_address = u64(gsBase.add(HV_GS_CURRENT_VMCS_OFFSET));

  loadHyperVTypes();
  return host.namespace.Debugger.Utility.Analysis.SyntheticTypes.CreateInstance(
    "HV_VMX_ENLIGHTENED_VMCS",
    vmcs_address,
  );
}

function getVmcsInfo(vmcs) {
  loadHyperVTypes();
  return host.namespace.Debugger.Utility.Analysis.SyntheticTypes.CreateInstance(
    "HV_VMX_ENLIGHTENED_VMCS",
    vmcs,
  );
}

function getCurrentEptPointer() {
  const currentVmcs = getCurrentVmcs();
  const eptRoot = currentVmcs.EptRoot;
  return eptRoot;
}

class Address {
  constructor(address, cr3 = undefined, physAddress = undefined) {
    this.address = asUint64(address);
    this.pml4Index = bits(this.address, 39, 9);
    this.pdptIndex = bits(this.address, 30, 9);
    this.pdIndex = bits(this.address, 21, 9);
    this.ptIndex = bits(this.address, 12, 9);
    this.cr3 = cr3;
    this.physAddress = physAddress;
  }

  toString() {
    return `Virt: 0x${this.address.toString(16)}, Phys: 0x${this.physAddress.toString(16)}`;
  }
}

class EptEntry {
  constructor(raw) {
    this.raw = asUint64(raw);
  }

  isPresent() {
    return !(this.raw.bitwiseAnd(0x7) == 0);
  }

  isLargePage() {
    return !(this.raw.bitwiseAnd(0x80) == 0);
  }

  entry(index) {
    return this.raw.bitwiseAnd(PFN_MASK).add(index.multiply(8));
  }
}

function gpa2Hpa(gpa) {
  const address = new Address(gpa);

  const pml4 = new EptEntry(getCurrentEptPointer());
  if (!pml4.isPresent()) return;

  const pdpt = new EptEntry(read64(pml4.entry(address.pml4Index), true));
  if (!pdpt.isPresent()) return;

  const pd = new EptEntry(read64(pdpt.entry(address.pdptIndex), true));
  if (!pd.isPresent()) return;

  // 1GB huge page
  if (pd.isLargePage()) {
    return pd.raw.bitwiseAnd(PFN_MASK_1G).bitwiseOr(gpa.bitwiseAnd(0x3fffffff));
  }

  const pde = new EptEntry(read64(pd.entry(address.pdIndex), true));
  if (!pde.isPresent()) return;

  // 2MB large page
  if (pde.isLargePage()) {
    return pde.raw.bitwiseAnd(PFN_MASK_2M).bitwiseOr(gpa.bitwiseAnd(0x1fffff));
  }

  // 4KB page
  const pte = new EptEntry(read64(pde.entry(address.ptIndex), true));
  return pte.raw.bitwiseAnd(PFN_MASK).bitwiseOr(gpa.bitwiseAnd(0xfff));
}

/**
  Wrapper to get the physical address for a virtual address and CR3.
  Assumes `kext` extension is loaded.
*/
function v2p(cr3, va) {
  const vtopOutput = system(`!vtop 0x${cr3.toString(16)} 0x${va.toString(16)}`);
  for (let line of vtopOutput) {
    if (line.includes("Mapped phys")) {
      return host.parseInt64(`0x${line.split(" ")[3].toString(16)}`);
    }
  }
  return null;
}

/**
  Returns the current guest image base virtual and physical addresses.
*/
function findGuestModuleBaseAddress() {
  const CHUNK_SIZE = PAGE_SIZE;
  const NUM_OF_PAGES_IN_1MB = ONE_MB / 256;

  // Find the guest return address by reading the guest top of the stack:
  let guestRspVirtAddr = getCurrentVmcs().GuestRsp;
  let guestCr3PhysAddr = getCurrentVmcs().GuestCr3;
  let guestRspPhysAddr = v2p(guestCr3PhysAddr, guestRspVirtAddr);
  // TODO: handle guestRspPhysAddr==null

  let guestReturnAddrVirtAddr = asUint64(read64(guestRspPhysAddr, true));
  let guestSymbolAligned = guestReturnAddrVirtAddr.bitwiseAnd(PAGE_MASK);

  // Now that we have an address in the guest memory space,
  // We can search for the guest module base address.

  // Find the guest module base address.
  let currentVirtAddr = guestSymbolAligned;
  for (let i = 0; i < NUM_OF_PAGES_IN_1MB; i++) {
    let currentPhysAddress = v2p(guestCr3PhysAddr, currentVirtAddr);
    if (null == currentPhysAddress) {
      return `[-] Probably Got invalid PTE for VA=0x${currentVirtAddr.toString(16)}`;
    }
    let tempPeMagic = read16(currentPhysAddress, true);
    if (tempPeMagic == 0x5a4d) {
      // 'MZ'
      return new Address(currentVirtAddr, guestCr3PhysAddr, currentPhysAddress);
    }

    currentVirtAddr = currentVirtAddr.subtract(CHUNK_SIZE);
  }
  return None;
}

class Guest {
  constructor() {
    const currentVmcs = getCurrentVmcs();

    this.rsp = currentVmcs.GuestRsp;
    this.rip = currentVmcs.GuestRip;
    this.cr0 = new CR0(currentVmcs.GuestCr0);
    this.cr3 = currentVmcs.GuestCr3;
    this.cr4 = new CR4(currentVmcs.GuestCr4);
    this.dr7 = new DR7(currentVmcs.GuestDr7);
    this.idtrBase = currentVmcs.GuestIdtrBase;
    this.imageBase = findGuestModuleBaseAddress();

    this.toString = () => {
      return `RIP = 0x${this.rip.toString(16)}`;
    };
  }
}

/**
  Returns information about the current guest.
*/
function getGuestInfo() {
  return new Guest();
}

function printUsage() {
  log(" HyperV Research Tools:");
  log("   !gpa2hpa <gpa>  - Translates GPA to SPA");
  log(
    "   !vmcs           - Prints the current active VMCS base address on logical processor",
  );
  log("   !vtlnumber      - Prints the active VTL's VTL number");
  log(
    "   !currentvp      - Prints the current Virtual Processor's HV_VP data structure base address",
  );
  log(
    "   !partition      - Prints the current partition's HV_PARTITION data structure base address",
  );
  log(
    "   !currentvtl     - Prints the current VTL's HV_VTL data structure base address",
  );
  log(
    "   !vtls           - Prints all the existing VTL's HV_VTL data structure base addresses",
  );
  log(
    "   !vps            - Prints all the existing VPs HV_VP data structure base addresses",
  );
  log(
    "   !vmcslist       - Prints a list of all VMCSes Virtual and Physical addresses",
  );
  log("   !guest          - Prints information about the guest VM");
}

function initializeScript() {
  printUsage();

  return [
    new host.apiVersionSupport(1, 9),
    new host.functionAlias(gpa2Hpa, "gpa2hpa"),
    new host.functionAlias(getCurrentVmcs, "vmcs"),
    new host.functionAlias(getCurrentVtlNumber, "vtlnumber"),
    new host.functionAlias(getCurrentVirtualProcessor, "currentvp"),
    new host.functionAlias(getCurrentVtl, "currentvtl"),
    new host.functionAlias(printVtlsList, "vtls"),
    new host.functionAlias(getCurrentPartition, "partition"),
    new host.functionAlias(getVpsList, "vps"),
    new host.functionAlias(getVmcsAddressesList, "vmcslist"),
    new host.functionAlias(getGuestInfo, "guest"),
    new host.functionAlias(getVmcsInfo, "vmcsinfo"),
  ];
}
