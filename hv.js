"use strict";

const log = (x) => host.diagnostics.debugLog(`${x}\n`);
const system = (x) => host.namespace.Debugger.Utility.Control.ExecuteCommand(x);
const asUint64 = (x) => host.evaluateExpression(`(unsigned __int64) ${x}`);

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

// For 25H2
const VMCS_OFFSET_FROM_GS_BASE = 0x2c680;
const VIRTUAL_PROCESSOR_OFFSET_FROM_GS_BASE = 0x358;
const VTL_OFFSET_FROM_VIRTUAL_PROCESSOR = 0x3c0;

// For 24H2 (Potentially also 25H2)
const VTL_ARRAY_OFFSET_FROM_VIRTUAL_PROCESSOR = 0x148;
const HV_PARTITION_OFFSET_FROM_GS_BASE = 0x360;
const VP_ARRAY_OFFSET_FROM_HV_PARTITION = 0x1e0;
const NUMBER_OF_VPS_OFFSET_FROM_HV_PARTITION = 0x1d0; // Holds the number of VPs under partition

const VTL_STATE_REGION_OFFSET_FROM_HV_VTL = 0x13C0;
const VMCS_INFO_STRUCTURE_OFFSET_FROM_VTL_STATE_REGION = 0x28;
const VMCS_VIRTUAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE = 0x180;
const VMCS_PHYSICAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE = 0x188;


// Globals
const PFN_MASK = 0x000fffffffff000;
const PFN_MASK_2M = 0x000ffffffe00000;
const PFN_MASK_1G = 0x000ffffffc00000;

const u8 = (x) => host.memory.readMemoryValues(x, 1, 1)[0];
const u16 = (x) => host.memory.readMemoryValues(x, 1, 2)[0];
const u32 = (x) => host.memory.readMemoryValues(x, 1, 4)[0];
const u64 = (x) => host.memory.readMemoryValues(x, 1, 8)[0];
const u128 = (x) => host.memory.readMemoryValues(x, 1, 16)[0];

function read64(x, phy = false) {
  if (phy) {
    x = host.memory.physicalAddress(x);
  }

  return host.memory.readMemoryValues(x, 1, 8)[0];
}

function getGsBase() {
  return host.parseInt64(system("dq gs:[0] L1")[0].split(" ")[2], 16);
}

function getCurrentVtlNumber() {
  const gsBase = getGsBase();
  const vp_address = u64(gsBase.add(VIRTUAL_PROCESSOR_OFFSET_FROM_GS_BASE));
  const vtl_number = u8(vp_address.add(VTL_OFFSET_FROM_VIRTUAL_PROCESSOR));
  return vtl_number;
}

// returns a HV_VP structure representing a virtual processor
function getCurrentVirtualProcessor() {
  const gsBase = getGsBase();
  const vp_address = u64(gsBase.add(VIRTUAL_PROCESSOR_OFFSET_FROM_GS_BASE));
  return vp_address;
}

// Returns a HV_VTL structure represeting a VTL
function getCurrentVtl() {
  const gsBase = getGsBase();
  const vp_address = u64(gsBase.add(VIRTUAL_PROCESSOR_OFFSET_FROM_GS_BASE));
  const vtl = u64(vp_address.add(VTL_OFFSET_FROM_VIRTUAL_PROCESSOR));
  return vtl;
}


function getVtlsList() {
    let VirtualProcessor = getCurrentVirtualProcessor();
    let vtlsListDoublePointer = VirtualProcessor.add(VTL_ARRAY_OFFSET_FROM_VIRTUAL_PROCESSOR);

    // Since there are currently only 2 VTLs (VTL0 & VTL1) supported, the function will iterate only on 2 VTLs.
    // but we can get per the number of active VTLs per VP - by reading
    // HvRegisterVsmVpStatus.EnabledVtlSet bitmask field
    for (let index = 0; index < 2; index++)
    {
      let vtl = u64(vtlsListDoublePointer.add(8 * index));
      let strVtlAddress  = vtl.toString(16);
      host.diagnostics.debugLog("\t[*] VTL[", index, "]: 0x", strVtlAddress, "\n")
    }
    return vtlsListDoublePointer;
}

function getCurrentPartition()
{
  let gsBase = getGsBase();
  return u64(gsBase.add(HV_PARTITION_OFFSET_FROM_GS_BASE));
}

// prints a list of Virtual Processors that are under the current partition
function getVpsList()
{
    let currentParition = getCurrentPartition();
    let numberOfVps = u32(currentParition.add(NUMBER_OF_VPS_OFFSET_FROM_HV_PARTITION));
    let vpsListPointer = u64(currentParition.add(VP_ARRAY_OFFSET_FROM_HV_PARTITION));

    host.diagnostics.debugLog("\t[*] current Partition: 0x", currentParition.toString(16), "\n")
    host.diagnostics.debugLog("\t[*] Number Of Virtual Processor: 0x", numberOfVps.toString(8), "\n")

    for (let index = 0; index < numberOfVps; index++)
    {
      let vp = u64(currentParition.add(VP_ARRAY_OFFSET_FROM_HV_PARTITION + 8 * index));
      let strVpAddress  = vp.toString(16);
      host.diagnostics.debugLog("\t[*] VP[", index, "]: 0x", strVpAddress, "\n")
    }
}

function getVmcsAddressesList() 
{
  let vtlsListDoublePointer = getVtlsList();
  
  host.diagnostics.debugLog("\n");

  // Hardcoding the number of VTLs since we know there are 2 VTLs.
  // We can get the exact number of active VTLs in 2 ways:
  //   1. Partition-wide active VTLs - by reading HvRegisterVsmPartitionStatus.EnabledVtlSet bitmask field
  //   2. Per Virtual Processor active VTLs - by reading HvRegisterVsmVpStatus.EnabledVtlSet bitmask field
  for(let index = 0; index < 2; index++)
  {
    let vtl = u64(vtlsListDoublePointer.add(8 * index));
    let vtlStateRegion = vtl.add(VTL_STATE_REGION_OFFSET_FROM_HV_VTL);
    let vmcsInfo = vtlStateRegion.add(VMCS_INFO_STRUCTURE_OFFSET_FROM_VTL_STATE_REGION);

    const vmcsVirtualAddress = u64(u64(vmcsInfo).add(VMCS_VIRTUAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE));
    const vmcsPhysicalAddress = u64(u64(vmcsInfo).add(VMCS_PHYSICAL_ADDRESS_OFFSET_FROM_VMCS_INFO_STRUCTURE));

    host.diagnostics.debugLog("VTL[", index, "]:\n");
    host.diagnostics.debugLog("\t[*] VMCS Virtual Address = 0x", vmcsVirtualAddress.toString(16), "\n");
    host.diagnostics.debugLog("\t[*] VMCS Physical Address = 0x", vmcsPhysicalAddress.toString(16), "\n");
  }
}

function getCurrentVmcs() {
  const gsBase = getGsBase();
  const vmcs_address = u64(gsBase.add(VMCS_OFFSET_FROM_GS_BASE));

  loadHyperVTypes();
  return host.namespace.Debugger.Utility.Analysis.SyntheticTypes.CreateInstance(
    "HV_VMX_ENLIGHTENED_VMCS",
    vmcs_address,
  );
}

// Returns the _HV_REGISTER_VSM_VP_SECURE_VTL_CONFIG value of a VTL
// The arithmetic operations were researched in HvCallGetVpRegister() hypercall
function getVsmSecureConfigVtlValue()
{
  // TODO: will be implemented soon
}

function getCurrentEptPointer() {
  const currentVmcs = getCurrentVmcs();
  const eptRoot = currentVmcs.EptRoot;
  return eptRoot;
}

class Address {
  constructor(address) {
    this.address = asUint64(address);
    this.pml4Index = bits(this.address, 39, 9);
    this.pdptIndex = bits(this.address, 30, 9);
    this.pdIndex = bits(this.address, 21, 9);
    this.ptIndex = bits(this.address, 12, 9);
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

function printUsage() {
  log(" HyperV Research Tools:");
  log("   !gpa2hpa <gpa>      ");
  log("   !vmcs               ");
  log("   !vtlnumber          ");
  log("   !currentvp          ");
  log("   !currentpartition   ");
  log("   !currentvtl         ");
  log("   !vtls               ");
  log("   !vps                ");
  log("   !vmcslist           ");
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
    new host.functionAlias(getVtlsList, "vtls"),
    new host.functionAlias(getCurrentPartition, "currentpartition"),
    new host.functionAlias(getVpsList, "vps"),
    new host.functionAlias(getVmcsAddressesList, "vmcslist")
  ];
}
