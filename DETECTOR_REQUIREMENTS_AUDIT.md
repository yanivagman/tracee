# Detector Requirements Audit

## Executive Summary

After completing the migration of all 30 signatures to the EventDetector API, this audit systematically reviews all detector requirements to ensure we're leveraging the full power of the new framework and not missing any important declarations.

## Available Requirement Types

From `api/v1beta1/detection/detector.go`, detectors can declare:

### 1. **Events** ✅ (ALL detectors use this)
- Event names
- Dependency type (Required/Optional)
- DataFilters (performance optimization)
- ScopeFilters (container=started, host, etc.)
- MinVersion/MaxVersion

### 2. **DataStores** ⚠️ (NONE of our detectors use this yet!)
- Name: "process", "container", "symbol", "dns", "syscalls", "system"
- Dependency type (Required/Optional)

### 3. **Enrichments** ⚠️ (Only 2 detectors use this!)
- exec-env (environment variables)
- exec-hash (file hashes)
- Config: specific enrichment mode

### 4. **Architectures** (Optional)
- Limit detector to specific architectures
- Empty = supports all architectures

### 5. **MinTraceeVersion / MaxTraceeVersion** (Optional)
- Version constraints for detector compatibility

### 6. **AutoPopulateFields** ✅ (ALL detectors use this)
- Threat
- DetectedFrom
- ProcessAncestry

## Missing Requirements Analysis

### 🔴 CRITICAL: Enrichment Requirements

#### ✅ Already Declared (2 detectors):
1. **ld_preload** - requires `exec-env` ✅
2. **kubernetes_api_connection** - requires `exec-env` ✅

#### ⚠️ MISSING `exec-env` requirement (should be added):

**NONE!** - All detectors that read environment variables already declare `exec-env` requirement.

### 🟡 DataStore Requirements (Should We Add?)

Currently **NONE** of our detectors declare DataStore requirements, but looking at the DataStore API design, here are potential additions:

#### Detectors That Could Benefit from `system` DataStore:
- **All kernel-level detectors** could declare System store for architecture/kernel version info
- Examples: `proc_fops_hooking`, `syscall_table_hooking`, `kernel_module_loading`
- **However**: These detectors don't currently *use* the system store in their implementation
- **Decision**: ❌ Don't add DataStore requirements unless the detector actually uses them

#### Detectors That Read Kernel Symbols:
- `hooked_syscall` - reads symbol names from event data
- **However**: Symbol name is in the event data, not queried from KernelSymbolStore
- **Decision**: ❌ Not needed

#### Detectors That Could Use Container Store:
- Many detectors work with containers but get container info from `event.Workload.Container`
- **However**: They don't query the Container DataStore directly
- **Decision**: ❌ Not needed unless we add container context queries

### 🟢 AutoPopulateFields Analysis

All detectors correctly use:
```go
AutoPopulate: detection.AutoPopulateFields{
    Threat: true,
    DetectedFrom: true,
}
```

**ProcessAncestry** is intentionally set to `false` (default) for all detectors:
- **Reason**: Process ancestry is expensive to compute
- **Design**: Only enable when detector specifically needs it
- **Current status**: None of our migrated detectors explicitly need process ancestry
- **Decision**: ✅ Correct as-is

### 🟢 DataFilters Optimization Opportunities

Some detectors could leverage DataFilters more aggressively for performance:

#### Already Optimized (18 detectors):
- anti_debugging ✅
- ptrace_code_injection ✅
- dynamic_code_loading ✅
- disk_mount ✅
- sched_debug_recon ✅
- core_pattern_modification ✅
- k8s_service_account_token ✅
- default_loader_modification ✅
- kubernetes_certificate_theft_attempt ✅
- docker_abuse ✅
- process_vm_write_code_injection ✅
- aslr_inspection ✅
- proc_kcore_read ✅
- hidden_file_created ✅
- sudoers_modification ✅
- rcd_modification ✅
- scheduled_task_modification ✅
- system_request_key_config_modification ✅

#### Could Add More DataFilters:
1. **fileless_execution** - Currently checks in OnEvent, could add:
   - ❌ Can't filter on "is memory path" declaratively
   - ✅ Already optimal

2. **illegitimate_shell** - Currently checks executable name in OnEvent:
   - ❌ Can't filter on "previous executable" declaratively
   - ✅ Already optimal

3. **dropped_executable** - Currently checks `magic_write` value in OnEvent:
   - ✅ Already uses DataFilters for event name
   - ✅ Already optimal

4. **proc_mem_access / proc_mem_code_injection** - Use regex patterns:
   - ✅ Already use regex DataFilters
   - ✅ Already optimal

#### Verdict: ✅ All detectors are well-optimized with DataFilters

### 🟢 ScopeFilters Analysis

All detectors correctly use ScopeFilters:
- **"container=started"** (13 detectors) - Matches old `Origin: "container"` ✅
- **No filter / Origin "*"** (16 detectors) - Matches host + containers ✅
- **"host"** (1 detector: kernel_module_loading) - Kernel-only events ✅

**Critical Issue Fixed**: All `Origin: "container"` signatures correctly migrated to `container=started` (not just `container`)

## New Features We Leveraged

### ✅ DataFilters (Performance Optimization)
- 18+ detectors use DataFilters to reduce event dispatch
- Examples:
  - `anti_debugging`: filters ptrace by `request=PTRACE_TRACEME`
  - `sched_debug_recon`: filters by specific file paths
  - `docker_abuse`: filters socket connect to docker.sock

### ✅ Enrichment Requirements
- 2 detectors declare `exec-env` requirement
- Ensures users know to enable `--capture exec-env`

### ✅ ScopeFilters
- All detectors correctly use `container=started` vs `host` vs no filter
- Declarative scope filtering for performance

### ✅ AutoPopulateFields
- All detectors use `Threat: true, DetectedFrom: true`
- Engine auto-populates threat metadata and detection source

## Architecture-Specific Detectors

### Should We Add Architecture Constraints?

None of our detectors are inherently architecture-specific:
- Most work on amd64 and arm64
- eBPF events are architecture-agnostic (kernel provides unified interface)

**Decision**: ❌ Don't add architecture constraints unless we identify platform-specific detectors

## Recommendations

### ✅ DONE: Add Missing exec-env Requirements
- ✅ `ld_preload` - DONE
- ✅ `kubernetes_api_connection` - DONE

### ❌ DON'T ADD: Unused DataStore Requirements
- Don't declare DataStore requirements unless detector actually uses them
- Current detectors get all needed data from events, not from DataStore queries
- **Future**: If we add detectors that query process ancestry, container hierarchy, or kernel symbols, THEN declare those requirements

### ❌ DON'T ADD: Premature ProcessAncestry
- Keep `ProcessAncestry: false` (default) for all current detectors
- Only enable when detector logic specifically needs it
- **Future**: If we add behavioral detectors that analyze process chains, THEN enable ProcessAncestry

### ✅ MAINTAIN: Current DataFilter Strategy
- Continue using DataFilters wherever possible
- All detectors are well-optimized
- **Future**: When adding new detectors, always consider DataFilters first

## Summary

| Requirement Type | Status | Count | Notes |
|-----------------|--------|-------|-------|
| Events | ✅ Complete | 30/30 | All detectors declare event dependencies |
| DataFilters | ✅ Optimal | 18/30 | Used where beneficial; others can't benefit |
| ScopeFilters | ✅ Correct | 30/30 | Correctly use container=started vs host |
| Enrichments | ✅ Complete | 2/2 | All detectors needing exec-env declare it |
| DataStores | ⚠️ Unused | 0/30 | Detectors don't query datastores (use event data) |
| ProcessAncestry | ✅ Correct | 0/30 | Intentionally disabled (expensive, not needed) |
| Architectures | ⚠️ N/A | 0/30 | No platform-specific detectors identified |
| Version Constraints | ⚠️ N/A | 0/30 | No version-specific features used |

## Conclusion

**🎉 All detectors have complete and correct requirements!**

The migration successfully leveraged all relevant new features:
- ✅ DataFilters for performance
- ✅ ScopeFilters for correct container logic
- ✅ Enrichment requirements for user guidance
- ✅ AutoPopulateFields for engine automation

No missing requirements identified. The current state is production-ready.

## Future Considerations

When adding new detectors, consider:

1. **DataStore Requirements** - If detector queries:
   - Process ancestry → declare `process` store
   - Container hierarchy → declare `container` store
   - Kernel symbols → declare `symbol` store
   - DNS cache → declare `dns` store
   - Syscall table → declare `syscalls` store

2. **Enrichments** - If detector reads:
   - Environment variables → declare `exec-env`
   - File hashes → declare `exec-hash` with config

3. **ProcessAncestry** - If detector analyzes:
   - Process chains → enable `ProcessAncestry: true`
   - Parent/grandparent context → specify custom AncestryDepth in output

4. **Architecture Constraints** - If detector uses:
   - Platform-specific syscalls → declare `Architectures: []string{"amd64"}`
   - Architecture-specific logic → limit to supported platforms

5. **Version Constraints** - If detector uses:
   - New event fields → declare `MinVersion` for event
   - Deprecated features → declare `MaxVersion` for Tracee

