# Signature Migration Status

## Overview

This document tracks the migration of signatures from the legacy plugin-based system to the new EventDetector framework. The migration follows the patterns established in the design documents and considers new features available to detectors.

## Migration Statistics

### Signatures
- **Total Signatures**: 28
- **Migrated**: 9 (32%)
- **Remaining**: 19 (68%)

### Derived Events
- **Total Derived Events**: ~10
- **Migrated**: 3 (`hooked_syscall`, `hooked_seq_ops`, `hidden_file_created`)
- **Remaining**: ~7 (`container_create`, `container_remove`, `hidden_kernel_module`, `symbols_collision`, `symbols_loaded`, `net_flow`, `net_packet`, `net_tcp`, `process_execute_failed`)

## Migrated Detectors

The following signatures have been successfully migrated to detectors:

| Signature | Detector | ID | Status | Notes |
|-----------|----------|----|----|-------|
| `anti_debugging_ptraceme.go` | `anti_debugging.go` | TRC-102 | ✅ Complete | Uses DataFilters for `request=PTRACE_TRACEME` |
| `aslr_inspection.go` | `aslr_inspection.go` | - | ✅ Complete | Stateful with LRU cache |
| `hidden_file_created.go` | `hidden_file_created.go` | TRC-1015 | ✅ Complete | Derived event detector |
| `proc_kcore_read.go` | `proc_kcore_read.go` | TRC-109 | ✅ Complete | **FIXED:** Uses ScopeFilters: `container=started` |
| `hooked_syscall.go` | `hooked_syscall.go` | TRC-1014 | ✅ Complete | Derived event detector |
| `hooked_seq_ops.go` | `hooked_seq_ops.go` | TRC-1026 | ✅ Complete | Derived event detector |
| **`ptrace_code_injection.go`** | **`ptrace_code_injection.go`** | **TRC-103** | ✅ **NEW** | **Uses DataFilters for POKETEXT/POKEDATA** |
| **`dynamic_code_loading.go`** | **`dynamic_code_loading.go`** | **TRC-104** | ✅ **NEW** | **Uses DataFilters for ProtAlertMprotectWXToX** |
| **`fileless_execution.go`** | **`fileless_execution.go`** | **TRC-105** | ✅ **NEW** | **Uses parsers.IsMemoryPath() logic** |

## Remaining Signatures to Migrate

### Batch 1: Simple Stateless Detectors (High Priority)

These signatures are stateless and should be straightforward to migrate. They can benefit from DataFilters to improve performance.

| Signature | ID | Complexity | Key Events | Migration Notes |
|-----------|----|----|-----------|----------------|
| ~~`ptrace_code_injection.go`~~ | ~~TRC-103~~ | ~~Low~~ | ~~`ptrace`~~ | ✅ **MIGRATED** |
| ~~`dynamic_code_loading.go`~~ | ~~TRC-104~~ | ~~Low~~ | ~~`mem_prot_alert`~~ | ✅ **MIGRATED** |
| ~~`fileless_execution.go`~~ | ~~TRC-105~~ | ~~Low~~ | ~~`sched_process_exec`~~ | ✅ **MIGRATED** |
| `dropped_executable.go` | TRC-1022 | Low | `magic_write` | Use ScopeFilters: `container=started` + DataFilters for ELF check |
| `proc_mem_access.go` | TRC-106 | Low | `security_file_open` | Use DataFilters for `/proc/*/mem` paths |
| `proc_mem_code_injection.go` | TRC-107 | Low | `security_file_open` | Use DataFilters for `/proc/*/mem` + write flags |
| `process_vm_write_code_injection.go` | TRC-108 | Low | `process_vm_writev` | Use DataFilters for write operations |
| `proc_fops_hooking.go` | TRC-109 | Low | `security_file_open` | Use DataFilters for `/proc/*` paths |
| `syscall_table_hooking.go` | TRC-110 | Low | `security_file_open` | Use DataFilters for syscall table paths |
| `kernel_module_loading.go` | TRC-111 | Low | `security_file_open` | Use DataFilters for module paths |
| `ld_preload.go` | TRC-112 | Low | `security_file_open` | Use DataFilters for `/etc/ld.so.preload` |
| `core_pattern_modification.go` | TRC-113 | Low | `security_file_open` | Use DataFilters for `/proc/sys/kernel/core_pattern` |
| `default_loader_modification.go` | TRC-114 | Low | `security_file_open` | Use DataFilters for loader paths |
| `cgroup_notify_on_release_modification.go` | TRC-115 | Low | `security_file_open` | Use DataFilters for cgroup paths |
| `cgroup_release_agent_modification.go` | TRC-116 | Low | `security_file_open` | Use DataFilters for cgroup paths |
| `rcd_modification.go` | TRC-117 | Low | `security_file_open` | Use DataFilters for rc.d paths |
| `scheduled_task_modification.go` | TRC-118 | Low | `security_file_open` | Use DataFilters for cron/task paths |
| `sudoers_modification.go` | TRC-119 | Low | `security_file_open` | Use DataFilters for `/etc/sudoers` |
| `system_request_key_config_modification.go` | TRC-120 | Low | `security_file_open` | Use DataFilters for sysrq paths |
| `disk_mount.go` | TRC-121 | Low | `mount` | Use DataFilters for mount operations |
| `docker_abuse.go` | TRC-122 | Low | `security_file_open` | Use DataFilters for docker socket paths |
| `illegitimate_shell.go` | TRC-123 | Low | `execve` | Use DataFilters for shell detection |
| `stdio_over_socket.go` | TRC-124 | Low | `connect` | Use DataFilters for socket operations |
| `sched_debug_recon.go` | TRC-125 | Low | `security_file_open` | Use DataFilters for `/proc/sched_debug` |

### Batch 2: Detectors Using Data Stores (Medium Priority)

These signatures require access to data stores (ProcessStore, ContainerStore) for context.

| Signature | ID | Complexity | Data Stores Needed | Migration Notes |
|-----------|----|----|-------------------|----------------|
| `k8s_service_account_token.go` | TRC-126 | Medium | ContainerStore | Access K8s metadata from container |
| `kubernetes_api_connection.go` | TRC-127 | Medium | ContainerStore | Access K8s metadata |
| `kubernetes_certificate_theft_attempt.go` | TRC-128 | Medium | ContainerStore | Access K8s certificate paths |

### Batch 3: Stateful Detectors (Lower Priority)

These signatures use LRU caches or state tracking and require careful migration.

| Signature | ID | Complexity | State Management | Migration Notes |
|-----------|----|----|------------------|----------------|
| None in OSS | - | - | - | Stateful signatures are primarily in nautilus |

## Migration Checklist

For each signature migration, ensure:

### ✅ Core Migration Steps

- [ ] Create detector file in `detectors/` directory
- [ ] Implement `EventDetector` interface:
  - [ ] `GetDefinition()` - Complete detector definition
  - [ ] `Init()` - Initialize detector state
  - [ ] `OnEvent()` - Detection logic
  - [ ] `Close()` - Cleanup (if needed)
- [ ] Add `init()` function with `register(&Detector{})`
- [ ] Update detector ID (keep same TRC-XXX ID)
- [ ] Convert metadata to `ThreatMetadata` structure
- [ ] Set `AutoPopulate` fields appropriately

### ✅ Performance Optimizations (New Features)

- [ ] **DataFilters**: Add event data filters to reduce unnecessary dispatches
  - Example: `DataFilters: []string{"request=PTRACE_TRACEME"}` for ptrace events
  - Example: `DataFilters: []string{"pathname=/proc/kcore"}` for file paths
  - Example: `DataFilters: []string{"flags=O_WRONLY"}` for write operations
- [ ] **ScopeFilters**: Add scope filters for container/host filtering
  - **CRITICAL**: Use `"container=started"` NOT `"container"` for `Origin: "container"`
  - ✅ Correct: `ScopeFilters: []string{"container=started"}` (matches old behavior)
  - ❌ Wrong: `ScopeFilters: []string{"container"}` (missing ContainerStarted check)
  - See `CONTAINER_FILTER_MIGRATION_NOTES.md` for details
- [ ] **Version Constraints**: Add MinVersion/MaxVersion if needed
- [ ] **Dependency Types**: Use `DependencyOptional` for enrichment events

### ✅ Code Quality

- [ ] Use `v1beta1.GetData[T]()` or `v1beta1.GetDataSafe[T]()` for data extraction
- [ ] Use `v1beta1.CreateEventFromBase()` for event creation (if needed)
- [ ] Replace `protocol.Event` with `*v1beta1.Event`
- [ ] Remove callback mechanism - return `[]DetectorOutput` directly
- [ ] Remove `OnSignal()` method (not needed in detectors)
- [ ] Add unit tests (see `*_test.go` files for examples)
- [ ] Update documentation/comments

### ✅ Data Store Integration (If Needed)

- [ ] Access stores via `params.DataStores` in `Init()`
- [ ] Use `ProcessStore.GetProcess(entityId)` with `event.Process.EntityId`
- [ ] Use `ContainerStore.GetContainer(id)` with `event.Container.Id`
- [ ] Use `GetAncestry()` for process lineage (if needed)

### ✅ State Management (If Needed)

- [ ] Use LRU caches from `github.com/hashicorp/golang-lru/v2`
- [ ] Initialize caches in `Init()`
- [ ] Clean up in `Close()` method
- [ ] Ensure thread-safety with mutexes if needed

## Migration Patterns

### Pattern 1: Simple Stateless Detector

**Before (Signature)**:
```go
func (sig *PtraceCodeInjection) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    requestArg, err := eventObj.GetIntArgumentByName("request")
    if requestArg == sig.ptracePokeText || requestArg == sig.ptracePokeData {
        sig.cb(&detect.Finding{...})
    }
    return nil
}
```

**After (Detector)**:
```go
func (d *PtraceCodeInjection) GetDefinition() detection.DetectorDefinition {
    return detection.DetectorDefinition{
        Requirements: detection.DetectorRequirements{
            Events: []detection.EventRequirement{
                {
                    Name: "ptrace",
                    DataFilters: []string{
                        fmt.Sprintf("request=%d", parsers.PTRACE_POKETEXT.Value()),
                        fmt.Sprintf("request=%d", parsers.PTRACE_POKEDATA.Value()),
                    },
                },
            },
        },
        // ... threat metadata ...
    }
}

func (d *PtraceCodeInjection) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    // DataFilter ensures we only get POKETEXT/POKEDATA events
    return []detection.DetectorOutput{{Data: nil}}, nil
}
```

### Pattern 2: Detector with Scope Filter

**CRITICAL**: Old signatures with `Origin: "container"` checked TWO conditions:
1. Container ID is non-empty
2. Container started flag is true

**Before (Signature)**:
```go
func (sig *ProcKcoreRead) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open", Origin: "container"},
    }, nil
}
```

**After (Detector)**:
```go
func (d *ProcKcoreRead) GetDefinition() detection.DetectorDefinition {
    return detection.DetectorDefinition{
        Requirements: detection.DetectorRequirements{
            Events: []detection.EventRequirement{
                {
                    Name: "security_file_open",
                    // ✅ CORRECT: container=started matches Origin: "container" behavior
                    // Checks both: Container.ID != "" AND ContainerStarted == true
                    ScopeFilters: []string{"container=started"},
                    DataFilters: []string{"pathname=/proc/kcore"},
                },
            },
        },
        // ...
    }
}
```

**⚠️ Common Mistake**:
```go
// ❌ WRONG: This only checks Container.ID != "", missing ContainerStarted check
ScopeFilters: []string{"container"}

// ✅ CORRECT: This matches old Origin: "container" behavior
ScopeFilters: []string{"container=started"}
```

### Pattern 3: Detector with Data Store Access

**Before (Signature)**:
```go
// Manual container lookup
```

**After (Detector)**:
```go
func (d *K8sDetector) Init(params detection.DetectorParams) error {
    d.containerStore = params.DataStores.Containers()
    return nil
}

func (d *K8sDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    containerID := event.Container.Id
    container, ok := d.containerStore.GetContainer(containerID)
    if ok {
        // Access K8s metadata from container
    }
    return nil, nil
}
```

## Implementation Differences from Design

The actual implementation differs slightly from the design docs:

1. **Return Type**: Detectors return `[]DetectorOutput` instead of `[]*v1beta1.Event`
   - `DetectorOutput` is a lightweight struct that the engine converts to full events
   - This allows detectors to return minimal data and let the engine handle enrichment

2. **Auto-Population**: Handled automatically by the engine based on `AutoPopulate` fields
   - Detectors don't need to manually create full events
   - Engine handles Threat, DetectedFrom, ProcessAncestry automatically

3. **Data Extraction**: Use `v1beta1.GetData[T]()` and `v1beta1.GetDataSafe[T]()`
   - Generic helpers for type-safe data extraction
   - No need for manual argument parsing

## Derived Events Migration Status

### Migrated Derived Events

| Derived Event | Detector | ID | Status | Notes |
|---------------|----------|----|----|-------|
| `hooked_syscall` | `hooked_syscall.go` | DRV-002 | ✅ Complete | Uses KernelSymbolStore + SyscallStore, LRU cache |
| `hooked_seq_ops` | `hooked_seq_ops.go` | DRV-* | ✅ Complete | Similar to hooked_syscall |

### Remaining Derived Events

| Derived Event | File | Complexity | Data Stores Needed | Migration Notes |
|---------------|------|------------|---------------------|-----------------|
| `container_create` | `container_create.go` | Medium | ContainerStore | Container lifecycle tracking |
| `container_remove` | `container_remove.go` | Medium | ContainerStore | Container lifecycle tracking |
| `hidden_kernel_module` | `hidden_kernel_module.go` | High | KernelSymbolStore | May require BPF map writes - review |
| `symbols_collision` | `symbols_collision.go` | High | KernelSymbolStore | Complex symbol analysis |
| `symbols_loaded` | `symbols_loaded.go` | High | KernelSymbolStore | Complex symbol analysis |
| `net_flow` | `net_flow.go` | Medium | - | Network flow aggregation |
| `net_packet` | `net_packet.go` | Medium | - | Network packet processing |
| `net_tcp` | `net_tcp.go` | Medium | - | TCP connection tracking |
| `process_execute_failed` | `process_execute_failed.go` | Low | ProcessStore | Failed execve tracking |

**Note**: Derived events should be migrated to detectors in `pkg/events/derive/` directory (not `detectors/`) to maintain their location as built-in engine components.

## Next Steps

1. **Immediate Priority**: Migrate Batch 1 signatures (simple stateless detectors)
   - Focus on signatures that can benefit most from DataFilters
   - Start with `ptrace_code_injection.go` as it's similar to already migrated `anti_debugging.go`

2. **Medium Priority**: Migrate Batch 2 signatures (data store users)
   - Ensure data store API is complete for these use cases
   - Test data store access patterns

3. **Lower Priority**: Review Batch 3 signatures (stateful)
   - Evaluate if state management patterns need updates
   - Consider if some should remain as signatures temporarily

4. **Testing**: For each migrated detector:
   - Create unit tests (see existing `*_test.go` files)
   - Compare detection output with original signature
   - Verify DataFilters/ScopeFilters work correctly
   - Test edge cases

5. **Documentation**: Update documentation as detectors are migrated
   - Add examples to developer guide
   - Document migration patterns
   - Update API reference

## Notes

- **Event ID Consistency**: Keep the same TRC-XXX IDs when migrating
- **Backward Compatibility**: Old signatures continue to work during migration
- **Performance**: DataFilters significantly reduce unnecessary event processing
- **Testing**: Use existing test patterns from migrated detectors as reference

