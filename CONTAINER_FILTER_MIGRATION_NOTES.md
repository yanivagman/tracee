# Container Filter Migration Notes

## Critical: Container Filter Behavior

### Old Signature Behavior (Origin: "container")

When old signatures specified `Origin: "container"`, it checked **TWO conditions**:
1. **Container ID is non-empty** (`Container.ID != ""`)
2. **Container started flag is true** (`ContextFlags.ContainerStarted == true`)

This is implemented in `pkg/filters/scope.go`:

```go
func (f *ScopeFilter) Filter(evt trace.Event) bool {
    return f.containerFilter.Filter(evt.Container.ID != "") &&
           f.containerStartedFilter.Filter(evt.ContextFlags.ContainerStarted) &&
           // ... other filters
}
```

### Container States

Tracee tracks three container states in eBPF:

1. **CONTAINER_CREATED** - Container exists but no process has executed yet
2. **CONTAINER_EXISTED** - Container existed before Tracee started
3. **CONTAINER_STARTED** - A process in the container executed a new binary

**Key Point**: Just having a container ID doesn't mean `ContainerStarted` is true!

### New Detector Migration

**❌ INCORRECT Migration:**
```go
// This is NOT equivalent to Origin: "container"
ScopeFilters: []string{"container"}
```

This only checks `Container.ID != ""`, missing the `ContainerStarted` check!

**✅ CORRECT Migration:**
```go
// This matches Origin: "container" behavior
ScopeFilters: []string{"container=started"}
```

This checks BOTH:
- `Container.ID != ""`
- `ContextFlags.ContainerStarted == true`

### Scope Filter Syntax

```yaml
# Option 1: Any container (ID != "", ignores started state)
ScopeFilters: ["container"]

# Option 2: Only started containers (ID != "" AND started == true)
ScopeFilters: ["container=started"]

# Option 3: Host only (ID == "")
ScopeFilters: ["host"]
```

### Migration Examples

#### Example 1: proc_kcore_read

**Old Signature:**
```go
func (sig *ProcKcoreRead) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open", Origin: "container"},
    }, nil
}
```

**New Detector (Current - INCORRECT):**
```go
Requirements: detection.DetectorRequirements{
    Events: []detection.EventRequirement{
        {
            Name: "security_file_open",
            ScopeFilters: []string{"container"},  // ❌ Missing ContainerStarted check
        },
    },
}
```

**New Detector (Corrected):**
```go
Requirements: detection.DetectorRequirements{
    Events: []detection.EventRequirement{
        {
            Name: "security_file_open",
            ScopeFilters: []string{"container=started"},  // ✅ Matches old behavior
        },
    },
}
```

#### Example 2: dropped_executable

**Old Signature:**
```go
func (sig *DroppedExecutable) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "magic_write", Origin: "container"},
    }, nil
}
```

**New Detector (Corrected):**
```go
Requirements: detection.DetectorRequirements{
    Events: []detection.EventRequirement{
        {
            Name: "magic_write",
            ScopeFilters: []string{"container=started"},  // ✅ Correct
        },
    },
}
```

### Why This Matters

Events from **CONTAINER_CREATED** or **CONTAINER_EXISTED** states would be:
- ✅ **Included** with `ScopeFilters: ["container"]` (any container)
- ❌ **Excluded** with `ScopeFilters: ["container=started"]` (only started)

Old signatures with `Origin: "container"` were **excluding** these early container states, so new detectors must do the same to maintain parity.

### Implementation Details

From `pkg/ebpf/c/common/filtering.h`:

```c
// Container filter: checks state == STARTED || state == EXISTED
if (policies_cfg->cont_filter_enabled) {
    bool is_container = false;
    u8 state = p->task_info->container_state;
    if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
        is_container = true;
    // ...
}

// Container started filter: checks flag & CONTAINER_STARTED_FLAG
if (policies_cfg->cont_started_filter_enabled) {
    bool is_started = false;
    if (p->event->context.task.flags & CONTAINER_STARTED_FLAG)
        is_started = true;
    // ...
}
```

When using `container=started`, **BOTH** filters are enabled and must match.

### Testing

To verify correct migration:

```go
// Test case 1: Container with CONTAINER_STARTED state
event := &v1beta1.Event{
    Workload: &v1beta1.Workload{
        Container: &v1beta1.Container{
            Id: "abc123",
            Started: true,  // This maps to ContainerStarted flag
        },
    },
}
// Should match with ScopeFilters: ["container=started"]

// Test case 2: Container with CONTAINER_CREATED state
event := &v1beta1.Event{
    Workload: &v1beta1.Workload{
        Container: &v1beta1.Container{
            Id: "abc123",
            Started: false,  // ContainerStarted == false
        },
    },
}
// Should NOT match with ScopeFilters: ["container=started"]
// WOULD match with ScopeFilters: ["container"]
```

### Action Items

1. **Review all migrated detectors** that use `ScopeFilters: ["container"]`
2. **Change to `container=started`** if the original signature had `Origin: "container"`
3. **Update migration documentation** with this critical detail
4. **Test each migration** with both started and non-started containers

### Affected Detectors

**Currently Migrated:**
- ✅ `proc_kcore_read.go` - **FIXED** - Now uses `ScopeFilters: ["container=started"]`
- ✅ All other migrated detectors verified - No other container scope filter issues found

**To Be Migrated:**
- `dropped_executable.go` - Origin: "container" → Must use `container=started`
- `disk_mount.go` - Origin: "container" → Must use `container=started`
- `core_pattern_modification.go` - Origin: "container" → Must use `container=started`
- `cgroup_notify_on_release_modification.go` - Origin: "container" → Must use `container=started`
- `cgroup_release_agent_modification.go` - Origin: "container" → Must use `container=started`
- `docker_abuse.go` - Origin: "container" → Must use `container=started`
- `sched_debug_recon.go` - Origin: "container" → Must use `container=started`
- `system_request_key_config_modification.go` - Origin: "container" → Must use `container=started`
- `k8s_service_account_token.go` - Origin: "container" → Must use `container=started`
- `kubernetes_api_connection.go` - Origin: "container" → Must use `container=started`

### Fix History

#### proc_kcore_read.go Fix (2025-11-24)

**Issue Found:**
The previous migration of `proc_kcore_read.go` incorrectly used:
```go
ScopeFilters: []string{"container"}
```

This did not match the old signature behavior, which checked both `Container.ID != ""` AND `ContainerStarted == true`.

**Fix Applied:**
Changed `detectors/proc_kcore_read.go`:
```go
// Before (WRONG)
ScopeFilters: []string{"container"}

// After (CORRECT)
ScopeFilters: []string{"container=started"}
```

**Impact:**
- **Before fix**: Would detect /proc/kcore reads from containers in `CONTAINER_CREATED` state (false positives)
- **After fix**: Only detects from containers in `CONTAINER_STARTED` state (matches old behavior)

**Verification:**
- ✅ Verified all currently migrated detectors
- ✅ Only `proc_kcore_read.go` required the fix
- ✅ No other migrated detectors use container scope filters

## Summary

**Critical Rule**: When migrating signatures with `Origin: "container"`:

```
Origin: "container"  →  ScopeFilters: ["container=started"]
```

NOT:

```
Origin: "container"  →  ScopeFilters: ["container"]  ❌ WRONG
```

