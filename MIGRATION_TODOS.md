# Signature Migration TODOs

## Quick Summary

**Status**: 6/28 signatures migrated (21%), 2/~10 derived events migrated

**Priority Order**:
1. ✅ **Foundation Complete** - Detector framework implemented
2. 🔄 **Batch 1** - Simple stateless signatures (22 remaining)
3. 🔄 **Batch 2** - Data store users (3 signatures)
4. 🔄 **Derived Events** - ~8 remaining derived events

## Critical TODOs

### 0. URGENT: Fix Container Filter in Existing Detectors

**Issue**: Current migrated detectors may use `ScopeFilters: ["container"]` which is **incorrect**.

Old signatures with `Origin: "container"` checked:
1. Container ID is non-empty
2. **AND** Container started flag is true

**Action Required**:
- [ ] Review `proc_kcore_read.go` - Change `"container"` to `"container=started"`
- [ ] Review all detectors with container scope filters
- [ ] Update tests to verify ContainerStarted flag behavior

See `CONTAINER_FILTER_MIGRATION_NOTES.md` for full details.

### 1. Migrate Simple Stateless Signatures (Batch 1)

**Goal**: Migrate 22 simple signatures that can benefit from DataFilters

**Top Priority** (similar to already migrated ones):
- [ ] `ptrace_code_injection.go` (TRC-103) - Similar to `anti_debugging.go`
- [ ] `dynamic_code_loading.go` (TRC-104) - Simple mem_prot_alert filter
- [ ] `dropped_executable.go` (TRC-1022) - Similar to `hidden_file_created.go`
- [ ] `fileless_execution.go` (TRC-105) - Similar to dynamic_code_loading

**Key Migration Pattern**:
```go
// Add DataFilters to reduce unnecessary dispatches
DataFilters: []string{"request=PTRACE_POKETEXT", "request=PTRACE_POKEDATA"}
// Or
ScopeFilters: []string{"container"}  // For container-only detection
```

**Benefits**:
- Engine-level filtering reduces CPU overhead
- Only relevant events reach detector's `OnEvent()`
- Better performance than manual filtering in detector

### 2. Migrate Data Store Users (Batch 2)

**Goal**: Migrate 3 signatures that use container/K8s metadata

- [ ] `k8s_service_account_token.go` (TRC-126)
- [ ] `kubernetes_api_connection.go` (TRC-127)
- [ ] `kubernetes_certificate_theft_attempt.go` (TRC-128)

**Key Migration Pattern**:
```go
func (d *K8sDetector) Init(params detection.DetectorParams) error {
    d.containerStore = params.DataStores.Containers()
    return nil
}

func (d *K8sDetector) OnEvent(ctx context.Context, event *v1beta1.Event) ([]detection.DetectorOutput, error) {
    containerID := event.Container.Id
    container, ok := d.containerStore.GetContainer(containerID)
    // Access K8s metadata from container
}
```

### 3. Migrate Remaining Derived Events

**Goal**: Migrate ~8 derived events to detector pattern

**High Priority**:
- [ ] `container_create.go` - Container lifecycle (uses ContainerStore)
- [ ] `container_remove.go` - Container lifecycle (uses ContainerStore)
- [ ] `process_execute_failed.go` - Failed execve tracking

**Medium Priority**:
- [ ] `net_flow.go` - Network flow aggregation
- [ ] `net_packet.go` - Network packet processing
- [ ] `net_tcp.go` - TCP connection tracking

**Review Required**:
- [ ] `hidden_kernel_module.go` - May require BPF map writes (review if suitable for detector)
- [ ] `symbols_collision.go` - Complex symbol analysis (review complexity)
- [ ] `symbols_loaded.go` - Complex symbol analysis (review complexity)

**Note**: Derived events should be migrated in `pkg/events/derive/` directory, not `detectors/`.

### 4. Testing & Validation

**For Each Migrated Detector**:
- [ ] Create unit tests (`*_test.go`)
- [ ] Compare detection output with original signature
- [ ] Verify DataFilters/ScopeFilters work correctly
- [ ] Test edge cases (missing fields, invalid data, etc.)
- [ ] Performance test (ensure no regression)

**Reference Examples**:
- `detectors/anti_debugging_test.go`
- `detectors/proc_kcore_read_test.go`
- `detectors/hidden_file_created_test.go`

### 5. Documentation Updates

- [ ] Update developer guide with migration examples
- [ ] Document DataFilters/ScopeFilters usage patterns
- [ ] Add migration checklist to developer guide
- [ ] Update API reference with new detector features

## Migration Checklist (Per Signature)

Use this checklist for each signature migration:

### Core Implementation
- [ ] Create detector file in `detectors/` directory
- [ ] Implement `GetDefinition()` with complete metadata
- [ ] Implement `Init()` for initialization
- [ ] Implement `OnEvent()` with detection logic
- [ ] Implement `Close()` if cleanup needed
- [ ] Add `init()` function with `register(&Detector{})`

### Performance Optimizations
- [ ] **Add DataFilters** to filter events at engine level
  - Filter by event data fields (pathname, request, flags, etc.)
  - Use policy filter syntax: `"pathname=/proc/kcore"`, `"request=PTRACE_TRACEME"`
- [ ] **Add ScopeFilters** for container/host filtering
  - Use: `ScopeFilters: []string{"container"}` for container-only
- [ ] **Add Version Constraints** if needed (MinVersion/MaxVersion)
- [ ] **Use DependencyOptional** for enrichment events

### Code Quality
- [ ] Use `v1beta1.GetData[T]()` or `v1beta1.GetDataSafe[T]()` for data extraction
- [ ] Replace `protocol.Event` with `*v1beta1.Event`
- [ ] Remove callback mechanism - return `[]DetectorOutput` directly
- [ ] Remove `OnSignal()` method (not needed)
- [ ] Keep same TRC-XXX ID for consistency
- [ ] Convert metadata to `ThreatMetadata` structure
- [ ] Set `AutoPopulate` fields appropriately

### Data Store Integration (If Needed)
- [ ] Access stores via `params.DataStores` in `Init()`
- [ ] Use `ProcessStore.GetProcess(entityId)` with `event.Process.EntityId`
- [ ] Use `ContainerStore.GetContainer(id)` with `event.Container.Id`
- [ ] Use `GetAncestry()` for process lineage if needed

### Testing
- [ ] Create unit tests following existing patterns
- [ ] Test DataFilters/ScopeFilters work correctly
- [ ] Test edge cases (missing fields, invalid data)
- [ ] Compare output with original signature
- [ ] Verify no detection gaps

## Implementation Notes

### Key Differences from Design Docs

1. **Return Type**: Detectors return `[]DetectorOutput` (not `[]*v1beta1.Event`)
   - Engine converts `DetectorOutput` to full events
   - Allows minimal data return + automatic enrichment

2. **Auto-Population**: Handled automatically by engine
   - Set `AutoPopulate.Threat = true` for threat metadata
   - Set `AutoPopulate.DetectedFrom = true` for detection provenance
   - Set `AutoPopulate.ProcessAncestry = true` for process lineage

3. **Data Extraction**: Use generic helpers
   - `v1beta1.GetData[T](event, "field")` - Returns (value, bool)
   - `v1beta1.GetDataSafe[T](event, "field")` - Returns (value, error)

### Common Patterns

**Pattern 1: Simple Filter-Based Detection**
```go
// DataFilter ensures only matching events reach OnEvent()
DataFilters: []string{"request=PTRACE_TRACEME"}

func OnEvent(ctx, event) ([]DetectorOutput, error) {
    // Event already filtered - just return detection
    return []DetectorOutput{{Data: nil}}, nil
}
```

**Pattern 2: Container-Only Detection**

**⚠️ CRITICAL**: Old `Origin: "container"` = `ScopeFilters: ["container=started"]`

```go
// ✅ CORRECT: Matches old Origin: "container" behavior
ScopeFilters: []string{"container=started"}  // Both Container.ID != "" AND ContainerStarted == true
DataFilters: []string{"pathname=/proc/kcore"}

func OnEvent(ctx, event) ([]DetectorOutput, error) {
    // Verify additional conditions if needed
    if strings.HasSuffix(pathname, "/proc/kcore") {
        return []DetectorOutput{{Data: nil}}, nil
    }
    return nil, nil
}
```

**❌ WRONG**:
```go
// This only checks Container.ID != "", missing ContainerStarted check
ScopeFilters: []string{"container"}
```

**Pattern 3: Data Store Access**
```go
func Init(params) error {
    d.containerStore = params.DataStores.Containers()
    return nil
}

func OnEvent(ctx, event) ([]DetectorOutput, error) {
    container, ok := d.containerStore.GetContainer(event.Container.Id)
    // Use container metadata
}
```

## Next Actions

1. **Start with `ptrace_code_injection.go`** - Similar to already migrated `anti_debugging.go`
2. **Batch migrate simple signatures** - Focus on ones that benefit most from DataFilters
3. **Test each migration** - Ensure detection parity and performance
4. **Document patterns** - Update developer guide as patterns emerge

## Resources

- **Migration Status**: `SIGNATURE_MIGRATION_STATUS.md`
- **Design Docs**: `mindmap/tracee/design/event-detector-api.md`
- **Developer Guide**: `docs/docs/detectors/developer-guide.md`
- **Example Detectors**: `detectors/*.go`
- **Test Examples**: `detectors/*_test.go`

