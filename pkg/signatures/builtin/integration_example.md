# External Signature Module Integration

This document shows how external signature modules can integrate with Tracee's configurable signature registry.

## For External Signature Module Authors

### 1. Implement the SignatureProvider Interface

```go
// In your external module: github.com/company/internal-signatures
package internalsigs

import (
    "github.com/aquasecurity/tracee/pkg/signatures/builtin"
    "github.com/aquasecurity/tracee/types/detect"
)

type InternalSignatureProvider struct{}

func (p *InternalSignatureProvider) GetSignatures() []detect.Signature {
    return []detect.Signature{
        &CompanySpecificThreat{},
        &InternalPolicyViolation{},
        &ProprietaryDataAccess{},
    }
}

func (p *InternalSignatureProvider) GetDataSources() []detect.DataSource {
    return []detect.DataSource{
        &CompanyActiveDirectory{},
        &InternalAssetDatabase{},
    }
}

// Export a function to get the provider
func GetProvider() builtin.SignatureProvider {
    return &InternalSignatureProvider{}
}
```

### 2. Export Signatures and Data Sources (Optional Legacy Format)

You can also export in the legacy format for compatibility:

```go
var ExportedSignatures = []detect.Signature{
    &CompanySpecificThreat{},
    &InternalPolicyViolation{},
    &ProprietaryDataAccess{},
}

var ExportedDataSources = []detect.DataSource{
    &CompanyActiveDirectory{},
    &InternalAssetDatabase{},
}
```

## For Tracee Integration

### Option 1: Direct Provider Registration

```go
// In your custom Tracee build
package main

import (
    internalsigs "github.com/company/internal-signatures"
    "github.com/aquasecurity/tracee/pkg/signatures/builtin"
    "github.com/aquasecurity/tracee/pkg/signatures/signature"
)

func createSignatureRegistry() *builtin.Registry {
    // Create registry with built-in signatures + external providers
    return builtin.NewRegistryWithProviders(
        internalsigs.GetProvider(),
        // Add more providers as needed
    )
}

// Then use in signature loading:
func loadSignatures() ([]detect.Signature, []detect.DataSource, error) {
    registry := createSignatureRegistry()
    return registry.GetSignatures(), registry.GetDataSources(), nil
}
```

### Option 2: Legacy Format Integration

```go
// If using legacy exported format
func createLegacyProvider(sigs []detect.Signature, ds []detect.DataSource) builtin.SignatureProvider {
    return builtin.NewExampleExternalProvider(sigs, ds)
}

func createSignatureRegistry() *builtin.Registry {
    registry := builtin.NewRegistry()
    
    // Add external signatures using legacy format
    externalProvider := createLegacyProvider(
        internalsigs.ExportedSignatures,
        internalsigs.ExportedDataSources,
    )
    registry.AddProvider(externalProvider)
    
    return registry
}
```

### Option 3: Runtime Configuration

```go
// For dynamic configuration based on environment or config files
func createConfigurableRegistry() *builtin.Registry {
    registry := builtin.NewRegistry()
    
    // Check environment or config to determine which external modules to load
    if shouldLoadInternalSignatures() {
        registry.AddProvider(internalsigs.GetProvider())
    }
    
    if shouldLoadPartnerSignatures() {
        registry.AddProvider(partnersigs.GetProvider())
    }
    
    return registry
}
```

## Benefits

1. **Modular**: External signature modules are completely separate
2. **Configurable**: Can choose which signature sets to include at build time
3. **Backward Compatible**: Existing signature interface unchanged
4. **No Plugin Issues**: Everything compiled statically, no runtime loading
5. **Version Control**: External signatures versioned independently
6. **Access Control**: Internal signatures can stay in private repositories

## Migration from Plugin System

The new approach provides the same flexibility as the plugin system but with static compilation:

- **Before**: `--signatures-dir /path/to/plugins` (loaded .so files at runtime)
- **After**: Import signature modules and configure registry at build time

This eliminates all the plugin.so issues while maintaining modularity and configurability. 