// Package builtin provides a configurable registry for compiled-in signatures
// This replaces the plugin.so loading system with direct compilation and
// supports both built-in signatures and external signature modules
package builtin

import (
	signatures "github.com/aquasecurity/tracee/signatures/golang"
	"github.com/aquasecurity/tracee/types/detect"
)

// SignatureProvider defines an interface for signature providers
type SignatureProvider interface {
	GetSignatures() []detect.Signature
	GetDataSources() []detect.DataSource
}

// BuiltinProvider provides access to the built-in signatures
type BuiltinProvider struct{}

// GetSignatures returns all built-in signatures
func (bp *BuiltinProvider) GetSignatures() []detect.Signature {
	return signatures.ExportedSignatures
}

// GetDataSources returns all built-in data sources
func (bp *BuiltinProvider) GetDataSources() []detect.DataSource {
	return signatures.ExportedDataSources
}

// Registry provides access to all compiled-in signatures and data sources
// from multiple providers (built-in and external)
type Registry struct {
	providers []SignatureProvider
}

// NewRegistry creates a new registry with built-in signatures
func NewRegistry() *Registry {
	return &Registry{
		providers: []SignatureProvider{&BuiltinProvider{}},
	}
}

// NewRegistryWithProviders creates a new registry with custom providers
func NewRegistryWithProviders(providers ...SignatureProvider) *Registry {
	// Always include built-in signatures as the first provider
	allProviders := make([]SignatureProvider, 0, len(providers)+1)
	allProviders = append(allProviders, &BuiltinProvider{})
	allProviders = append(allProviders, providers...)

	return &Registry{
		providers: allProviders,
	}
}

// AddProvider adds an additional signature provider to the registry
func (r *Registry) AddProvider(provider SignatureProvider) {
	r.providers = append(r.providers, provider)
}

// GetSignatures returns all available signatures from all providers
func (r *Registry) GetSignatures() []detect.Signature {
	var allSignatures []detect.Signature
	for _, provider := range r.providers {
		allSignatures = append(allSignatures, provider.GetSignatures()...)
	}
	return allSignatures
}

// GetDataSources returns all available data sources from all providers
func (r *Registry) GetDataSources() []detect.DataSource {
	var allDataSources []detect.DataSource
	for _, provider := range r.providers {
		allDataSources = append(allDataSources, provider.GetDataSources()...)
	}
	return allDataSources
}

// GetAllSignatures returns all compiled-in signatures (legacy function for compatibility)
func GetAllSignatures() []detect.Signature {
	registry := NewRegistry()
	return registry.GetSignatures()
}

// GetAllDataSources returns all compiled-in data sources (legacy function for compatibility)
func GetAllDataSources() []detect.DataSource {
	registry := NewRegistry()
	return registry.GetDataSources()
}
