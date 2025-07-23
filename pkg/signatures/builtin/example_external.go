// Package builtin - example of how external signature modules would implement SignatureProvider
package builtin

import "github.com/aquasecurity/tracee/types/detect"

// ExternalSignatureProvider is an example of how external signature modules
// would implement the SignatureProvider interface
//
// Example usage in an external module:
//
//	package myexternalsigs
//
//	import (
//		"github.com/aquasecurity/tracee/pkg/signatures/builtin"
//		"github.com/aquasecurity/tracee/types/detect"
//	)
//
//	type MySignatureProvider struct{}
//
//	func (p *MySignatureProvider) GetSignatures() []detect.Signature {
//		return []detect.Signature{
//			&MyCustomSignature1{},
//			&MyCustomSignature2{},
//		}
//	}
//
//	func (p *MySignatureProvider) GetDataSources() []detect.DataSource {
//		return []detect.DataSource{
//			// custom data sources if any
//		}
//	}
//
//	// To use the external signatures:
//	//
//	// registry := builtin.NewRegistryWithProviders(&MySignatureProvider{})
//	//
//	// Or add to existing registry:
//	//
//	// registry := builtin.NewRegistry()
//	// registry.AddProvider(&MySignatureProvider{})

// ExampleExternalProvider demonstrates the SignatureProvider interface
type ExampleExternalProvider struct {
	signatures  []detect.Signature
	dataSources []detect.DataSource
}

// NewExampleExternalProvider creates a new example external provider
func NewExampleExternalProvider(sigs []detect.Signature, ds []detect.DataSource) *ExampleExternalProvider {
	return &ExampleExternalProvider{
		signatures:  sigs,
		dataSources: ds,
	}
}

// GetSignatures returns signatures from this external provider
func (ep *ExampleExternalProvider) GetSignatures() []detect.Signature {
	return ep.signatures
}

// GetDataSources returns data sources from this external provider
func (ep *ExampleExternalProvider) GetDataSources() []detect.DataSource {
	return ep.dataSources
}
