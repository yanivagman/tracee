package signature

import (
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/builtin"
	"github.com/aquasecurity/tracee/types/detect"
)

func Find(signaturesDir []string, signatures []string) ([]detect.Signature, []detect.DataSource, error) {
	// With the removal of plugin.so, signaturesDir is no longer used for loading
	// signatures as they are now compiled directly into the binary.
	// We log a deprecation warning if directories are specified.
	if len(signaturesDir) > 0 {
		logger.Warnw("Signature directories are deprecated with compiled-in signatures and will be ignored",
			"directories", signaturesDir)
	}

	// Get compiled-in signatures from the builtin registry
	registry := builtin.NewRegistry()
	allSigs := registry.GetSignatures()
	allDataSources := registry.GetDataSources()

	// Filter signatures based on the requested names/IDs
	var selectedSigs []detect.Signature
	if signatures == nil {
		// No filter specified, return all signatures
		selectedSigs = allSigs
	} else {
		// Filter signatures by name or ID
		for _, sig := range allSigs {
			for _, requested := range signatures {
				if metadata, err := sig.GetMetadata(); err == nil &&
					(metadata.ID == requested || metadata.EventName == requested) {
					selectedSigs = append(selectedSigs, sig)
					break
				}
			}
		}
	}

	return selectedSigs, allDataSources, nil
}
