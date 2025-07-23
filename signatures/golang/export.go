package signatures

import "github.com/aquasecurity/tracee/types/detect"

// ExportedSignatures provides the list of signatures that were previously
// exported as a plugin, now compiled directly into the binary
var ExportedSignatures = []detect.Signature{
	&StdioOverSocket{},
	&K8sApiConnection{},
	&AslrInspection{},
	&ProcMemCodeInjection{},
	&DockerAbuse{},
	&ScheduledTaskModification{},
	&LdPreload{},
	&CgroupNotifyOnReleaseModification{},
	&DefaultLoaderModification{},
	&SudoersModification{},
	&SchedDebugRecon{},
	&SystemRequestKeyConfigModification{},
	&CgroupReleaseAgentModification{},
	&RcdModification{},
	&CorePatternModification{},
	&ProcKcoreRead{},
	&ProcMemAccess{},
	&HiddenFileCreated{},
	&AntiDebuggingPtraceme{},
	&PtraceCodeInjection{},
	&ProcessVmWriteCodeInjection{},
	&DiskMount{},
	&DynamicCodeLoading{},
	&FilelessExecution{},
	&IllegitimateShell{},
	&KernelModuleLoading{},
	&KubernetesCertificateTheftAttempt{},
	&ProcFopsHooking{},
	&SyscallTableHooking{},
	&DroppedExecutable{},
}

// ExportedDataSources provides the list of data sources that were previously
// exported as a plugin, now compiled directly into the binary
var ExportedDataSources = []detect.DataSource{
	// add data-sources here
}
