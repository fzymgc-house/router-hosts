package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HostMappingSpec defines the desired state of a HostMapping.
type HostMappingSpec struct {
	// IP address (IPv4 or IPv6) for the host entry.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	IP string `json:"ip"`

	// Primary DNS hostname for the host entry.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Hostname string `json:"hostname"`

	// Optional hostname aliases (additional names resolving to the same IP).
	// +optional
	Aliases []string `json:"aliases,omitempty"`

	// Optional tags for categorization and filtering.
	// +optional
	Tags []string `json:"tags,omitempty"`
}

// HostMappingPhase represents the sync state of a HostMapping.
// +kubebuilder:validation:Enum=Pending;Synced;Error
type HostMappingPhase string

const (
	HostMappingPhasePending HostMappingPhase = "Pending"
	HostMappingPhaseSynced  HostMappingPhase = "Synced"
	HostMappingPhaseError   HostMappingPhase = "Error"
)

// HostMappingStatus defines the observed state of a HostMapping.
type HostMappingStatus struct {
	// Phase indicates the current sync state (Pending, Synced, Error).
	// +optional
	Phase HostMappingPhase `json:"phase,omitempty"`

	// Human-readable message with details about the current phase.
	// +optional
	Message string `json:"message,omitempty"`

	// Timestamp of the last successful sync to the router-hosts server.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// The router-hosts server-assigned ID for this host entry.
	// +optional
	HostID string `json:"hostId,omitempty"`

	// Version string from the router-hosts server for optimistic concurrency.
	// +optional
	HostVersion string `json:"hostVersion,omitempty"`

	// Standard Kubernetes conditions.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Condition types for HostMapping.
const (
	// ConditionSynced indicates whether the host entry is in sync with
	// the router-hosts server.
	ConditionSynced = "Synced"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.spec.ip`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.spec.hostname`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`

// HostMapping is the Schema for the hostmappings API.
type HostMapping struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HostMappingSpec   `json:"spec,omitempty"`
	Status HostMappingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HostMappingList contains a list of HostMapping resources.
type HostMappingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HostMapping `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HostMapping{}, &HostMappingList{})
}
