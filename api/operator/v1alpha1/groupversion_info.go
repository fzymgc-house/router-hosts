// Package v1alpha1 contains API Schema definitions for the router-hosts v1alpha1 API group.
//
// +kubebuilder:object:generate=true
// +groupName=router-hosts.fzymgc.house
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the API group and version for this package.
	GroupVersion = schema.GroupVersion{Group: "router-hosts.fzymgc.house", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionResource scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
