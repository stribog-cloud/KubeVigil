package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestIsEmptyPodSelector tests the isEmptyPodSelector helper function
// covering all branches: nil/missing selector, empty matchLabels, non-empty matchLabels.
func TestIsEmptyPodSelector(t *testing.T) {
	testCases := []struct {
		name string
		pol  unstructured.Unstructured
		want bool
	}{
		{
			name: "missing podSelector treated as empty (selects all)",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{},
			}},
			want: true,
		},
		{
			name: "empty podSelector map selects all",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{},
				},
			}},
			want: true,
		},
		{
			name: "podSelector with matchLabels is not empty",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							"app": "web",
						},
					},
				},
			}},
			want: false,
		},
		{
			name: "nil object spec returns true (missing selector)",
			pol: unstructured.Unstructured{Object: map[string]interface{}{}},
			want: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isEmptyPodSelector(&tc.pol)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestHasOverlyPermissiveEgress tests hasOverlyPermissiveEgress helper
// covering branches: no egress field, empty egress list, non-map rule entries,
// egress with empty "to" list, egress with 0.0.0.0/0 CIDR, egress with except.
func TestHasOverlyPermissiveEgress(t *testing.T) {
	testCases := []struct {
		name string
		pol  unstructured.Unstructured
		want bool
	}{
		{
			name: "no egress field returns false",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{},
			}},
			want: false,
		},
		{
			name: "empty egress slice returns false",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{},
				},
			}},
			want: false,
		},
		{
			name: "egress rule with no to key returns true (allows all)",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{},
					},
				},
			}},
			want: true,
		},
		{
			name: "egress rule with empty to slice returns true",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{},
						},
					},
				},
			}},
			want: true,
		},
		{
			name: "egress rule with 0.0.0.0/0 no except returns true",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr": "0.0.0.0/0",
									},
								},
							},
						},
					},
				},
			}},
			want: true,
		},
		{
			name: "egress rule with 0.0.0.0/0 and empty except returns true",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr":   "0.0.0.0/0",
										"except": []interface{}{},
									},
								},
							},
						},
					},
				},
			}},
			want: true,
		},
		{
			name: "egress rule with 0.0.0.0/0 and non-empty except returns false",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"ipBlock": map[string]interface{}{
										"cidr":   "0.0.0.0/0",
										"except": []interface{}{"10.0.0.0/8"},
									},
								},
							},
						},
					},
				},
			}},
			want: false,
		},
		{
			name: "egress rule with specific podSelector returns false",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{
						map[string]interface{}{
							"to": []interface{}{
								map[string]interface{}{
									"podSelector": map[string]interface{}{
										"matchLabels": map[string]interface{}{"app": "db"},
									},
								},
							},
						},
					},
				},
			}},
			want: false,
		},
		{
			name: "non-map rule entry is skipped",
			pol: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"egress": []interface{}{
						"not-a-map",
					},
				},
			}},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasOverlyPermissiveEgress(&tc.pol)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestIsRuleOverlyPermissive tests the isRuleOverlyPermissive helper
// covering: no direction key, non-slice peers, empty peer slice, non-map peer entries,
// ipBlock with non-0.0.0.0/0, 0.0.0.0/0 without except, with empty except, with non-empty except.
func TestIsRuleOverlyPermissive(t *testing.T) {
	testCases := []struct {
		name         string
		ruleMap      map[string]interface{}
		directionKey string
		want         bool
	}{
		{
			name:         "no direction key present returns true",
			ruleMap:      map[string]interface{}{},
			directionKey: "from",
			want:         true,
		},
		{
			name:         "direction key with non-slice value returns false",
			ruleMap:      map[string]interface{}{"from": "not-a-slice"},
			directionKey: "from",
			want:         false,
		},
		{
			name:         "direction key with empty slice returns true",
			ruleMap:      map[string]interface{}{"from": []interface{}{}},
			directionKey: "from",
			want:         true,
		},
		{
			name: "peer entry that is not a map is skipped",
			ruleMap: map[string]interface{}{
				"from": []interface{}{"not-a-map"},
			},
			directionKey: "from",
			want:         false,
		},
		{
			name: "peer with non-map ipBlock is skipped",
			ruleMap: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"ipBlock": "not-a-map",
					},
				},
			},
			directionKey: "from",
			want:         false,
		},
		{
			name: "ipBlock with non-0.0.0.0/0 CIDR returns false",
			ruleMap: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"ipBlock": map[string]interface{}{
							"cidr": "10.0.0.0/8",
						},
					},
				},
			},
			directionKey: "from",
			want:         false,
		},
		{
			name: "0.0.0.0/0 without except returns true",
			ruleMap: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"ipBlock": map[string]interface{}{
							"cidr": "0.0.0.0/0",
						},
					},
				},
			},
			directionKey: "from",
			want:         true,
		},
		{
			name: "0.0.0.0/0 with empty except returns true",
			ruleMap: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"ipBlock": map[string]interface{}{
							"cidr":   "0.0.0.0/0",
							"except": []interface{}{},
						},
					},
				},
			},
			directionKey: "from",
			want:         true,
		},
		{
			name: "0.0.0.0/0 with non-empty except returns false",
			ruleMap: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"ipBlock": map[string]interface{}{
							"cidr":   "0.0.0.0/0",
							"except": []interface{}{"10.0.0.0/8"},
						},
					},
				},
			},
			directionKey: "from",
			want:         false,
		},
		{
			name: "0.0.0.0/0 with non-slice except returns false",
			ruleMap: map[string]interface{}{
				"from": []interface{}{
					map[string]interface{}{
						"ipBlock": map[string]interface{}{
							"cidr":   "0.0.0.0/0",
							"except": "not-a-slice",
						},
					},
				},
			},
			directionKey: "from",
			want:         false,
		},
		{
			name: "to direction key works the same way",
			ruleMap: map[string]interface{}{
				"to": []interface{}{
					map[string]interface{}{
						"ipBlock": map[string]interface{}{
							"cidr": "0.0.0.0/0",
						},
					},
				},
			},
			directionKey: "to",
			want:         true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isRuleOverlyPermissive(tc.ruleMap, tc.directionKey)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestServiceType tests the serviceType helper function
// covering: missing spec, missing type field, empty type string, valid types.
func TestServiceType(t *testing.T) {
	testCases := []struct {
		name string
		svc  unstructured.Unstructured
		want string
	}{
		{
			name: "LoadBalancer type returns LoadBalancer",
			svc: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"type": "LoadBalancer",
				},
			}},
			want: "LoadBalancer",
		},
		{
			name: "ClusterIP type returns ClusterIP",
			svc: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"type": "ClusterIP",
				},
			}},
			want: "ClusterIP",
		},
		{
			name: "NodePort type returns NodePort",
			svc: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"type": "NodePort",
				},
			}},
			want: "NodePort",
		},
		{
			name: "missing spec defaults to ClusterIP",
			svc: unstructured.Unstructured{Object: map[string]interface{}{}},
			want: "ClusterIP",
		},
		{
			name: "missing type field defaults to ClusterIP",
			svc: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{},
			}},
			want: "ClusterIP",
		},
		{
			name: "empty type string defaults to ClusterIP",
			svc: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"type": "",
				},
			}},
			want: "ClusterIP",
		},
		{
			name: "type field is non-string returns ClusterIP",
			svc: unstructured.Unstructured{Object: map[string]interface{}{
				"spec": map[string]interface{}{
					"type": 42,
				},
			}},
			want: "ClusterIP",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceType(&tc.svc)
			assert.Equal(t, tc.want, got)
		})
	}
}
