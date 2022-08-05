// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package metadata

import (
	"fmt"
	"os"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/checker"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ManagerSuite struct {
	mm *Manager
}

var _ = Suite(&ManagerSuite{})

type cgroupMock struct {
	cgroupIds map[string]uint64
}

type fsMock map[string]struct{}

func (cg cgroupMock) GetCgroupID(cgroupPath string) (uint64, error) {
	if o, ok := cg.cgroupIds[cgroupPath]; ok {
		return o, nil
	}
	return 0, fmt.Errorf("")
}

func (fs fsMock) Stat(file string) (info os.FileInfo, err error) {
	if _, ok := fs[file]; ok {
		return nil, nil
	}

	return nil, fmt.Errorf("")
}

var (
	pod1IP         = slimcorev1.PodIP{IP: "1.2.3.4"}
	pod2IP         = slimcorev1.PodIP{IP: "5.6.7.8"}
	pod3IP         = slimcorev1.PodIP{IP: "7.8.7.8"}
	c1Id           = "d8f227cc24940cfdce8d8e601f3b92242ac9661b0e83f0ea57fdea1cb6bc93ec"
	c3Id           = "e8f227cc24940cfdce8d8e601f3b92242ac9661b0e83f0ea57fdea1cb6bc93ed"
	pod1C1CgrpPath = cgroups.GetCgroupRoot() + "/kubepods/burstable/pod1858680e-b044-4fd5-9dd4-f137e30e2180/" + c1Id
	pod2C1CgrpPath = cgroups.GetCgroupRoot() + "/kubepods/pod1858680e-b044-4fd5-9dd4-f137e30e2181/e8f227cc24940cfdce8d8e601f3b92242ac9661b0e83f0ea57fdea1cb6bc93ed"
	pod3C1CgrpPath = cgroups.GetCgroupRoot() + "/kubelet" + "/kubepods/burstable/pod2858680e-b044-4fd5-9dd4-f137e30e2180/" + c3Id
	pod3C2CgrpPath = cgroups.GetCgroupRoot() + "/kubelet" + "/kubepods/burstable/pod2858680e-b044-4fd5-9dd4-f137e30e2180/" + c1Id
	pod1Ips        = []slimcorev1.PodIP{pod1IP}
	pod2Ips        = []slimcorev1.PodIP{pod2IP}
	pod3Ips        = []slimcorev1.PodIP{pod3IP}
	pod1           = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-p1",
			Namespace: "ns1",
			UID:       "1858680e-b044-4fd5-9dd4-f137e30e2180",
		},
		Spec: slimcorev1.PodSpec{
			NodeName: "n1",
		},
		Status: slimcorev1.PodStatus{
			PodIP:  pod1IP.IP,
			PodIPs: pod1Ips,
			ContainerStatuses: []slimcorev1.ContainerStatus{
				{
					ContainerID: "foo://" + c1Id,
					State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
				},
			},
			QOSClass: slimcorev1.PodQOSBurstable,
		},
	}
	pod2 = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-p2",
			Namespace: "ns1",
			UID:       "1858680e-b044-4fd5-9dd4-f137e30e2181",
		},
		Spec: slimcorev1.PodSpec{
			NodeName: "n1",
		},
		Status: slimcorev1.PodStatus{
			PodIP:  pod2IP.IP,
			PodIPs: []slimcorev1.PodIP{pod2IP},
			ContainerStatuses: []slimcorev1.ContainerStatus{
				{
					ContainerID: "foo://" + c3Id,
					State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
				},
			},
			QOSClass: slimcorev1.PodQOSGuaranteed,
		},
	}
	pod3 = &slimcorev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "foo-p3",
			Namespace: "ns1",
			UID:       "2858680e-b044-4fd5-9dd4-f137e30e2180",
		},
		Spec: slimcorev1.PodSpec{
			NodeName: "n1",
		},
		Status: slimcorev1.PodStatus{
			PodIP:  pod3IP.IP,
			PodIPs: []slimcorev1.PodIP{pod3IP},
			ContainerStatuses: []slimcorev1.ContainerStatus{
				{
					ContainerID: "foo://" + c3Id,
					State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
				},
			},
			QOSClass: slimcorev1.PodQOSBurstable,
		},
	}
)

func (m *ManagerSuite) SetUpTest(c *C) {
	option.Config.Opts.SetBool(option.TraceSockNotify, true)
	m.mm = newManagerTest(fsMock{}, cgroupMock{})
	nodetypes.SetName("n1")
}

func (m *ManagerSuite) TestGetParentPodMetadataOnPodAdd(c *C) {
	c1CId := uint64(1234)
	c2CId := uint64(4567)
	c3CId := uint64(2345)
	cgMock := cgroupMock{cgroupIds: map[string]uint64{
		pod1C1CgrpPath: c1CId,
		pod2C1CgrpPath: c2CId,
	}}
	// Fs with regular cgroup base path.
	fsMock := fsMock{
		defaultCgroupBasePath: struct{}{},
	}
	pod10 := pod1.DeepCopy()
	mm := newManagerTest(fsMock, cgMock)

	type test struct {
		input  *slimcorev1.Pod
		cgrpId uint64
		want   *PodMetadata
	}

	// Add pods, and check for parent pod metadata for their containers.
	tests := []test{
		// Pod with Qos burstable.
		{input: pod1, cgrpId: c1CId, want: &PodMetadata{name: pod1.Name, namespace: pod1.Namespace, ips: pod1Ips}},
		// {input: pod3, cgrpId: c3CId, fs: f2, want: &PodMetadata{name: pod3.Name, namespace: pod3.Namespace, ips: pod3Ips}},
		// Pod with Qos guaranteed.
		{input: pod2, cgrpId: c2CId, want: &PodMetadata{name: pod2.Name, namespace: pod2.Namespace, ips: pod2Ips}},
		// Pod's container cgroup path doesn't exist.
		{input: pod10, cgrpId: c3CId, want: nil},
	}

	for _, tc := range tests {
		mm.OnAddPod(tc.input)

		got := mm.GetParentPodMetadata(tc.cgrpId)
		c.Assert(got, checker.Equals, tc.want)
	}
}
func (m *ManagerSuite) TestGetParentPodMetadataOnPodUpdate(c *C) {
	c3CId := uint64(2345)
	c1CId := uint64(1234)
	cgMock := cgroupMock{cgroupIds: map[string]uint64{
		pod3C1CgrpPath: c3CId,
		pod3C2CgrpPath: c1CId,
	}}
	// Fs with nested cgroup base paths.
	fsMock := fsMock{
		defaultNestedCgroupBasePath: struct{}{},
	}
	mm := newManagerTest(fsMock, cgMock)
	newPod := pod3.DeepCopy()
	cs := slimcorev1.ContainerStatus{
		State:       slimcorev1.ContainerState{Running: &slimcorev1.ContainerStateRunning{}},
		ContainerID: "foo://" + c1Id,
	}
	newPod.Status.ContainerStatuses = append(newPod.Status.ContainerStatuses, cs)

	// No pod added yet, so no parent pod metadata.
	got := mm.GetParentPodMetadata(c3CId)
	c.Assert(got, checker.Equals, (*PodMetadata)(nil))

	// Add pod, and check for parent pod metadata for their containers.
	mm.OnAddPod(pod3)

	got = mm.GetParentPodMetadata(c3CId)
	c.Assert(got, checker.Equals, &PodMetadata{name: pod3.Name, namespace: pod3.Namespace, ips: pod3Ips})

	// Update pod, and check for parent pod metadata for their containers.
	mm.OnUpdatePod(pod1, newPod)

	got1 := mm.GetParentPodMetadata(c3CId)
	got2 := mm.GetParentPodMetadata(c1CId)
	c.Assert(got1, checker.Equals, &PodMetadata{name: pod3.Name, namespace: pod3.Namespace, ips: pod3Ips})
	c.Assert(got2, checker.Equals, &PodMetadata{name: pod3.Name, namespace: pod3.Namespace, ips: pod3Ips})
}
