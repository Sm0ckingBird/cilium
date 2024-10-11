// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2019 Authors of Cilium

package ipcache

import (
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-ipcache")

// datapath is an interface to the datapath implementation, used to apply
// changes that are made within this module.
type datapath interface {
	TriggerReloadWithoutCompile(reason string) (*sync.WaitGroup, error)
}

// monitor is an interface not notify the monitor about changes to the ipcache
type monitorNotify interface {
	SendNotification(msg monitorAPI.AgentNotifyMessage) error
}

// BPFListener implements the ipcache.IPIdentityMappingBPFListener
// interface with an IPCache store that is backed by BPF maps.
//
// One listener is shared between callers of OnIPIdentityCacheChange() and the
// controller launched from OnIPIdentityCacheGC(). However, The listener is not
// updated after initialization so no locking is provided for access.
type BPFListener struct {
	// bpfMap is the BPF map that this listener will update when events are
	// received from the IPCache.
	bpfMap *ipcacheMap.Map

	// datapath allows this listener to trigger BPF program regeneration.
	datapath datapath

	// monitorNotify is used to notify the monitor about ipcache updates
	monitorNotify monitorNotify
}

func newListener(m *ipcacheMap.Map, d datapath, mn monitorNotify) *BPFListener {
	return &BPFListener{
		bpfMap:        m,
		datapath:      d,
		monitorNotify: mn,
	}
}

// NewListener returns a new listener to push IPCache entries into BPF maps.
func NewListener(d datapath, mn monitorNotify) *BPFListener {
	return newListener(ipcacheMap.IPCache, d, mn)
}

func (l *BPFListener) notifyMonitor(modType ipcache.CacheModification,
	cidr net.IPNet, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity,
	newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	var (
		k8sNamespace, k8sPodName string
		newIdentity, oldIdentity uint32
		oldIdentityPtr           *uint32
	)

	if l.monitorNotify == nil {
		return
	}

	if k8sMeta != nil {
		k8sNamespace = k8sMeta.Namespace
		k8sPodName = k8sMeta.PodName
	}

	newIdentity = newID.ID.Uint32()
	if oldID != nil {
		oldIdentity = oldID.ID.Uint32()
		oldIdentityPtr = &oldIdentity
	}

	switch modType {
	case ipcache.Upsert:
		msg := monitorAPI.IPCacheUpsertedMessage(cidr.String(), newIdentity, oldIdentityPtr,
			newHostIP, oldHostIP, encryptKey, k8sNamespace, k8sPodName)
		l.monitorNotify.SendNotification(msg)
	case ipcache.Delete:
		msg := monitorAPI.IPCacheDeletedMessage(cidr.String(), newIdentity, oldIdentityPtr,
			newHostIP, oldHostIP, encryptKey, k8sNamespace, k8sPodName)
		l.monitorNotify.SendNotification(msg)
	}
}

// OnIPIdentityCacheChange is called whenever there is a change of state in the
// IPCache (pkg/ipcache).
// TODO (FIXME): GH-3161.
//
// 'oldIPIDPair' is ignored here, because in the BPF maps an update for the
// IP->ID mapping will replace any existing contents; knowledge of the old pair
// is not required to upsert the new pair.
func (l *BPFListener) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr net.IPNet,
	oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity,
	encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {

	scopedLog := log
	if option.Config.Debug {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.IPAddr:       cidr,
			logfields.Identity:     newID,
			logfields.Modification: modType,
		})
	}

	scopedLog.Debug("Daemon notified of IP-Identity cache state change")

	l.notifyMonitor(modType, cidr, oldHostIP, newHostIP, oldID, newID, encryptKey, k8sMeta)

	// TODO - see if we can factor this into an interface under something like
	// pkg/datapath instead of in the daemon directly so that the code is more
	// logically located.

	// Update BPF Maps.

	key := ipcacheMap.NewKey(cidr.IP, cidr.Mask)

	switch modType {
	case ipcache.Upsert:
		value := ipcacheMap.RemoteEndpointInfo{
			SecurityIdentity: uint32(newID.ID),
			Key:              encryptKey,
		}

		if newHostIP != nil {
			// If the hostIP is specified and it doesn't point to
			// the local host, then the ipcache should be populated
			// with the hostIP so that this traffic can be guided
			// to a tunnel endpoint destination.
			nodeIPv4 := node.GetIPv4()
			if ip4 := newHostIP.To4(); ip4 != nil && !ip4.Equal(nodeIPv4) {
				copy(value.TunnelEndpoint[:], ip4)
			}
		}
		err := l.bpfMap.Update(&key, &value)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"key":                  key.String(),
				"value":                value.String(),
				logfields.IPAddr:       cidr,
				logfields.Identity:     newID,
				logfields.Modification: modType,
			}).Warning("unable to update bpf map")
		}
	case ipcache.Delete:
		err := l.bpfMap.DeleteWithOverwrite(&key)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"key":                  key.String(),
				logfields.IPAddr:       cidr,
				logfields.Identity:     newID,
				logfields.Modification: modType,
			}).Warning("unable to delete from bpf map")
		}
	default:
		scopedLog.Warning("cache modification type not supported")
	}
}

func (l *BPFListener) OnIPIdentityCacheGC() {}
