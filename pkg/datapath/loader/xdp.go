// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/ebpf"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const XDPRoutingRoot = "xdp_routing_root"
const XDPRoutingEntryId = 1

func xdpConfigModeToFlag(xdpMode string) uint32 {
	switch xdpMode {
	case option.XDPModeNative:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	case option.XDPModeLinkDriver:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeLinkGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	}
	return 0
}

// These constant values are returned by the kernel when querying the XDP program attach mode.
// Important: they differ from constants that are used when attaching an XDP program to a netlink device.
const (
	XDPAttachedNone uint32 = iota
	XDPAttachedDriver
	XDPAttachedGeneric
)

// xdpAttachedModeToFlag maps the attach mode that is returned in the metadata when
// querying netlink devices to the attach flags that were used to configure the
// xdp program attachement.
func xdpAttachedModeToFlag(mode uint32) uint32 {
	switch mode {
	case XDPAttachedDriver:
		return nl.XDP_FLAGS_DRV_MODE
	case XDPAttachedGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	}
	return 0
}

// maybeUnloadObsoleteXDPPrograms removes bpf_xdp.o from previously used devices.
func maybeUnloadObsoleteXDPPrograms(xdpDevs []string, xdpMode string) {

	links, err := netlink.LinkList()
	if err != nil {
		log.WithError(err).Warn("Failed to list links for XDP unload")
	}

	for _, link := range links {
		linkxdp := link.Attrs().Xdp
		if linkxdp == nil || !linkxdp.Attached {
			// No XDP program is attached
			continue
		}
		if strings.Contains(link.Attrs().Name, "cilium") {
			// Ignore devices created by cilium-agent
			continue
		}

		used := false
		for _, xdpDev := range xdpDevs {
			if link.Attrs().Name == xdpDev &&
				xdpAttachedModeToFlag(linkxdp.AttachMode) == xdpConfigModeToFlag(xdpMode) {
				// XDP mode matches; don't unload, otherwise we might introduce
				// intermittent connectivity problems
				used = true
				break
			}
		}
		if !used {
			netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpConfigModeToFlag(option.XDPModeLinkGeneric)))
			netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpConfigModeToFlag(option.XDPModeLinkDriver)))

			// load from pinned map and remove the entry index
			hookMap, err := ebpf.LoadPinnedMap(fmt.Sprintf("%s/%s", bpf.MapPrefixPath(), XDPRoutingRoot), nil)
			if err != nil {
				log.WithError(err).Warn("can't load the pinned XDP root map")
				continue
			}
			if err := hookMap.Delete(uint32(XDPRoutingEntryId)); err != nil {
				log.WithError(err).Warn("hook map delete XDP entry err")
				continue
			}
		}
	}
}

// xdpCompileArgs derives compile arguments for bpf_xdp.c.
func xdpCompileArgs(xdpDev string, extraCArgs []string) ([]string, error) {
	link, err := netlink.LinkByName(xdpDev)
	if err != nil {
		return nil, err
	}

	args := []string{
		fmt.Sprintf("-DSECLABEL=%d", identity.ReservedIdentityWorld),
		fmt.Sprintf("-DNODE_MAC={.addr=%s}", mac.CArrayString(link.Attrs().HardwareAddr)),
		"-DCALLS_MAP=cilium_calls_xdp",
	}
	args = append(args, extraCArgs...)
	if option.Config.EnableNodePort {
		args = append(args, []string{
			fmt.Sprintf("-DTHIS_MTU=%d", link.Attrs().MTU),
			fmt.Sprintf("-DNATIVE_DEV_IFINDEX=%d", link.Attrs().Index),
			"-DDISABLE_LOOPBACK_LB",
		}...)
	}

	return args, nil
}

// compileAndLoadXDPProg compiles bpf_xdp.c for the given XDP device and loads it.
func compileAndLoadXDPProg(ctx context.Context, xdpDev, xdpMode string, extraCArgs []string) error {
	args, err := xdpCompileArgs(xdpDev, extraCArgs)
	if err != nil {
		return fmt.Errorf("failed to derive XDP compile extra args: %w", err)
	}

	dirs := &directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		Output:  option.Config.StateDir,
		State:   option.Config.StateDir,
	}
	prog := &progInfo{
		Source:     xdpProg,
		Output:     xdpObj,
		OutputType: outputObject,
		Options:    args,
	}

	if err := compile(ctx, prog, dirs); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	objPath := path.Join(dirs.Output, prog.Output)
	progs := []progDefinition{
		{progName: symbolFromHostNetdevRootXDP, direction: "", xdpLoad: &xdpLoadDetail{xdpAttach: true}},
		{progName: symbolFromHostNetdevXDP, direction: "", xdpLoad: &xdpLoadDetail{
			xdpMapPath: fmt.Sprintf("%s/%s", bpf.MapPrefixPath(), XDPRoutingRoot), xdpMapIndex: XDPRoutingEntryId}},
	}
	finalize, err := replaceDatapath(ctx, xdpDev, objPath, progs, xdpMode)
	if err != nil {
		return err
	}
	finalize()

	return err
}
