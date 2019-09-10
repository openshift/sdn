// +build windows

package hcsoci

// Contains functions relating to a WCOW container, as opposed to a utility VM

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/internal/guestrequest"
	"github.com/Microsoft/hcsshim/internal/log"
	hcsschema "github.com/Microsoft/hcsshim/internal/schema2"
	"github.com/Microsoft/hcsshim/internal/schemaversion"
	"github.com/Microsoft/hcsshim/internal/wclayer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func allocateWindowsResources(ctx context.Context, coi *createOptionsInternal, resources *Resources) error {
	if coi.Spec == nil || coi.Spec.Windows == nil || coi.Spec.Windows.LayerFolders == nil {
		return fmt.Errorf("field 'Spec.Windows.Layerfolders' is not populated")
	}

	scratchFolder := coi.Spec.Windows.LayerFolders[len(coi.Spec.Windows.LayerFolders)-1]
	log.G(ctx).WithField("scratchFolder", scratchFolder).Debug("hcsshim::allocateWindowsResources scratch folder")

	// TODO: Remove this code for auto-creation. Make the caller responsible.
	// Create the directory for the RW scratch layer if it doesn't exist
	if _, err := os.Stat(scratchFolder); os.IsNotExist(err) {
		log.G(ctx).WithField("scratchFolder", scratchFolder).Debug("hcsshim::allocateWindowsResources container scratch folder does not exist so creating")
		if err := os.MkdirAll(scratchFolder, 0777); err != nil {
			return fmt.Errorf("failed to auto-create container scratch folder %s: %s", scratchFolder, err)
		}
	}

	// Create sandbox.vhdx if it doesn't exist in the scratch folder. It's called sandbox.vhdx
	// rather than scratch.vhdx as in the v1 schema, it's hard-coded in HCS.
	if _, err := os.Stat(filepath.Join(scratchFolder, "sandbox.vhdx")); os.IsNotExist(err) {
		log.G(ctx).WithField("scratchFolder", scratchFolder).Debug("hcsshim::allocateWindowsResources container sandbox.vhdx does not exist so creating")
		if err := wclayer.CreateScratchLayer(scratchFolder, coi.Spec.Windows.LayerFolders[:len(coi.Spec.Windows.LayerFolders)-1]); err != nil {
			return fmt.Errorf("failed to CreateSandboxLayer %s", err)
		}
	}

	if coi.Spec.Root == nil {
		coi.Spec.Root = &specs.Root{}
	}

	if coi.Spec.Root.Path == "" && (coi.HostingSystem != nil || coi.Spec.Windows.HyperV == nil) {
		log.G(ctx).Debug("hcsshim::allocateWindowsResources mounting storage")
		mcl, err := MountContainerLayers(ctx, coi.Spec.Windows.LayerFolders, resources.containerRootInUVM, coi.HostingSystem)
		if err != nil {
			return fmt.Errorf("failed to mount container storage: %s", err)
		}
		if coi.HostingSystem == nil {
			coi.Spec.Root.Path = mcl.(string) // Argon v1 or v2
		} else {
			coi.Spec.Root.Path = mcl.(guestrequest.CombinedLayers).ContainerRootPath // v2 Xenon WCOW
		}
		resources.layers = coi.Spec.Windows.LayerFolders
	}

	// Validate each of the mounts. If this is a V2 Xenon, we have to add them as
	// VSMB shares to the utility VM. For V1 Xenon and Argons, there's nothing for
	// us to do as it's done by HCS.
	for i, mount := range coi.Spec.Mounts {
		if mount.Destination == "" || mount.Source == "" {
			return fmt.Errorf("invalid OCI spec - a mount must have both source and a destination: %+v", mount)
		}
		switch mount.Type {
		case "":
		case "physical-disk":
		case "virtual-disk":
		case "automanage-virtual-disk":
		default:
			return fmt.Errorf("invalid OCI spec - Type '%s' not supported", mount.Type)
		}

		if coi.HostingSystem != nil && schemaversion.IsV21(coi.actualSchemaVersion) {
			uvmPath := fmt.Sprintf("C:\\%s\\%d", coi.actualID, i)

			readOnly := false
			for _, o := range mount.Options {
				if strings.ToLower(o) == "ro" {
					readOnly = true
					break
				}
			}
			l := log.G(ctx).WithField("mount", fmt.Sprintf("%+v", mount))
			if mount.Type == "physical-disk" {
				l.Debug("hcsshim::allocateWindowsResources Hot-adding SCSI physical disk for OCI mount")
				_, _, err := coi.HostingSystem.AddSCSIPhysicalDisk(ctx, mount.Source, uvmPath, readOnly)
				if err != nil {
					return fmt.Errorf("adding SCSI physical disk mount %+v: %s", mount, err)
				}
				coi.Spec.Mounts[i].Type = ""
				resources.scsiMounts = append(resources.scsiMounts, scsiMount{path: mount.Source})
			} else if mount.Type == "virtual-disk" || mount.Type == "automanage-virtual-disk" {
				l.Debug("hcsshim::allocateWindowsResources Hot-adding SCSI virtual disk for OCI mount")
				_, _, err := coi.HostingSystem.AddSCSI(ctx, mount.Source, uvmPath, readOnly)
				if err != nil {
					return fmt.Errorf("adding SCSI virtual disk mount %+v: %s", mount, err)
				}
				coi.Spec.Mounts[i].Type = ""
				resources.scsiMounts = append(resources.scsiMounts, scsiMount{path: mount.Source, autoManage: mount.Type == "automanage-virtual-disk"})
			} else {
				l.Debug("hcsshim::allocateWindowsResources Hot-adding VSMB share for OCI mount")
				options := &hcsschema.VirtualSmbShareOptions{}
				if readOnly {
					options.ReadOnly = true
					options.CacheIo = true
					options.ShareRead = true
					options.ForceLevelIIOplocks = true
					break
				}

				err := coi.HostingSystem.AddVSMB(ctx, mount.Source, "", options)
				if err != nil {
					return fmt.Errorf("failed to add VSMB share to utility VM for mount %+v: %s", mount, err)
				}
				resources.vsmbMounts = append(resources.vsmbMounts, mount.Source)
			}
		}
	}

	return nil
}
