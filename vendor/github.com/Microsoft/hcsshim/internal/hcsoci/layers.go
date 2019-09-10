// +build windows

package hcsoci

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/Microsoft/hcsshim/internal/guestrequest"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/ospath"
	"github.com/Microsoft/hcsshim/internal/requesttype"
	hcsschema "github.com/Microsoft/hcsshim/internal/schema2"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/internal/wclayer"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type lcowLayerEntry struct {
	hostPath string
	uvmPath  string
	scsi     bool
}

const scratchPath = "scratch"

// mountContainerLayers is a helper for clients to hide all the complexity of layer mounting
// Layer folder are in order: base, [rolayer1..rolayern,] scratch
//
// v1/v2: Argon WCOW: Returns the mount path on the host as a volume GUID.
// v1:    Xenon WCOW: Done internally in HCS, so no point calling doing anything here.
// v2:    Xenon WCOW: Returns a CombinedLayersV2 structure where ContainerRootPath is a folder
//                    inside the utility VM which is a GUID mapping of the scratch folder. Each
//                    of the layers are the VSMB locations where the read-only layers are mounted.
//
func MountContainerLayers(ctx context.Context, layerFolders []string, guestRoot string, uvm *uvm.UtilityVM) (interface{}, error) {
	log.G(ctx).WithField("layerFolders", layerFolders).Debug("hcsshim::mountContainerLayers")

	if uvm == nil {
		if len(layerFolders) < 2 {
			return nil, fmt.Errorf("need at least two layers - base and scratch")
		}
		path := layerFolders[len(layerFolders)-1]
		rest := layerFolders[:len(layerFolders)-1]
		log.G(ctx).WithField("path", path).Debug("hcsshim::mountContainerLayers ActivateLayer")
		if err := wclayer.ActivateLayer(path); err != nil {
			return nil, err
		}
		log.G(ctx).WithFields(logrus.Fields{
			"path": path,
			"rest": rest,
		}).Debug("hcsshim::mountContainerLayers PrepareLayer")
		if err := wclayer.PrepareLayer(path, rest); err != nil {
			if err2 := wclayer.DeactivateLayer(path); err2 != nil {
				log.G(ctx).WithFields(logrus.Fields{
					logrus.ErrorKey: err,
					"path":          path,
				}).Warn("Failed to Deactivate")
			}
			return nil, err
		}

		mountPath, err := wclayer.GetLayerMountPath(path)
		if err != nil {
			if err := wclayer.UnprepareLayer(path); err != nil {
				log.G(ctx).WithFields(logrus.Fields{
					logrus.ErrorKey: err,
					"path":          path,
				}).Warn("Failed to Unprepare")
			}
			if err2 := wclayer.DeactivateLayer(path); err2 != nil {
				log.G(ctx).WithFields(logrus.Fields{
					logrus.ErrorKey: err,
					"path":          path,
				}).Warn("Failed to Deactivate")
			}
			return nil, err
		}
		return mountPath, nil
	}

	// V2 UVM
	log.G(ctx).WithField("os", uvm.OS()).Debug("hcsshim::mountContainerLayers V2 UVM")

	// 	Add each read-only layers. For Windows, this is a VSMB share with the ResourceUri ending in
	// a GUID based on the folder path. For Linux, this is a VPMEM device, except where is over the
	// max size supported, where we put it on SCSI instead.
	//
	//  Each layer is ref-counted so that multiple containers in the same utility VM can share them.
	var wcowLayersAdded []string
	var lcowlayersAdded []lcowLayerEntry
	attachedSCSIHostPath := ""

	for _, layerPath := range layerFolders[:len(layerFolders)-1] {
		var err error
		if uvm.OS() == "windows" {
			options := &hcsschema.VirtualSmbShareOptions{
				ReadOnly:            true,
				PseudoOplocks:       true,
				TakeBackupPrivilege: true,
				CacheIo:             true,
				ShareRead:           true,
			}
			err = uvm.AddVSMB(ctx, layerPath, "", options)
			if err == nil {
				wcowLayersAdded = append(wcowLayersAdded, layerPath)
			}
		} else {
			uvmPath := ""
			hostPath := filepath.Join(layerPath, "layer.vhd")

			var fi os.FileInfo
			fi, err = os.Stat(hostPath)

			if err == nil && uvm.ExceededVPMem(fi.Size()) {
				// Too big for PMEM. Add on SCSI instead (at /tmp/S<C>/<L>).
				var (
					controller int
					lun        int32
				)
				controller, lun, err = uvm.AddSCSILayer(ctx, hostPath)
				if err == nil {
					lcowlayersAdded = append(lcowlayersAdded,
						lcowLayerEntry{
							hostPath: hostPath,
							uvmPath:  fmt.Sprintf("/tmp/S%d/%d", controller, lun),
							scsi:     true,
						})
				}
			} else {
				_, uvmPath, err = uvm.AddVPMEM(ctx, hostPath, true) // UVM path is calculated. Will be /tmp/vN/
				if err == nil {
					lcowlayersAdded = append(lcowlayersAdded,
						lcowLayerEntry{
							hostPath: hostPath,
							uvmPath:  uvmPath,
						})
				}
			}
		}
		if err != nil {
			cleanupOnMountFailure(ctx, uvm, wcowLayersAdded, lcowlayersAdded, attachedSCSIHostPath)
			return nil, err
		}
	}

	// Add the scratch at an unused SCSI location. The container path inside the
	// utility VM will be C:\<ID>.
	hostPath := filepath.Join(layerFolders[len(layerFolders)-1], "sandbox.vhdx")

	// BUGBUG Rename guestRoot better.
	containerScratchPathInUVM := ospath.Join(uvm.OS(), guestRoot, scratchPath)
	_, _, err := uvm.AddSCSI(ctx, hostPath, containerScratchPathInUVM, false)
	if err != nil {
		cleanupOnMountFailure(ctx, uvm, wcowLayersAdded, lcowlayersAdded, attachedSCSIHostPath)
		return nil, err
	}
	attachedSCSIHostPath = hostPath

	if uvm.OS() == "windows" {
		// 	Load the filter at the C:\s<ID> location calculated above. We pass into this request each of the
		// 	read-only layer folders.
		layers, err := computeV2Layers(ctx, uvm, wcowLayersAdded)
		if err != nil {
			cleanupOnMountFailure(ctx, uvm, wcowLayersAdded, lcowlayersAdded, attachedSCSIHostPath)
			return nil, err
		}
		guestRequest := guestrequest.CombinedLayers{
			ContainerRootPath: containerScratchPathInUVM,
			Layers:            layers,
		}
		combinedLayersModification := &hcsschema.ModifySettingRequest{
			GuestRequest: guestrequest.GuestRequest{
				Settings:     guestRequest,
				ResourceType: guestrequest.ResourceTypeCombinedLayers,
				RequestType:  requesttype.Add,
			},
		}
		if err := uvm.Modify(ctx, combinedLayersModification); err != nil {
			cleanupOnMountFailure(ctx, uvm, wcowLayersAdded, lcowlayersAdded, attachedSCSIHostPath)
			return nil, err
		}
		log.G(ctx).Debug("hcsshim::mountContainerLayers Succeeded")
		return guestRequest, nil
	}

	// This is the LCOW layout inside the utilityVM. NNN is the container "number"
	// which increments for each container created in a utility VM.
	//
	// /run/gcs/c/NNN/config.json
	// /run/gcs/c/NNN/rootfs
	// /run/gcs/c/NNN/scratch/upper
	// /run/gcs/c/NNN/scratch/work
	//
	// /dev/sda on /tmp/scratch type ext4 (rw,relatime,block_validity,delalloc,barrier,user_xattr,acl)
	// /dev/pmem0 on /tmp/v0 type ext4 (ro,relatime,block_validity,delalloc,norecovery,barrier,dax,user_xattr,acl)
	// /dev/sdb on /run/gcs/c/NNN/scratch type ext4 (rw,relatime,block_validity,delalloc,barrier,user_xattr,acl)
	// overlay on /run/gcs/c/NNN/rootfs type overlay (rw,relatime,lowerdir=/tmp/v0,upperdir=/run/gcs/c/NNN/scratch/upper,workdir=/run/gcs/c/NNN/scratch/work)
	//
	// Where /dev/sda      is the scratch for utility VM itself
	//       /dev/pmemX    are read-only layers for containers
	//       /dev/sd(b...) are scratch spaces for each container

	layers := []hcsschema.Layer{}
	for _, l := range lcowlayersAdded {
		layers = append(layers, hcsschema.Layer{Path: l.uvmPath})
	}
	guestRequest := guestrequest.CombinedLayers{
		ContainerRootPath: path.Join(guestRoot, rootfsPath),
		Layers:            layers,
		ScratchPath:       containerScratchPathInUVM,
	}
	combinedLayersModification := &hcsschema.ModifySettingRequest{
		GuestRequest: guestrequest.GuestRequest{
			ResourceType: guestrequest.ResourceTypeCombinedLayers,
			RequestType:  requesttype.Add,
			Settings:     guestRequest,
		},
	}
	if err := uvm.Modify(ctx, combinedLayersModification); err != nil {
		cleanupOnMountFailure(ctx, uvm, wcowLayersAdded, lcowlayersAdded, attachedSCSIHostPath)
		return nil, err
	}
	log.G(ctx).Debug("hcsshim::mountContainerLayers Succeeded")
	return guestRequest, nil

}

// UnmountOperation is used when calling Unmount() to determine what type of unmount is
// required. In V1 schema, this must be unmountOperationAll. In V2, client can
// be more optimal and only unmount what they need which can be a minor performance
// improvement (eg if you know only one container is running in a utility VM, and
// the UVM is about to be torn down, there's no need to unmount the VSMB shares,
// just SCSI to have a consistent file system).
type UnmountOperation uint

const (
	UnmountOperationSCSI  UnmountOperation = 0x01
	UnmountOperationVSMB                   = 0x02
	UnmountOperationVPMEM                  = 0x04
	UnmountOperationAll                    = UnmountOperationSCSI | UnmountOperationVSMB | UnmountOperationVPMEM
)

// UnmountContainerLayers is a helper for clients to hide all the complexity of layer unmounting
func UnmountContainerLayers(ctx context.Context, layerFolders []string, guestRoot string, uvm *uvm.UtilityVM, op UnmountOperation) error {
	log.G(ctx).WithField("layerFolders", layerFolders).Debug("hcsshim::unmountContainerLayers")
	if uvm == nil {
		// Must be an argon - folders are mounted on the host
		if op != UnmountOperationAll {
			return fmt.Errorf("only operation supported for host-mounted folders is unmountOperationAll")
		}
		if len(layerFolders) < 1 {
			return fmt.Errorf("need at least one layer for Unmount")
		}
		path := layerFolders[len(layerFolders)-1]
		log.G(ctx).WithField("path", path).Debug("hcsshim::Unmount UnprepareLayer")
		if err := wclayer.UnprepareLayer(path); err != nil {
			return err
		}
		// TODO Should we try this anyway?
		log.G(ctx).WithField("path", path).Debug("hcsshim::unmountContainerLayers DeactivateLayer")
		return wclayer.DeactivateLayer(path)
	}

	// V2 Xenon

	// Base+Scratch as a minimum. This is different to v1 which only requires the scratch
	if len(layerFolders) < 2 {
		return fmt.Errorf("at least two layers are required for unmount")
	}

	var retError error

	// Unload the storage filter followed by the SCSI scratch
	if (op & UnmountOperationSCSI) == UnmountOperationSCSI {
		containerRoofFSPathInUVM := ospath.Join(uvm.OS(), guestRoot, rootfsPath)
		log.G(ctx).WithField("rootPath", containerRoofFSPathInUVM).Debug("hcsshim::unmountContainerLayers CombinedLayers")
		combinedLayersModification := &hcsschema.ModifySettingRequest{
			GuestRequest: guestrequest.GuestRequest{
				ResourceType: guestrequest.ResourceTypeCombinedLayers,
				RequestType:  requesttype.Remove,
				Settings:     guestrequest.CombinedLayers{ContainerRootPath: containerRoofFSPathInUVM},
			},
		}
		if err := uvm.Modify(ctx, combinedLayersModification); err != nil {
			log.G(ctx).WithError(err).Error("failed guest request to remove combined layers")
		}

		// Hot remove the scratch from the SCSI controller
		hostScratchFile := filepath.Join(layerFolders[len(layerFolders)-1], "sandbox.vhdx")
		containerScratchPathInUVM := ospath.Join(uvm.OS(), guestRoot, scratchPath)
		log.G(ctx).WithFields(logrus.Fields{
			"scratchPath": containerScratchPathInUVM,
			"scratchFile": hostScratchFile,
		}).Debug("hcsshim::unmountContainerLayers SCSI")
		if err := uvm.RemoveSCSI(ctx, hostScratchFile); err != nil {
			e := fmt.Errorf("failed to remove SCSI %s: %s", hostScratchFile, err)
			log.G(ctx).WithError(e).Error("failed to remove SCSI")
			if retError == nil {
				retError = e
			} else {
				retError = errors.Wrapf(retError, e.Error())
			}
		}
	}

	// Remove each of the read-only layers from VSMB. These's are ref-counted and
	// only removed once the count drops to zero. This allows multiple containers
	// to share layers.
	if uvm.OS() == "windows" && len(layerFolders) > 1 && (op&UnmountOperationVSMB) == UnmountOperationVSMB {
		for _, layerPath := range layerFolders[:len(layerFolders)-1] {
			if e := uvm.RemoveVSMB(ctx, layerPath); e != nil {
				log.G(ctx).WithError(e).Debug("remove VSMB failed")
				if retError == nil {
					retError = e
				} else {
					retError = errors.Wrapf(retError, e.Error())
				}
			}
		}
	}

	// Remove each of the read-only layers from VPMEM (or SCSI). These's are ref-counted
	// and only removed once the count drops to zero. This allows multiple containers to
	// share layers. Note that SCSI is used on large layers.
	if uvm.OS() == "linux" && len(layerFolders) > 1 && (op&UnmountOperationVPMEM) == UnmountOperationVPMEM {
		for _, layerPath := range layerFolders[:len(layerFolders)-1] {
			hostPath := filepath.Join(layerPath, "layer.vhd")
			if fi, err := os.Stat(hostPath); err != nil {
				var e error
				if uint64(fi.Size()) > uvm.PMemMaxSizeBytes() {
					e = uvm.RemoveSCSI(ctx, hostPath)
				} else {
					e = uvm.RemoveVPMEM(ctx, hostPath)
				}
				if e != nil {
					log.G(ctx).WithError(e).Debug("remove layer failed")
					if retError == nil {
						retError = e
					} else {
						retError = errors.Wrapf(retError, e.Error())
					}
				}
			}
		}
	}

	// TODO (possibly) Consider deleting the container directory in the utility VM

	return retError
}

func cleanupOnMountFailure(ctx context.Context, uvm *uvm.UtilityVM, wcowLayers []string, lcowLayers []lcowLayerEntry, scratchHostPath string) {
	for _, wl := range wcowLayers {
		if err := uvm.RemoveVSMB(ctx, wl); err != nil {
			log.G(ctx).WithError(err).Warn("Possibly leaked vsmbshare on error removal path")
		}
	}
	for _, ll := range lcowLayers {
		if ll.scsi {
			if err := uvm.RemoveSCSI(ctx, ll.hostPath); err != nil {
				log.G(ctx).WithError(err).Warn("Possibly leaked SCSI on error removal path")
			}
		} else if err := uvm.RemoveVPMEM(ctx, ll.hostPath); err != nil {
			log.G(ctx).WithError(err).Warn("Possibly leaked vpmemdevice on error removal path")
		}
	}
	if scratchHostPath != "" {
		if err := uvm.RemoveSCSI(ctx, scratchHostPath); err != nil {
			log.G(ctx).WithError(err).Warn("Possibly leaked SCSI disk on error removal path")
		}
	}
}

func computeV2Layers(ctx context.Context, vm *uvm.UtilityVM, paths []string) (layers []hcsschema.Layer, err error) {
	for _, path := range paths {
		uvmPath, err := vm.GetVSMBUvmPath(ctx, path)
		if err != nil {
			return nil, err
		}
		layerID, err := wclayer.LayerID(path)
		if err != nil {
			return nil, err
		}
		layers = append(layers, hcsschema.Layer{Id: layerID.String(), Path: uvmPath})
	}
	return layers, nil
}
