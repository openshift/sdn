package uvm

import (
	"context"
	"fmt"

	"github.com/Microsoft/hcsshim/internal/guestrequest"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/requesttype"
	hcsschema "github.com/Microsoft/hcsshim/internal/schema2"
	"github.com/Microsoft/hcsshim/internal/wclayer"
	"github.com/sirupsen/logrus"
)

var (
	ErrNoAvailableLocation      = fmt.Errorf("no available location")
	ErrNotAttached              = fmt.Errorf("not attached")
	ErrAlreadyAttached          = fmt.Errorf("already attached")
	ErrNoSCSIControllers        = fmt.Errorf("no SCSI controllers configured for this utility VM")
	ErrTooManyAttachments       = fmt.Errorf("too many SCSI attachments")
	ErrSCSILayerWCOWUnsupported = fmt.Errorf("SCSI attached layers are not supported for WCOW")
)

// allocateSCSI finds the next available slot on the
// SCSI controllers associated with a utility VM to use.
// Lock must be held when calling this function
func (uvm *UtilityVM) allocateSCSI(ctx context.Context, hostPath string, uvmPath string, isLayer bool) (int, int32, error) {
	for controller, luns := range uvm.scsiLocations {
		for lun, si := range luns {
			if si.hostPath == "" {
				uvm.scsiLocations[controller][lun].hostPath = hostPath
				uvm.scsiLocations[controller][lun].uvmPath = uvmPath
				uvm.scsiLocations[controller][lun].isLayer = isLayer
				if isLayer {
					uvm.scsiLocations[controller][lun].refCount = 1
				}
				log.G(ctx).WithFields(logrus.Fields{
					"hostPath":   hostPath,
					"uvmPath":    uvmPath,
					"isLayer":    isLayer,
					"refCount":   0,
					"controller": controller,
					"lun":        lun,
				}).Debug("allocated SCSI location")
				return controller, int32(lun), nil
			}
		}
	}
	return -1, -1, ErrNoAvailableLocation
}

func (uvm *UtilityVM) deallocateSCSI(ctx context.Context, controller int, lun int32) {
	uvm.m.Lock()
	defer uvm.m.Unlock()
	si := uvm.scsiLocations[controller][lun]
	if si.hostPath != "" {
		log.G(ctx).WithFields(logrus.Fields{
			"hostPath":   si.hostPath,
			"uvmPath":    si.uvmPath,
			"isLayer":    si.isLayer,
			"refCount":   si.refCount,
			"controller": controller,
			"lun":        lun,
		}).Debug("removed SCSI location")
		uvm.scsiLocations[controller][lun] = scsiInfo{}
	}
}

// Lock must be held when calling this function.
func (uvm *UtilityVM) findSCSIAttachment(ctx context.Context, findThisHostPath string) (int, int32, string, error) {
	for controller, luns := range uvm.scsiLocations {
		for lun, si := range luns {
			if si.hostPath == findThisHostPath {
				log.G(ctx).WithFields(logrus.Fields{
					"hostPath":   si.hostPath,
					"uvmPath":    si.uvmPath,
					"isLayer":    si.isLayer,
					"refCount":   si.refCount,
					"controller": controller,
					"lun":        lun,
				}).Debug("found SCSI location")
				return controller, int32(lun), si.uvmPath, nil
			}
		}
	}
	return -1, -1, "", ErrNotAttached
}

// AddSCSI adds a SCSI disk to a utility VM at the next available location. This
// function should be called for a RW/scratch layer or a passthrough vhd/vhdx.
// For read-only layers on LCOW as an alternate to PMEM for large layers, use
// AddSCSILayer instead.
//
// `hostPath` is required and must point to a vhd/vhdx path.
//
// `uvmPath` is optional.
//
// `readOnly` set to `true` if the vhd/vhdx should be attached read only.
func (uvm *UtilityVM) AddSCSI(ctx context.Context, hostPath string, uvmPath string, readOnly bool) (int, int32, error) {
	return uvm.addSCSIActual(ctx, hostPath, uvmPath, "VirtualDisk", false, readOnly)
}

// AddSCSIPhysicalDisk attaches a physical disk from the host directly to the
// Utility VM at the next available location.
//
// `hostPath` is required and `likely` start's with `\\.\PHYSICALDRIVE`.
//
// `uvmPath` is optional if a guest mount is not requested.
//
// `readOnly` set to `true` if the physical disk should be attached read only.
func (uvm *UtilityVM) AddSCSIPhysicalDisk(ctx context.Context, hostPath, uvmPath string, readOnly bool) (int, int32, error) {
	return uvm.addSCSIActual(ctx, hostPath, uvmPath, "PassThru", false, readOnly)
}

// AddSCSILayer adds a read-only layer disk to a utility VM at the next available
// location. This function is used by LCOW as an alternate to PMEM for large layers.
// The UVMPath will always be /tmp/S<controller>/<lun>.
func (uvm *UtilityVM) AddSCSILayer(ctx context.Context, hostPath string) (int, int32, error) {
	if uvm.operatingSystem == "windows" {
		return -1, -1, ErrSCSILayerWCOWUnsupported
	}

	return uvm.addSCSIActual(ctx, hostPath, "", "VirtualDisk", true, true)
}

// addSCSIActual is the implementation behind the external functions AddSCSI and
// AddSCSILayer.
//
// We are in control of everything ourselves. Hence we have ref- counting and
// so-on tracking what SCSI locations are available or used.
//
// `hostPath` is required and may be a vhd/vhdx or physical disk path.
//
// `uvmPath` is optional, and `must` be empty for layers. If `!isLayer` and
// `uvmPath` is empty no guest modify will take place.
//
// `attachmentType` is required and `must` be `VirtualDisk` for vhd/vhdx
// attachments and `PassThru` for physical disk.
//
// `isLayer` indicates that this is a read-only (LCOW) layer VHD. This parameter
// `must not` be used for Windows.
//
// `readOnly` indicates the attachment should be added read only.
//
// Returns the controller ID (0..3) and LUN (0..63) where the disk is attached.
func (uvm *UtilityVM) addSCSIActual(ctx context.Context, hostPath, uvmPath, attachmentType string, isLayer, readOnly bool) (_ int, _ int32, err error) {
	if uvm.scsiControllerCount == 0 {
		return -1, -1, ErrNoSCSIControllers
	}

	// Ensure the utility VM has access
	if !isLayer {
		if err := wclayer.GrantVmAccess(uvm.id, hostPath); err != nil {
			return -1, -1, err
		}
	}

	// We must hold the lock throughout the lookup (findSCSIAttachment) until
	// after the possible allocation (allocateSCSI) has been completed to ensure
	// there isn't a race condition for it being attached by another thread between
	// these two operations. All failure paths between these two must release
	// the lock.
	uvm.m.Lock()
	if controller, lun, _, err := uvm.findSCSIAttachment(ctx, hostPath); err == nil {
		// So is attached
		if isLayer {
			// Increment the refcount
			uvm.scsiLocations[controller][lun].refCount++
			uvm.m.Unlock()
			return controller, lun, nil
		}

		uvm.m.Unlock()
		return -1, -1, ErrAlreadyAttached
	}

	// At this point, we know it's not attached, regardless of whether it's a
	// ref-counted layer VHD, or not.
	controller, lun, err := uvm.allocateSCSI(ctx, hostPath, uvmPath, isLayer)
	if err != nil {
		uvm.m.Unlock()
		return -1, -1, err
	}
	defer func() {
		if err != nil {
			uvm.deallocateSCSI(ctx, controller, lun)
		}
	}()

	// Auto-generate the UVM path for LCOW layers
	if isLayer {
		uvmPath = fmt.Sprintf("/tmp/S%d/%d", controller, lun)
	}

	// See comment higher up. Now safe to release the lock.
	uvm.m.Unlock()

	// Note: Can remove this check post-RS5 if multiple controllers are supported
	if controller > 0 {
		return -1, -1, ErrTooManyAttachments
	}

	SCSIModification := &hcsschema.ModifySettingRequest{
		RequestType: requesttype.Add,
		Settings: hcsschema.Attachment{
			Path:     hostPath,
			Type_:    attachmentType,
			ReadOnly: readOnly,
		},
		ResourcePath: fmt.Sprintf("VirtualMachine/Devices/Scsi/%d/Attachments/%d", controller, lun),
	}

	if uvmPath != "" {
		if uvm.operatingSystem == "windows" {
			SCSIModification.GuestRequest = guestrequest.GuestRequest{
				ResourceType: guestrequest.ResourceTypeMappedVirtualDisk,
				RequestType:  requesttype.Add,
				Settings: guestrequest.WCOWMappedVirtualDisk{
					ContainerPath: uvmPath,
					Lun:           lun,
				},
			}
		} else {
			SCSIModification.GuestRequest = guestrequest.GuestRequest{
				ResourceType: guestrequest.ResourceTypeMappedVirtualDisk,
				RequestType:  requesttype.Add,
				Settings: guestrequest.LCOWMappedVirtualDisk{
					MountPath:  uvmPath,
					Lun:        uint8(lun),
					Controller: uint8(controller),
					ReadOnly:   readOnly,
				},
			}
		}
	}

	if err := uvm.Modify(ctx, SCSIModification); err != nil {
		return -1, -1, fmt.Errorf("uvm::AddSCSI: failed to modify utility VM configuration: %s", err)
	}
	return controller, lun, nil

}

// RemoveSCSI removes a SCSI disk from a utility VM.
func (uvm *UtilityVM) RemoveSCSI(ctx context.Context, hostPath string) error {
	uvm.m.Lock()
	defer uvm.m.Unlock()

	if uvm.scsiControllerCount == 0 {
		return ErrNoSCSIControllers
	}

	// Make sure is actually attached
	controller, lun, uvmPath, err := uvm.findSCSIAttachment(ctx, hostPath)
	if err != nil {
		return err
	}

	if uvm.scsiLocations[controller][lun].isLayer {
		uvm.scsiLocations[controller][lun].refCount--
		if uvm.scsiLocations[controller][lun].refCount > 0 {
			return nil
		}
	}

	scsiModification := &hcsschema.ModifySettingRequest{
		RequestType:  requesttype.Remove,
		ResourcePath: fmt.Sprintf("VirtualMachine/Devices/Scsi/%d/Attachments/%d", controller, lun),
	}

	// Include the GuestRequest so that the GCS ejects the disk cleanly if the
	// disk was attached/mounted
	//
	// Note: We always send a guest eject even if there is no UVM path in lcow
	// so that we synchronize the guest state. This seems to always avoid SCSI
	// related errors if this index quickly reused by another container.
	if uvm.operatingSystem == "windows" && uvmPath != "" {
		scsiModification.GuestRequest = guestrequest.GuestRequest{
			ResourceType: guestrequest.ResourceTypeMappedVirtualDisk,
			RequestType:  requesttype.Remove,
			Settings: guestrequest.WCOWMappedVirtualDisk{
				ContainerPath: uvmPath,
				Lun:           lun,
			},
		}
	} else {
		scsiModification.GuestRequest = guestrequest.GuestRequest{
			ResourceType: guestrequest.ResourceTypeMappedVirtualDisk,
			RequestType:  requesttype.Remove,
			Settings: guestrequest.LCOWMappedVirtualDisk{
				MountPath:  uvmPath, // May be blank in attach-only
				Lun:        uint8(lun),
				Controller: uint8(controller),
			},
		}
	}

	if err := uvm.Modify(ctx, scsiModification); err != nil {
		return fmt.Errorf("failed to remove SCSI disk %s from container %s: %s", hostPath, uvm.id, err)
	}
	uvm.scsiLocations[controller][lun] = scsiInfo{}
	return nil
}

// GetScsiUvmPath returns the guest mounted path of a SCSI drive.
//
// If `hostPath` is not mounted returns `ErrNotAttached`.
func (uvm *UtilityVM) GetScsiUvmPath(ctx context.Context, hostPath string) (string, error) {
	uvm.m.Lock()
	defer uvm.m.Unlock()

	_, _, uvmPath, err := uvm.findSCSIAttachment(ctx, hostPath)
	return uvmPath, err
}
