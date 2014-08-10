#!/usr/bin/env python
# Utility to prepare a QCOW2 image for QEMU by installing the necessary drivers
# and making registry changes.
#
# Copyright (C) 2014 Peter Wu <peter@lekensteyn.nl>

import os, sys
import guestfs, hivex
# Available post-1.3.10, https://github.com/Lekensteyn/hivex/tree/develop
# hivex 1.3.11 is *required* anyway, otherwise it will segfault on setting
# values.
from hivex.hive_types import *
from collections import defaultdict
from tempfile import NamedTemporaryFile
from copy import copy
import argparse
import logging

# TODO: callable fallback for Python 3.0 and 3.1

_logger = logging.getLogger(__name__)

# Utilities for handling registry structure
class RegistryHandle(defaultdict):
    def __init__(self):
        super(RegistryHandle, self).__init__(self.__class__)

    def __getattr__(self, key):
        return self[key]

    def __setattr__(self, key, val):
        self[key] = val

    def __copy__(self):
        s = self.__class__()
        for k, v in self.items():
            s[k] = v
        return s

    def __iadd__(self, two):
        """
        Union operator that merges two into itself.
        """
        for k, v in two.items():
            if k in self and isinstance(v, self.__class__):
                self[k] += v
            else:
                self[k] = v
        return self
    def __add__(self, two):
        """
        Union operator that merges instances of self or overwrites them with the
        right-hand values.
        """
        s = copy(self)
        s += two
        return s

    def walk(self, callback, opaque=None):
        """
        Walks through the keys of this handle, invoking callback with four
        arguments: the key, its value and an opaque element that is passed to
        the callback. If the value is another RegistryHandle, then the return
        value of the callback will be used as opaque parameter when walking
        through its children.
        """
        for k, v in self.items():
            if isinstance(v, self.__class__):
                _opaque = callback(k, v, opaque)
                v.walk(callback, opaque=_opaque)
            else:
                callback(k, v, opaque)

class RegistryValue(object):
    def __init__(self, value, type=None):
        self._value = value
        self._type = type
    def type(self):
        return self._type
    def value(self):
        return self._value
    def __repr__(self):
        return repr(self._value)


# Mapping from Windows major,minor versions to VirtIO folders
# https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
_WINDOWS_VERSIONS = {
    "6.3": "win8",  # Windows 8.1
    "6.2": "win8",  # Windows 8
    "6.1": "win7",  # Windows 7
    "6.0": "wlh",   # Windows Vista
    "5.2": "wnet",  # Windows Server 2003 (and Windows XP Pro x64)
    "5.1": "xp",    # Windows XP
}

class Machine(object):
    def __init__(self, win_disk_image, virtio_iso_image):
        """
        Adds the images as block devices, launches the machine and fetches some
        version information about the guest.
        """
        self.g = guestfs.GuestFS()
        self.g.add_drive(win_disk_image)
        self.g.add_drive_ro(virtio_iso_image)
        self.g.launch()
        self.win_blkroot = self._mount_block_devices()
        self.win_ver = "{}.{}".format(
            self.g.inspect_get_major_version(self.win_blkroot),
            self.g.inspect_get_minor_version(self.win_blkroot)
        )
        self.is_x64 = self.g.inspect_get_arch(self.win_blkroot) == "x86_64"

    def _mount_block_devices(self):
        """
        Mounts block devices, returning the block device for the root Windows
        partition.
        """
        rootdevs = self.g.inspect_os()
        blockdevs = self.g.list_devices()
        if not rootdevs:
            raise RuntimeError("No root device found!")
        win_blkroot = rootdevs[0]
        # Assume that the virtio ISO is the most recently added device
        virtio_cd_rootdev = blockdevs[-1]
        images = [
            (win_blkroot, "/win"),
            (virtio_cd_rootdev, "/cd")
        ]
        for blockdev, mountpoint in images:
            self.g.mkmountpoint(mountpoint)
            self.g.mount(blockdev, mountpoint)
        return win_blkroot

    def get_windir_path(self, path):
        """
        Resolves %systemroot% against the guest, it will return an absolute path
        to the "Windows" directory in the guest.
        """
        sysroot = self.g.inspect_get_windows_systemroot(self.win_blkroot)
        path = "/win/{}/{}".format(sysroot, path)
        path = self.g.case_sensitive_path(path)
        return path

    def install_driver(self, name, overwrite=False):
        """
        Copies driver files from a VirtIO CD to the guest. The kernel driver
        (.sys), setup information file (.inf) and signed catalog file (.cat) are
        copied.
        """
        exts = {
            "sys": "system32/drivers",
            "inf": "inf",
            "cat": "system32/CatRoot",
        }
        vio_win_name = _WINDOWS_VERSIONS[self.win_ver]
        # For WinXP, drivers other than netkvm are only available for x86
        if name != "netkvm" and vio_win_name == "xp":
            isodir = "/cd/wxp/x86"
        else:
            arch = "amd64" if self.is_x64 else "x86"
            isodir = "/cd/{}/{}".format(vio_win_name, arch)
        for ext, dstdir in exts.items():
            src = "{}/{}.{}".format(isodir, name, ext)
            dst = self.get_windir_path("{}/{}.{}".format(dstdir, name, ext))
            should_copy = not self.g.exists(dst)
            if not should_copy and overwrite:
                _logger.info("Overwriting existing {}".format(dst))
                should_copy = True
            if should_copy:
                _logger.info("cp '{}' -> '{}'".format(src, dst))
                self.g.cp(src, dst)
            else:
                _logger.info("Not copying '{}' to existing '{}'".format(
                            src, dst))

    def reg_get_ccs_name(self):
        """
        Returns the current control set name (e.g. ControlSet001).
        """
        return self.g.inspect_get_windows_current_control_set(self.win_blkroot)

    def import_win_reg(self, hive, handle=None, modify_handle=None):
        """
        Given the destination hive (typically "system" for HKLM\\SYSTEM),
        download the registry hive file from the guest. If the RegistryHandle
        handle parameter is given, apply changes from this handle. Missing keys
        will be created. After this, apply changes from modify_handle, but do
        not create subkeys if missing (but values are still considered). Finally
        upload the modified registry file back to the image.

        At least one of the handle or modify_handle parameters must be given.
        """
        if not handle and not modify_handle:
            raise ValueError("Must supply at least handle or modify_handle")

        _logger.info("Retrieving {} registry".format(hive))
        regfile = self.get_windir_path("system32/config/" + hive)
        # Note: Windows propably have issues with using an open file
        with NamedTemporaryFile() as tmpfile:
            self.g.download(regfile, tmpfile.name)
            h = hivex.Hivex(tmpfile.name, write=True)
            _logger.info("Retrieved registry, updating keys...")

            if handle:
                opaque = True, h, h.root(), "HKLM\\{}".format(hive)
                handle.walk(self._import_callback, opaque)
            if modify_handle:
                opaque = False, h, h.root(), "HKLM\\{}".format(hive)
                handle.walk(self._import_callback, opaque)

            h.commit(None)
            _logger.info("Updating registry {}".format(hive))
            self.g.upload(tmpfile.name, regfile)

    def _import_callback(self, key, value, opaque):
        # If the parent key does not exist and should not be created, ignore all
        # subkeys and values
        if not opaque:
            return

        create_missing, h, root, path = opaque
        path += "\\" + key
        if isinstance(value, RegistryHandle):
            # value is a handle, return the handle matching this child
            node = h.node_get_child(root, key)
            if node is None:
                if not create_missing:
                    return None
                node = h.node_add_child(root, key)
            # Promote the child node as new root for its children
            return create_missing, h, node, path
        else:
            old_value = h.node_get_value(root, key)
            if old_value:
                old_type, old_data = h.value_value(old_value)
            #if callable(value):
            #    _logger.debug("Calling {} for {}".format(value, path))
            #    value = value(h, path, old_value)
            #    if value is None:
            #        _logger.debug("Not setting value for {}".format(path))
            #        return

            # Find the most appropriate type for the value
            if isinstance(value, int):
                t = REG_DWORD
            elif isinstance(value, bytes):
                t = REG_SZ
            elif isinstance(value, str):
                t = REG_SZ
            elif isinstance(value, RegistryValue):
                t = value.type()
                value = value.value()
            else:
                raise RuntimeError("Unknown type for {}={}".format(key, value))

            # Assume that strings are nul-terminated UTF-16 (LE)
            if not isinstance(value, bytes) and isinstance(value, str):
                value = value.encode("utf-16-le") + b"\x00\x00"
            elif isinstance(value, list):
                t = REG_MULTI_SZ
                items, value = value, b''
                # Assume UTF-16 (LE) Unicode strings
                for item in items:
                    value += item.encode("utf-16-le") + b"\x00\x00"
                value += b"\x00\x00"

            new_value = {
                "key": key,
                "t": t,
                "value": value
            }
            if old_value and (old_type, old_data) == (t, value):
                _logger.debug("Skipping unmodified key {}".format(path))
                return
            _logger.debug("Setting key {}".format(path))
            if old_value:
                _logger.debug("Changing from type {}, value {}".format(old_type,
                            repr(old_data)))
            _logger.debug("Setting to type {}, value {}".format(t, repr(value)))
            h.node_set_value(root, new_value)

# If you are ever going to implement a full-fledged inf file parsing, have a
# look at
# http://msdn.microsoft.com/en-us/library/windows/hardware/ff546320%28v=vs.85%29.aspx

class Driver(object):
    def __init__(self, name):
        self.name = name
        # System\CurrentControlSet; HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001
        self.reg_system_ccs = RegistryHandle()

    def set_service(self, group, load_order, start_type=0):
        """
        start_type: 0 (boot), 3 (on demand)
        """
        # See http://support.microsoft.com/kb/103000 for a description
        svc = self.reg_system_ccs.Services[self.name]
        # corresponds to ServiceBinary (in inf) where %12% is the drivers dir
        image_path = "system32\\drivers\\{}.sys".format(self.name)
        svc.ImagePath = RegistryValue(image_path, type=REG_EXPAND_SZ)
        svc.Group           = group
        svc.ErrorControl    = 0x00000001 # SERVICE_ERROR_NORMAL
        svc.Start           = start_type
        svc.Type            = 0x00000001 # SERVICE_KERNEL_DRIVER
        svc.Tag             = load_order # load order within group
        return svc

class PciDriver(Driver):
    def __init__(self, name, class_guid, vid, pid, svid, spid):
        super(PciDriver, self).__init__(name)
        # Add self to critical device database
        cddb = self.reg_system_ccs.Control.CriticalDeviceDatabase
        fmt = "pci#ven_{:04x}&dev_{:04x}&subsys_{:04x}{:04x}&rev_00"
        subs = [
            (0, 0),
            (svid, 0),
            (svid, spid)
        ]
        for _svid, _spid in subs:
            regkey = fmt.format(vid, pid, _svid, _spid)
            cddb[regkey].ClassGUID = class_guid
            cddb[regkey].Service = name

# Drivers (values taken from INF file)
viostor = PciDriver("viostor", "{4D36E97B-E325-11CE-BFC1-08002BE10318}",
    0x1af4, 0x1001, 0x0002, 0x1af4)
_svc = viostor.set_service("SCSI miniport", 0x40)
# pnpsafe_pci_addreg
_svc.Parameters.PnpInterface["5"] = 0x00000001
_svc.Parameters.BusType = 0x00000001
_svc.Enum["0"] = "PCI\\VEN_1AF4&DEV_1001&SUBSYS_00021AF4&REV_00\\3&13c0b0c5&2&20"
_svc.Enum.Count = 0x00000001
_svc.Enum.NextInstance = 0x00000001
#viostor.reg_system_ccs.Services.Disk.Enum["1"] = \
#    "SCSI\\Disk&Ven_Red_Hat&Prod_VirtIO&Rev_0001\\4&35110308&0&000"
#_ctrl = viostor.reg_system_ccs.Control.Class
#_t = _ctrl["{4D36E97B-E325-11CE-BFC1-08002BE10318}"]["0000"]
#_t.InfPath          = "oem1.inf"
#_t.InfSection       = "rhelscsi_inst"
#_t.ProviderName     = "Red Hat, Inc."
## the hivex library sadly does not support anything but UTF-8 strings...
##_t.DriverDateData   = b"\x00\x40\xb1\xf6\x3d\x63\xcf\x01"
#_t.DriverDate       = "4-29-2014"
#_t.DriverVersion    = "51.70.104.8100"
#_t.MatchingDeviceId = "pci\\ven_1af4&dev_1001&subsys_00021af4&rev_00"
#_t.DriverDesc       = "Red Hat VirtIO SCSI controller"

netkvm = PciDriver("netkvm", "{4D36E972-E325-11CE-BFC1-08002BE10318}",
    0x1af4, 0x1000, 0x0001, 0x1af4)
_svc = netkvm.set_service("NDIS", 0x18, start_type=3)
_svc.DisplayName = "Red Hat VirtIO Ethernet Adapter Service"
_svc.BootFlags = 0x00000001
# TextModeFlags.Reg
_svc.TextModeFlags = 1
_svc.Parameters.DisableMSI = 0
_svc.Parameters.EarlyDebug = 3
_svc.Enum["0"] = "PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00\\3&13c0b0c5&2&18"
_svc.Enum.Count = 0x00000001
_svc.Enum.NextInstance = 0x00000001


def main(win_disk_image, virtio_iso, testing, overwrite_files):
    if not os.path.isfile(win_disk_image):
        raise ValueError("Disk image {} not found".format(win_disk_image))
    if not os.path.isfile(virtio_iso):
        raise ValueError("VirtIO iso image {} not found".format(virtio_iso))

    m = Machine(win_disk_image, virtio_iso)
    _logger.info("Started machine {} (x64={})".format(m.win_ver, m.is_x64))
    #drivers = ["viostor", "netkvm", "vioscsi"]
    drivers = [
        viostor,
#        netkvm
    ]
    system_hive = RegistryHandle()
    ccs_name = m.reg_get_ccs_name()
    ccs = system_hive[ccs_name]
    for driver in drivers:
        m.install_driver(driver.name, overwrite=overwrite_files)
        ccs += driver.reg_system_ccs

    #import pprint
    #pprint.PrettyPrinter(indent=4).pprint(system_hive)

    # Disable unnecessary or conflicting services
    disable_services = [
        "VBoxGuest",
        "VBoxMouse", # Needs additional treatment to avoid dead mouse
        "VBoxService",
        "VBoxSF",
        "VBoxVideo",
        "Processor",
    ]
    mod_system_hive = RegistryHandle()
    mod_ccs_svc = mod_system_hive[ccs_name].Services
    for service_name in disable_services:
        # http://support.microsoft.com/kb/103000 Start values:
        # 0 Boot (by bootloader)
        # 1 System (by IO subsystem)
        # 2 Auto-load (by Service Control Manager)
        # 3 On-demand (by Service Control Manager)d
        # 4 Disable (by Service Control Manager)d
        mod_ccs_svc[service_name].Start = 4
    # Remove VBoxMouse from UpperFilters
    mse_cls_id = "{4D36E96F-E325-11CE-BFC1-08002BE10318}"
    mse_cls = mod_ccs_svc.Control.Class[mse_cls_id]
    mse_cls.UpperFilters = ["mouclass"]

    # TODO: needed from WinXP SP3 CD D:\i386\
    # SP3.CAB (17748719 bytes, md5 3c10b0c178a26a6d8e96a2f70a32c9da).
    # Extract it to C:\Windows\ServicePackInstallation\i386\.
    # usbuhci.sys
    # RTL8139.sys
    # DRIVER.CAB (62540124 bytes, md5 34f823a3c125fb81d3d77e9ebe865a1d)
    # Extract is to C:\Windows\Driver Cache\i386\.
    # mouhid.sys

    # If in test-mode, create registry entries below some other entry
    if testing:
        test_hive = RegistryHandle()
        test_hive.testhandle = system_hive
        system_hive = test_hive
        test_hive = RegistryHandle()
        test_hive.testhandle = mod_system_hive
        mod_system_hive = test_hive

    m.import_win_reg("system", handle=system_hive,
            modify_handle=mod_system_hive)

_verbosities = [
    logging.CRITICAL,
    logging.ERROR,
    logging.WARNING, # Default
    logging.INFO,
    logging.DEBUG
]
parser = argparse.ArgumentParser(
       description="Prepares a Windows disk image for QEMU")
parser.add_argument("win_disk_image",
                    help="Windows disk image (qcow2 recommended)")
parser.add_argument("--virtio-iso",
                    default="/media/DEBIAN/qemu/virtio-win-0.1-81.iso",
                    help="VirtIO driver CD image (see \
                    http://alt.fedoraproject.org/pub/alt/virtio-win/, \
                    defaults to %(default)s)")
parser.add_argument("-o", "--overwrite", default=False, action="store_true",
                    help="Overwrite files during driver installation")
parser.add_argument("-v", "--verbose", action="count",
                    default=_verbosities.index(logging.WARNING),
                    help="Increase log level (twice for extra verbosity)")
parser.add_argument("-t", "--testing", default=False, action="store_true",
                    help="Create registry entries under HKLM\\SYSTEM\\testhandle")

if __name__ == "__main__":
    args = parser.parse_args()
    args.verbose = min(args.verbose, len(_verbosities) - 1)
    #_logger.setLevel(_verbosities[args.verbose])
    logging.basicConfig(level=_verbosities[args.verbose])
    main(args.win_disk_image, args.virtio_iso, args.testing, args.overwrite)
