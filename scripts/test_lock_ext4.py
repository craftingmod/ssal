"""Offline ext4/xattr preservation, including symlinks; no mounts or device access."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
spec=importlib.util.spec_from_file_location("ext4builder",Path(__file__).with_name("build-lock-sysconfig-ext4.py"))
builder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class Ext4PreservationTests(unittest.TestCase):
    def test_symlink_inventory_does_not_follow_host_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"link"
            path.symlink_to("/data/system/locksettings.db")
            self.assertEqual(builder.content(path),{"symlink":"/data/system/locksettings.db"})

    @unittest.skipUnless(shutil.which("debugfs") and shutil.which("mke2fs"),"requires offline e2fsprogs tools")
    def test_real_inode_xattrs_dac_files_and_symlink_survive(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            tree=root/"tree/system/etc/sysconfig"
            tree.mkdir(parents=True)
            (tree/"original.xml").write_bytes(b"<permissions/>\n")
            (tree/"alias.xml").symlink_to("original.xml")
            image=root/"original.ext4"
            with image.open("wb") as file:
                file.truncate(8*1024*1024)
            builder.run(["mke2fs","-q","-t","ext4","-F","-d",root/"tree",image])
            label=root/"label.bin"
            label.write_bytes(builder.LABEL)
            for name,meta in builder.entries(image).items():
                builder.debug(image,f"ea_set -f {label} <{meta['inode']}> security.selinux",write=True)
            expected=builder.sha(image)
            old=builder.BASE_SHA
            builder.BASE_SHA=expected
            try:
                xml=root/"ssal.xml"
                xml.write_bytes(b"<permissions><unavailable-feature name='android.software.secure_lock_screen'/></permissions>")
                report=builder.build(image,xml,root/"out/build")
            finally:
                builder.BASE_SHA=old
            self.assertEqual(builder.sha(image),expected)
            self.assertEqual(report["status"],"passed")
            self.assertEqual(report["source_symlinks"],1)
            self.assertEqual(report["manifest"]["alias.xml"]["content"],{"symlink":"original.xml"})
            self.assertEqual(report["manifest"]["ssal-lockscreen.xml"]["xattr_hex"],builder.LABEL.hex())

if __name__=="__main__":
    unittest.main()