#!/bin/busybox sh
# /init of the QEMU guest make_ubifs.py boots: the Linux kernel writes a
# UBIFS volume on simulated NAND. Phase 1 (the tree) is committed by the
# unmount; phase 2 (the changes) is synced but stays in the journal. The
# guest lists what it sees -- the answer key -- then reads the flash out.
/bin/busybox --install -s /bin 2>/dev/null
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
while read module params; do
    insmod "/modules/$module" $params || { echo "TRACE: insmod $module failed"; dmesg | tail -5; }
done < /modules/order
ubimkvol /dev/ubi0 -N rootfs -m || echo "TRACE: ubimkvol failed"
mkdir -p /mnt
mount -t ubifs ubi0:rootfs /mnt || echo "TRACE: mount failed"
cp -a /tree/. /mnt/
sync
umount /mnt
mount -t ubifs ubi0:rootfs /mnt || echo "TRACE: second mount failed"
cd /mnt
echo "written after the commit" > journal-new.txt
mkdir -p journal-dir
echo "in a new folder" > journal-dir/inside.txt
rm docs/report.bin
rm many/file-01*
mv docs/notes.txt docs/renamed-notes.txt
truncate -s 5000 big/log.txt
dd if=/dev/zero of=big/video.bin bs=4096 seek=10 count=3 conv=notrunc 2>/dev/null
echo "appended" >> dup/one.bin
ln -s journal-new.txt journal-link
# Not sync: UBIFS commits on sync. Each changed file is fsynced (written to
# the journal), and the write-buffers' timers flush the rest.
sync journal-new.txt journal-dir/inside.txt dup/one.bin big/video.bin
sync big/log.txt docs/renamed-notes.txt
sleep 12
cd /
. /listing.sh
list_tree /mnt > /listing
echo TRACE-END >> /listing
dd if=/listing of=/dev/vdb bs=4096 conv=fsync 2>/dev/null
cat /dev/mtd0 > /dev/vda
sync /dev/vda
echo "TRACE: done"
poweroff -f
