#!/bin/busybox sh
# /init of the QEMU guest make_kernel_keys.py boots: the Linux kernel's own
# read-only drivers (qnx4, qnx6, cramfs, romfs) mount each image and the
# guest lists what they see -- the answer key. vda is the listing out;
# /disks names the others, one 'device fstype label' a line.
/bin/busybox --install -s /bin 2>/dev/null
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
while read module params; do
    insmod "/modules/$module" $params || { echo "TRACE: insmod $module failed"; dmesg | tail -5; }
done < /modules/order
. /listing.sh
: > /listing
while read device fstype label; do
    mkdir -p "/mnt/$label"
    if mount -t "$fstype" -o ro "/dev/$device" "/mnt/$label"; then
        list_tree "/mnt/$label" "$label" >> /listing
        echo "mounted $label:"
        dmesg | tail -4
        umount "/mnt/$label"
    else
        echo "TRACE: mount $label ($fstype) failed"
        dmesg | tail -5
    fi
done < /disks
echo TRACE-END >> /listing
dd if=/listing of=/dev/vda bs=4096 conv=fsync 2>/dev/null
echo "TRACE: done"
poweroff -f
