#!/bin/busybox sh
# /init of the QEMU guest make_zfs.py boots: OpenZFS (the kernel module and
# zpool/zfs, Ubuntu's) writes pools; the guest lists every dataset and the
# snapshot as it sees them -- the answer key -- and exports the pools.
#   vda listing out; vdb solo; vdc vdd twin; vde vdf vdg parity;
#   vdh-vdk double (raidz2); vdl vdm wide (a stripe) -- each
#   disk GPT with the pool in partition 1 (make_zfs.py partitions them)
/bin/busybox --install -s /bin 2>/dev/null
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /etc/zfs /run /var/tmp
ln -sf /proc/mounts /etc/mtab
while read module params; do
    insmod "/modules/$module" $params || { echo "TRACE: insmod $module failed"; dmesg | tail -5; }
done < /modules/order
fail() { echo "TRACE: $*" > /dev/console; }
. /listing.sh

# -- solo: datasets with every compressor, a deep file, a snapshot ---------
zpool create -f -o ashift=12 -O compression=lz4 -O atime=off \
    -O xattr=sa -O mountpoint=/pool/solo solo /dev/vdb1 || fail "zpool create solo"
cp -a /tree/. /pool/solo/
for c in gzip-9 zstd lzjb zle off; do
    zfs create -o compression=$c solo/$c || fail "zfs create $c"
    cp -a /tree/docs /tree/big /pool/solo/$c/
done
zfs create -o recordsize=512 -o compression=off solo/smallrec || fail "zfs create smallrec"
cp /tree/big/video.bin /pool/solo/smallrec/
zfs create -o dnodesize=auto solo/nested || fail "zfs create nested"
zfs create solo/nested/child || fail "zfs create child"
echo "a nested dataset" > /pool/solo/nested/child/note.txt
sync
zfs snapshot solo@before || fail "zfs snapshot"
rm /pool/solo/docs/report.bin
echo "changed after the snapshot" > /pool/solo/docs/notes.txt
echo "new after the snapshot" > /pool/solo/after.txt
sync

# -- twin and parity (raidz1) ---------------------------------------------
zpool create -f -o ashift=9 -O compression=lz4 -O mountpoint=/pool/twin \
    twin mirror /dev/vdc1 /dev/vdd1 || fail "zpool create twin"
cp -a /tree/. /pool/twin/
zpool create -f -o ashift=12 -O compression=off -O mountpoint=/pool/parity \
    parity raidz1 /dev/vde1 /dev/vdf1 /dev/vdg1 || fail "zpool create parity"
cp -a /tree/. /pool/parity/
zpool create -f -o ashift=9 -O compression=lz4 -O mountpoint=/pool/double     double raidz2 /dev/vdh1 /dev/vdi1 /dev/vdj1 /dev/vdk1 || fail "zpool create double"
cp -a /tree/. /pool/double/
zpool create -f -o ashift=12 -O compression=zstd -O mountpoint=/pool/wide     wide /dev/vdl1 /dev/vdm1 || fail "zpool create wide"
cp -a /tree/. /pool/wide/
sync

{
    for ds in solo solo/gzip-9 solo/zstd solo/lzjb solo/zle solo/off \
              solo/smallrec solo/nested solo/nested/child twin parity \n              double wide; do
        echo "dataset${TAB}$(zfs get -H -o value compression $ds)${TAB}$ds"
        # A dataset's own files only (-xdev): a child's mountpoint is the
        # empty folder it is in the parent.
        list_tree "/pool/$ds" "$ds" -xdev
    done
    mkdir -p /snap && mount -t zfs solo@before /snap || fail "mount snapshot"
    echo "dataset${TAB}snapshot${TAB}solo@before"
    list_tree /snap "solo@before"
    umount /snap
    zpool status -P
    zfs list -t all -o name,used,compression,recordsize
} > /listing 2>&1
echo TRACE-END >> /listing
for p in solo twin parity double wide; do zpool export $p || fail "zpool export $p"; done
dd if=/listing of=/dev/vda bs=4096 conv=fsync 2>/dev/null
sync
echo "TRACE: done"
poweroff -f
