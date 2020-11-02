# mount root lvm inside ubuntu privileged container

apt-get update && apt-get install lvm2
mount
lvscan
vgchange -ay
mkdir /osroot 
dmsetup ls --tree -o blkdevname
mount /dev/dm-0 osroot/ # assuming dm-0 corresponds to root lvm
cd /osroot
