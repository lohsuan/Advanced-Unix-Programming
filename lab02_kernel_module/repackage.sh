
### decompress rootfs.cpio.bz2

# bzip2 -d rootfs.cpio.bz2
# cpio -iv < rootfs.cpio

### under mazemod dir (buildenv:/build/crossbuild/mazemod$)
make
make install

cd ../rootfs
find . | cpio -ov -H newc > ../rootfs.cpio

cd ..
bzip2 rootfs.cpio
mv rootfs.cpio.bz2 dist/