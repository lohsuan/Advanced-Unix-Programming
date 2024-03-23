
obj-m     += maze.o
ccflags-y += -DEXPORT_SYMTAB

# For cross-compilatoin, use `make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu-` instead
# cross-compilatoin is needed when we use arm based Mac or wsl in windows
# If we use ubuntu to make, it is no need to run cross-compile images

all:
	make -C ../dist/modulebuild M=$(PWD) modules ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu-

# maze: maze.c
# 	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f maze
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp maze.ko ../rootfs/modules
	# cp maze.ko ../rootfs
