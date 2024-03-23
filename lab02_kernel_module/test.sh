# This file is placed in the "rootfs" directory of the kernel source tree.
Cyan='\033[0;36m'
NC='\033[0m' # No Color

# 
insmod modules/maze.ko

echo -e "${Cyan}============================== mazetest 0 ==============================${NC}"
./mazetest 0

echo -e "${Cyan}============================== mazetest 1 ==============================${NC}"
./mazetest 1

echo -e "${Cyan}============================== mazetest 2 ==============================${NC}"
./mazetest 2

echo -e "${Cyan}============================== mazetest 3 ==============================${NC}"
./mazetest 3

echo -e "${Cyan}============================== mazetest 4 ==============================${NC}"
./mazetest 4

echo -e "${Cyan}============================== mazetest 5 ==============================${NC}"
./mazetest 5

echo -e "${Cyan}============================== mazetest 6 ==============================${NC}"
./mazetest 6

# rmmod modules/maze.ko
