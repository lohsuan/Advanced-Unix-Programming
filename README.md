# Advanced UNIX Programming 2024
The topics include file I/O, process control, signals, multi-thread, daemons, IPC, and terminal I/O...

### HW01 - library injection & API hijacking

Monitor File Activities of Dynamically Linked Programs \
Implement a simple logger program that can show file-access-related activities of an arbitrary binary running on a Linux operating system.

#### 1. Logger program

[logger.c](./hw01_lib_inject/logger.c)

* The logger program's job is to prepare the environment to inject, load, and execute a monitored binary.

#### 2. Shared object

[liblogger.c](./hw01_lib_inject/liblogger.c)

* This shared object will be injected into the monitored binary using `LD_PRELOAD`. 
* It will **intercept file access related library calls** and log them along with their parameters and return values.

---

### Lab03 - GOT table hijack

This lab aims to play with **LD_PRELOAD** and **GOT table**. 

實作內容：

#### 1. Library hijack
[libsolver.c](./lab03_got_table_hijack/libsolver.c) 
* 負責產生我們自己的 shared library `libsolver.so`
* 執行程式時：`LD_PRELOAD=./libsolver.so ./maze`
* hijack `maze_load`，讓 [`maze.c`](./lab03_got_table_hijack/maze.c) 在呼叫 `maze_load` 時並不是執行原本 [`libmaze_dummy.c`](./lab03_got_table_hijack/libmaze_dummy.c)，而是 `libsolver.so` 中的 `maze_load`
* 使用 `dlsym` 取得原本的 `maze_load` 並呼叫，達到在 `maze_load` 前後執行我們自己的程式

#### 2. GOT table hijack
[got.py](./lab03_got_table_hijack/got/got.py)
* 使用 `pwntools` 工具取得 GOT table offset

[libsolver.c](./lab03_got_table_hijack/libsolver.c) 
* 算出解開 maze 需走的路徑，再依序蓋到  `move_1` ~ `move_n` 的 GOT table
* `move_1` 的實際 address:
  * GOT table entries = *main_real_address* - *main_relative_address* + *got_offset_of_move_1* 


#### 3. Makefile
* `gcc -shared -o libsolver.so -fPIC libsolver.c -ldl`
  * `-shared -fPIC`: 編譯動態函式庫
  * `-ldl`: dynamic linking library (dlopen, dlsym, dlclose, dlerror)
* `LD_PRELOAD=./libsolver.so ./maze`
  * `LD_PRELOAD` 是系統中的環境變數：會讓指定載入的 library 且優先級最高，使我們可以覆蓋原本調用的 library

---

### Lab02 - kernel modules

This lab aims to practice implementing a character device as a kernel module that handles `read`, `write`, and `ioctl` operations. The character device has to implement several required features to construct and run a maze in the Linux kernel.

實作內容：
1. **裝置管理：** 在 `/dev` file system 自動建立 `maze` device，每個 process 同時僅能建立一個迷宮。
1. **裝置互動：** process 使用 `read`、`write`、`ioctl` 操作 kernel module。
    - **`ioctl`：** 定義 `MAZE_CREATE`、`MAZE_RESET`、`MAZE_DESTROY`、`MAZE_GETSIZE`、`MAZE_MOVE`、`MAZE_GETPOS`、`MAZE_GETSTART`、`MAZE_GETEND` 命令，並進行錯誤處理。
    - **`read`：** process 可讀取迷宮佈局。
    - **`write`：** 批次移動迷宮中玩家的位置。
1. **`/proc/maze` 接口：** 提供有關所有由 user space process 創建的迷宮狀態的信息。
    - `cat /proc/maze`
1. **資源管理：** 當裝置被關閉或 process 終止時，釋放所有分配的資源。
1. **數量限制：** 最多同時處理 `_MAZE_MAXUSER`（3）個迷宮，並確保每個 process 同時只能創建一個迷宮。

---

### Lab01 - docker & pwntools

This lab aims to build a runtime environment required by this course. You have to be familiar with `docker`, `python`, and `pwntools` in this lab.
