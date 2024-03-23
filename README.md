# Advanced UNIX Programming 2024
The topics include file I/O, process control, signals, multi-thread, daemons, IPC, and terminal I/O...

### Lab01 - docker & pwntools

This lab aims to build a runtime environment required by this course. You have to be familiar with `docker`, `python`, and `pwntools` in this lab.

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