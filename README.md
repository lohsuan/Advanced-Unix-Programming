# Advanced UNIX Programming 2024
The topics include file I/O, process control, signals, multi-thread, daemons, IPC, and terminal I/O...

### Lab01 - docker & pwntools

This lab aims to build a runtime environment required by this course. You have to be familiar with `docker`, `python`, and `pwntools` in this lab.

### Lab02 - kernel modules

This lab aims to practice implementing a character device as a kernel module that handles `read`, `write`, and `ioctl` operations. The character device has to implement several required features to construct and run a maze in the Linux kernel.

實作內容：
1. **裝置管理：** 在 `/dev` 檔案系統中自動建立名為 `maze` 的裝置，每個 process 同時僅能建立一個迷宮。
2. **裝置互動：** 允許 process 使用 `read`、`write` 和 `ioctl` 操作與 kernel module 互動。
3. **`ioctl`：** 定義 `MAZE_CREATE`、`MAZE_RESET`、`MAZE_DESTROY`、`MAZE_GETSIZE`、`MAZE_MOVE`、`MAZE_GETPOS`、`MAZE_GETSTART`、`MAZE_GETEND` 命令，並進行錯誤處理。
4. **`read`：** 允許 process 讀取迷宮的佈局。
5. **`write`：** 允許批次移動迷宮中玩家的位置。
6. **/proc/maze 介面：** 提供有關所有由 user space process 創建的迷宮狀態的信息。
7. **資源管理：** 當裝置被關閉或 process 終止時，釋放所有分配的資源。
8. **Concurrent 限制：** 最多同時處理 `_MAZE_MAXUSER`（3）個迷宮，並確保每個 process 同時只能創建一個迷宮。