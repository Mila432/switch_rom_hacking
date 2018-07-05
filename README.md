# Setup SX Pro

layout on micro SD:

`/hbmenu.nro`

`/switch/WAINCartDumperNX.nro`

`/biskeydump.bin`

`/hekate_ctcaer_3.1.bin`

Boot into SX OS -> `Options` -> `Launch external payload` -> `biskeydump.bin`.

Write down `SBK` & `TSEC` keys.

Boot into SX OS -> `Options` -> `Launch external payload` -> `hekate_ctcaer_3.x.bin`.

Inside hekate first do `Tools` -> `Dump package1` after that `Tools` -> `Backup` -> `Backup eMMC BOOT0/1` and then `Tools` -> `Backup` -> `Backup eMMC SYS`.

Create a folder and put hactool, `keys.py`, BOOT0.bin (from sdcard/Backup/BOOT0), BCPKG2-1-Normal-Main.bin (from sdcard/Backup/Partitions/BCPKG2-1-Normal-Main) inside.

Run `keys.py` <SBK> <TSEC>, if everything worked you can continue with the extraction of the game binaries.

# Payloads overview

# hactool setup with SX Pro