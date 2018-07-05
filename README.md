# Setup SX Pro

Layout for your microSD:

`/hbmenu.nro`

`/switch/WAINCartDumperNX.nro`

`/biskeydump.bin`

`/hekate_ctcaer_3.1.bin`

Boot into SX OS -> `Options` -> `Launch external payload` -> `biskeydump.bin`.

Write down `SBK` & `TSEC` keys.

Boot into SX OS -> `Options` -> `Launch external payload` -> `hekate_ctcaer_3.x.bin`.

Inside hekate first do `Tools` -> `Dump package1` after that `Tools` -> `Backup` -> `Backup eMMC BOOT0/1` and then `Tools` -> `Backup` -> `Backup eMMC SYS`.

Create a folder and put hactool, `keys.py`, BOOT0.bin (from sdcard/Backup/BOOT0), BCPKG2-1-Normal-Main.bin (from sdcard/Backup/Partitions/BCPKG2-1-Normal-Main) inside.

Run `keys.py` \<SBK\> \<TSEC\>, if everything worked you can continue with the extraction of the game binaries.

# Extracing application binary from .xci (version0 binary)

Create a folder with hactool , keys.txt (find it online or do steps above), `Decrypt-XCI-v2.1.bat`, target .xci inside. Now simply run Decrypt-XCI-v2.1.bat and look for `xciDecrypted/exefs/main`.

# Downloading application updates

Extract CDNSP.zip.
- getting info `CDNSP.py -i \<titleid\>`
- downloading update `CDNSP.py -i \<titleid\>-\<version\>`

# Loading main with IDA Pro
## Using loader

Download nxo64.py to `ida_path/loaders`
![main](https://raw.githubusercontent.com/Mila432/switch_rom_hacking/master/png/1.png)

## Uncompressing main (recommended)

Execute `nx2elf.exe main`.
![main](https://raw.githubusercontent.com/Mila432/switch_rom_hacking/master/png/2.png)


# Payloads overview

# hactool setup with SX Pro