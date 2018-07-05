# Setup SX Pro (optional but nice to have!)

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

# Extracting application binary from .xci (version0 binary)

Create a folder with hactool , keys.txt (find it online or do steps above), `Decrypt-XCI-v2.1.bat`, target .xci inside.

Now simply run Decrypt-XCI-v2.1.bat and look for `xciDecrypted/exefs/main`.

# Downloading application updates

Extract CDNSP.zip.
- getting info `CDNSP.py -i <titleid>`
- downloading update `CDNSP.py -i <titleid>+0x800-<version>` (only add 0x800 if you use the base titleid)

# Extracting application binary from .nca (updated binary)

Download the patch with `CDNSP.py` and look for the biggest .nca file. I will use `v196608` for `0100000000010000`. Inside CDNSP/0100000000010000/0100000000010800/196608 you should see one folder and some .nca files:

```
04.07.2018  22:10         9.250.816 2675bb31701f9969ac16e646ec36a2ef.nca
04.07.2018  22:10    <DIR>          4138fdc0b8e1176d5df6e0f78ec7f8d5.cnmt
04.07.2018  22:10             5.632 4138fdc0b8e1176d5df6e0f78ec7f8d5.cnmt.nca
04.07.2018  22:12         9.289.728 72aab69399f18a10807bd5f2f171ffb9.nca
04.07.2018  22:12            49.152 8cc0092c0dceda57ea45f951ec798426.nca
04.07.2018  22:12           245.760 a2ad9245d40dc57e69c47b45cdb2cb47.nca
04.07.2018  22:10         1.120.768 acc9da939a8e0b339aa3be3d409d9ada.nca
04.07.2018  22:12        15.368.192 bc76593c02f86b1c4ec66969cc9b1ea5.nca
04.07.2018  22:10       281.985.024 c0628fb07a89e9050bda258f74868e8d.nca <------ choose this one
04.07.2018  22:11       132.513.792 c6d4f22aa6077b940a9ef196964a5bdc.nca
04.07.2018  22:12         1.163.264 cb71d988f456d2b84b865eb4ac72a46b.nca
04.07.2018  22:10           210.944 e374fa88b7cd3c688fb3e40b2d5589f1.nca
04.07.2018  22:12       134.299.648 e9bddc82a414f9c9b6de7146f40bdfc6.nca
```

Create a new folder with hactool, c0628fb07a89e9050bda258f74868e8d.nca, keys.txt and run the following command `hactool -tnca -k keys.txt --exefsdir=exeout --titlekey=(find your titlekey online) c0628fb07a89e9050bda258f74868e8d.nca`. Under `exeout` you will find the new `main`. Use it for the steps below.

# Loading main with IDA Pro
## Using loader

Download nxo64.py to `ida_path/loaders`, when loading the compressed `main` you will see this.

![main](https://raw.githubusercontent.com/Mila432/switch_rom_hacking/master/png/1.png)

## Uncompressing main (recommended)

Execute `nx2elf.exe main` and load `main.elf` with this settings.

![main](https://raw.githubusercontent.com/Mila432/switch_rom_hacking/master/png/2.png)

## Saving changes

After modifying the file to your liking, there are some steps required to create a working main again.
If you used the recommended method simply run `elf2nso.exe main.elf newmain`.
Otherwise execute `nx2elf.exe main`, apply your patches and finally `elf2nso.exe main.elf newmain`.

# Using moded main

Move your new `main` to `sdcard/sxos/titles/<titleid>/exefs/main`.