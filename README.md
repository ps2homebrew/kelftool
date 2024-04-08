# kelftool

An open-source utility for decrypting, encrypting and signing PS2/PSX DESR KELF files.

## You need to bring your keys

Place them in your home directory (%USERPROFILE%) in the "PS2KEYS.dat" file as a 'KEY=HEX_VALUE' pair. Or place them in your working directory.

## Usage

    decrypt - decrypt and check the signature of kelf files
	encrypt <headerid> - encrypt and sign kelf files <headerid>: fmcb, fhdb, mbr
		fmcb - for retail PS2 memory cards
		fhdb - for retail PS2 HDD (HDD OSD / BB Navigator)
		mbr  - for retail PS2 HDD (mbr injection).
		       Note: for mbr, elf should load from 0x100000 and should be without headers:
		       readelf -h <input_elf> should show 0x100000 or 0x100008
headerless elf creation:

      $(EE_OBJCOPY) -O binary -v <input_elf> <headerless_elf>
examples:

	kelftool encrypt fhdb input.elf output.kelf
    kelftool decrypt input.kelf output.elf

*decrypt* command will also print useful information about kelf

## SHA256 Hashes of the keys

### THESE ARE HASHES, NOT THE ACTUAL KEYS

#### Retail

**MG_SIG_MASTER_KEY**=*e6e41172c069b752b9e88d31c70606c580b1c15ee782abd83cf34117bfc47c91*
**MG_SIG_HASH_KEY**=*0dc3a1e225d3e701cfd07c2b25e7a3cc661ded10870218f1f22f936ba350bef5*
**MG_KBIT_MASTER_KEY**=*1512f3f196d6edb723e3c2f4258f6a937c4efd6441785b02d7c9ea7c817ad8fa*
**MG_KBIT_IV**=*14dfe8dbec477884c5eefceb215fa3910e33f4d371ddc125a16ac5ebc9c63a80*
**MG_KC_MASTER_KEY**=*7858c04eb5029d3e7e703ef46829279bfeaf30cb33bc13f54b7f78f0940905c1*
**MG_KC_IV**=*2fa98f860a4562ecb9aff64a79aaeff7c82099c83ca1e61320a9b05f50ca9170*
**MG_ROOTSIG_MASTER_KEY**=*27393c06331f5de238ea62a016f5b4428b11bd2c78d9f0e4bba3bc242a9a1bba*
**MG_ROOTSIG_HASH_KEY**=*5023ea32da5f595d15edf3aad08941dd96ae42a1ad32690a8ca35a024d758bd2*
**MG_CONTENT_TABLE_IV**=*3d9ac39d6e1b69b076da20a38593b2f4ccdd5f943b991c99eacbea13cb1cf0a4*
**MG_CONTENT_IV**=*4e3f5dfaf24c8016c60a23ced78af1e469522dbedb65ca7c8abfb990458f036b*

#### Arcade

Note: for arcade units (Namco System 246/256 and Konami Python 1) it is necessary to provide different keys and also additional keys: **OVERRIDE_KBIT** and **OVERRIDE_KC**

#### Dev and proto

For DTL units it is necessary to provide different keys (dev keystore). Proto keystore probably was never used.
