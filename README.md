# Solan

Tool for reading Microsoft Defender signature files.

Based on the excellent research @ [retooling.io](https://retooling.io/blog/an-unexpected-journey-into-microsoft-defenders-signature-world#:~:text=The%20signature%20database,-The%20MDA%20signatures&text=vdm%20files%3A,contains%20the%20anti-malware%20signatures) and [commial](https://github.com/commial/experiments/tree/master/windows-defender/VDM)

## Usage

`python -m solan <path to .vdm>`

The `.vdm` files are typically found in `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\<GUID>`

Example output:

```text
Loaded 305796 threats with 2223461 signatures.

2147910221 - AmsiBypass.CCHZ!MTB
[0x67: SIGNATURE_TYPE_STATIC
detection bytes: ca fc 87 30 15 99 12 ad be af 19 43 00 77 86 00 01 20 7b 19 d5 bf,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: ca fc 87 30 7f 10 6f df be af 19 43 9e de 85 00 01 20 68 4a 34 6d,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: 7e 18 99 3a d2 ba 97 06 c8 35 4d c8 30 f4 28 00 01 20 35 1c e5 c0,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: ad d2 46 52 ee ff e3 38 c7 9c e5 18 00 00 80 01 01 20 93 02 4f 2b,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: a2 6a 19 58 ee ff e3 38 02 9d d5 90 00 00 50 01 01 20 c6 98 22 5f,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: 5a f7 22 5c d1 c0 96 a3 05 b1 10 6a 00 50 57 00 01 20 ff 43 85 3f,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: f3 f8 aa 62 c2 31 8a d3 84 39 48 ed 00 7c 1d 00 01 20 77 b6 d9 31,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: fd 1f 3f 76 ae 2f ad 79 a8 cd 1f 1f 00 9a 1b 00 01 20 97 65 84 40,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: cd ed 52 79 79 eb 34 dc c4 88 16 81 00 bc 23 00 01 20 9d 16 7a 5d,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: 64 1c cf c2 e3 3e c4 10 71 af d5 6b 50 e7 1e 00 01 20 0a ea 73 f1,
 0x67: SIGNATURE_TYPE_STATIC
detection bytes: 33 96 f1 cd 42 fb 07 9a 56 86 87 5d 00 30 00 00 01 20 56 86 87 5d,
 0x78: SIGNATURE_TYPE_PEHSTR_EXT
detection_threshold: 23 - rule_count: 7
rules:
 weight: 10 rule: \x01amsi.dl
 weight: 10 rule: \x01AmsiScanBuffe
 weight: 10 rule: \x01YW1zaS5kbGw
 weight: 10 rule: \x01QW1zaVNjYW5CdWZmZXI
 weight: 1 rule: \x01D84F4C120005F1837DC65C04181F3DA9466B123FC369C359A301BABC1206157
 weight: 1 rule: \x01Patch Applie
 weight: 1 rule: \x01The number of processes in the system is less than 40. Exiting the progra
]
```
