<div align="center">

# DecryptBinary

**A tool for decrypting iOS application binaries**


</div>

---

## Features

- List all running applications
- Decrypt application binaries with ease
- Create IPA files with decrypted binaries
- Target specific apps by bundle ID
- Support for both rootful and rootless jailbreaks

## Quick Start

### List Running Applications

```bash
decryptbinary -l
```

### Decrypt an Application

**Rootful Jailbreak:**
```bash
decryptbinary -d <bundle_id>
```

**Rootless Jailbreak:**
```bash
sudo decryptbinary -d <bundle_id>
```

### Create IPA File

Extract the entire app as an IPA file with decrypted binary:

**Rootful Jailbreak:**
```bash
decryptbinary -i <bundle_id>
```

**Rootless Jailbreak:**
```bash
sudo decryptbinary -i <bundle_id>
```

## Output Location

**Decrypted binaries:**
```
<app_data_directory>/Documents/<app_name>.decrypted
```

**IPA files (when using -i option):**
```
<app_data_directory>/Documents/<app_name>.ipa
```

## Requirements

### Runtime Requirements
- Jailbroken iOS device
  - **Rootful :** MobileSubstrate
  - **Rootless :** ElleKit
- **zip** (for IPA creation with `-i` option)

> **Note:** If you don't have the required packages installed, you can install them via terminal:
> ```bash
> # For Rootful (MobileSubstrate)
> apt install mobilesubstrate
> apt install zip
>
> # For Rootless (ElleKit)
> sudo apt install ellekit
> sudo apt install zip
> ```

### Build Requirements
- [Theos](https://theos.dev/) development environment

## Installation

### From Pre-built Package

**Rootful:**
```bash
dpkg -i com.merona.decryptbinary_*.deb
```

**Rootless:**
```bash
sudo dpkg -i com.merona.decryptbinary_*.deb
```

## Building from Source

**Rootful:**
```bash
make clean && make package
```

**Rootless:**
```bash
make clean && make package ROOTLESS=1
```
