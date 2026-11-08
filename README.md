<div align="center">

# Heaven's Night

### A Digital Forensics and Malware Analysis Investigation

![Status](https://img.shields.io/badge/status-active%20investigation-orange)
![Focus](https://img.shields.io/badge/focus-malware%20analysis-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2011-0078D6)
![Framework](https://img.shields.io/badge/framework-Ren'Py%208.1.3-lightgrey)
![Family](https://img.shields.io/badge/malware%20family-unconfirmed-red)

**Incident Response • Malware Analysis • Threat Intelligence • Static Analysis • Reverse Engineering**

</div>

> [!WARNING]
> **Research Notice**
>
> This investigation is ongoing. The findings documented here reflect evidence collected and analyzed so far. Certain behaviors and relationships remain unverified, and conclusions may change as additional artifacts are examined.
>
> **No malware family, confirmed infostealer activity, or complete infection chain has been conclusively established.**

---

## Table of Contents

- [Overview](#overview)
- [Research Objectives](#research-objectives)
- [1. Initial Incident and Evidence](#1-initial-incident-and-evidence)
- [2. Primary Sample: Setup.exe](#2-primary-sample-setupexe)
- [3. Portable Executable Analysis](#3-portable-executable-analysis)
- [4. VirusTotal Threat Intelligence](#4-virustotal-threat-intelligence)
- [5. Network and Behavioral Observations](#5-network-and-behavioral-observations)
- [6. Examination of the Associated ZIP Archive](#6-examination-of-the-associated-zip-archive)
- [7. Suspicious and Unidentified Application Resources](#7-suspicious-and-unidentified-application-resources)
- [8. Ren'Py Execution Log Analysis](#8-renpy-execution-log-analysis)
- [9. Current Findings and Assessment](#9-current-findings-and-assessment)
- [10. Research Roadmap](#10-research-roadmap)
- [11. Tools and Methodology](#11-tools-and-methodology)
- [12. Limitations](#12-limitations)
- [13. References and Further Reading](#13-references-and-further-reading)
- [Research Ethics and Disclosure](#research-ethics-and-disclosure)
- [Project Status](#project-status)

---

## Overview

Heaven's Night is an ongoing digital forensics and malware analysis investigation originating from a suspected malware infection on a Windows 11 computer.

The case began when I was contacted by a friend regarding an individual whose computer had reportedly been infected. I was provided with a Malwarebytes scan report and several potentially suspicious files for investigation.

The initial suspicion was that the infection originated from a malicious Minecraft `.jar` mod. However, preliminary open-source intelligence (OSINT) and antivirus analysis shifted my attention toward another file identified during the scan: `Setup.exe`.

The executable was found inside a directory named:

```text
RT809H_Software_Free_Download_Archive_win_7552
```

Further research revealed that the detected executable shares characteristics with a legitimate launcher for the Ren'Py Visual Novel Engine, a framework commonly used to develop visual novels and other interactive applications.

This raised an important question:

> **Could a legitimate application launcher be used to execute malicious code stored elsewhere in a software package?**

To investigate this possibility, I began examining the executable's VirusTotal relationships, Portable Executable (PE) structure, behavioral indicators, and a subsequently obtained ZIP archive containing Ren'Py application resources.

The investigation has since expanded into examining compiled Ren'Py scripts, unusual binary resources, application initialization logs, and potential relationships between the archive and other files detected on the affected system.

This repository documents my methodology, evidence, observations, hypotheses, and continuing research.

## Research Objectives

The primary objectives of this investigation are to:

1. Determine whether the suspicious software package contains malicious functionality.
2. Understand the role of `Setup.exe` and its relationship to the Ren'Py application framework.
3. Identify and analyze potentially suspicious files embedded within the associated archive.
4. Investigate whether the application retrieves, extracts, or executes additional payloads.
5. Examine potential relationships between the software package and the victim's other Malwarebytes detections.
6. Reconstruct a possible infection chain using verifiable evidence.
7. Document reproducible findings, limitations, and defensive indicators.

The long-term objective is to produce a comprehensive technical case study supported by static analysis, forensic artifacts, and, where possible, controlled behavioral analysis.

---

## 1. Initial Incident and Evidence

### Affected System

The initial source of evidence was a Malwarebytes Threat Scan report generated on November 4, 2026.

| Property | Value |
|---|---|
| Operating System | Windows 11 |
| Build | 26200.9711 |
| Architecture | x64 |
| File System | NTFS |
| Malwarebytes Version | 5.7.3.376 |
| Scan Type | Threat Scan |
| Objects Scanned | 222,143 |
| Threats Detected | 4 |
| Threats Quarantined | 4 |
| Scan Duration | 5 minutes, 38 seconds |

### Detected Files

The Malwarebytes report identified four suspicious files, all of which were reported as quarantined.

| Detection | Filename | SHA-256 |
|---|---|---|
| Trojan.Crypt | `ETWPROVIDERS.DLL` | `c3839787f93f90b92f2718981318a1dda1b8a3492dd42c53693afc1b45cdbafe` |
| RiskWare.Agent | `ULTIMMC.EXE` | `3f34eca2f805d2a83904357ab156ec8a2fc7c82ec254930220d31c7e0a752d39` |
| RiskWare.Agent | `A Minecraft Launcher.lnk` | `5cfa51c7dd3819d53c75c3a5dbf411612f6ad69dd7823cd3d0f7ef5ba8dee94a` |
| Generic.Malware/Suspicious | `SETUP.EXE` | `7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab` |

The scan did not identify malicious running processes, loaded modules, registry entries, or WMI objects at the time of scanning.

> [!NOTE]
> This does not rule out prior execution or malicious activity that may have occurred before the scan.

### Initial Investigative Direction

The presence of a Minecraft launcher initially suggested that the infection might have originated from a malicious Minecraft mod or unofficial launcher.

However, there was insufficient evidence to establish that connection.

During further investigation, `SETUP.EXE` became the primary focus due to its VirusTotal relationships and association with multiple suspicious software packages.

A separate hypothesis involving an infostealer and a cryptocurrency scam was also considered. That connection remains unverified and is not treated as a confirmed finding.

---

## 2. Primary Sample: Setup.exe

**SHA-256**

```text
7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab
```

[View sample on VirusTotal](https://www.virustotal.com/gui/file/7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab)

### File Identification

According to the VirusTotal metadata examined during the investigation, the executable appears consistent with a standard Ren'Py launcher.

| Property | Value |
|---|---|
| Filename | `Setup.exe` |
| File Type | Windows PE executable |
| Architecture | x86-64 |
| Magic | PE32+ executable (GUI) |
| Size | 104,448 bytes |
| Magika | PEBIN |
| Detect It Easy | PE64, Microsoft Linker 14.0 |
| Compilation Timestamp | September 19, 2023 |

VirusTotal's behavioral description also referenced MinGW-w64, while Detect It Easy reported Microsoft Linker 14.0.

This discrepancy has not been independently resolved.

### File Hashes

| Type | Value |
|---|---|
| MD5 | `0323998e0e85eca5fd90d9f8ecbbd6c2` |
| SHA-1 | `56dc080f728d7a276495d6a4371670f9ea71519b` |
| SHA-256 | `7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab` |
| Imphash | `a9563ca2ee659a9314820bead4ec962b` |

These identifiers refer to the specific executable examined through VirusTotal, not the complete ZIP archive obtained later.

### Antivirus Detection Results

At the time of the initial investigation, VirusTotal reported a detection ratio of **1/71**, with Malwarebytes being the only antivirus vendor flagging the executable.

The reported community score was −63.

Interestingly, despite the low detection ratio, the executable appeared in numerous relationships with other files, including software packages with substantially higher antivirus detection counts.

One possible explanation is that this executable is a reusable, legitimate Ren'Py launcher distributed alongside different application scripts and resources.

In that scenario, malicious functionality could exist in files loaded by the application rather than within the launcher executable itself.

> [!IMPORTANT]
> The low detection ratio does not establish that the executable is safe, and suspicious file relationships do not independently establish that it is malicious.

---

## 3. Portable Executable Analysis

VirusTotal provided information about the executable's PE structure, imports, and initialization behavior.

### PE Sections

| Section | Virtual Address | Virtual Size | Raw Size | Entropy |
|---|---:|---:|---:|---:|
| `.text` | 4096 | 7302 | 7680 | 5.78 |
| `.rdata` | 12288 | 4428 | 4608 | 4.35 |
| `.buildid` | 20480 | 53 | 512 | 0.60 |
| `.data` | 24576 | 444 | 512 | 1.43 |
| `.pdata` | 28672 | 396 | 512 | 3.12 |
| `.tls` | 32768 | 16 | 512 | 0.00 |
| `.rsrc` | 36864 | 88888 | 89088 | 7.72 |

The `.rsrc` section occupies a large portion of the executable and has a reported entropy of 7.72.

High entropy can sometimes indicate compression or encryption, but it is also common in legitimate embedded resources.

VirusTotal identified four icon resources and one icon group, which could explain much of the resource section's size.

No conclusion about malicious packing or encryption can be made from this section's entropy alone.

### Observed Initialization Behavior

VirusTotal's behavioral information described several operations associated with the executable.

**Windows Version Identification**

The application checks the Windows operating system version, consistent with common compatibility checks.

**DLL Search Path Configuration**

The executable uses `SetDllDirectoryW` to configure the Windows DLL search path.

Although DLL search behavior can be abused, this operation is also common in legitimate applications.

**Dynamic Loading of `librenpython.dll`**

The executable loads `librenpython.dll` and invokes `launcher_main_wide`.

This behavior is consistent with Ren'Py initializing its Python runtime.

**Memory Operations**

The application also uses:

- `VirtualProtect`
- `VirtualQuery`
- `SetUnhandledExceptionFilter`

These APIs can appear in malicious software, but they are also used for legitimate runtime initialization, memory management, and exception handling.

The evidence reviewed so far does not establish malicious use of these APIs.

### Initial Assessment

The executable's observed behavior is consistent with a Ren'Py launcher.

This suggests that investigation of the surrounding application files may be more productive than treating the executable as an independently malicious program.

---

## 4. VirusTotal Threat Intelligence

### Submission History

| Event | Date (UTC) |
|---|---|
| Compilation Timestamp | 2023-09-19 02:30:08 |
| First Submission | 2023-09-19 03:52:17 |
| First Seen in the Wild | 2023-12-12 14:31:05 |
| Last Analysis Observed | 2026-11-05 01:27:11 |
| Last Submission Observed | 2026-11-05 01:44:20 |

The executable has appeared in VirusTotal records under multiple filenames.

Examples include:

- `Setup.exe`
- `Setup[1].exe`
- `Setup-1.exe`
- `Setup-2.exe`
- `executable.exe`
- `renpy.exe`
- `Setup.exe.disabled`

Other filenames were associated with various software packages, including pirated and adult-oriented applications. Those titles have been omitted.

Because the SHA-256 hash is identical, the different filenames represent the same executable content.

This supports the observation that the Ren'Py launcher may be reused across unrelated applications.

### Execution-Parent and Archive Relationships

VirusTotal displayed more than 20,000 relationships categorized as execution parents for this executable.

Numerous related files appeared suspicious based on their detection counts.

Several compressed packages containing the executable also had comparatively high antivirus detection ratios.

Examples from the investigation include:

| Archive | Reported Detection Ratio |
|---|---:|
| `Free Downloaded Files.zip` | 27/66 |
| `Free Download Files.zip` | 26/68 |
| `Free Downloaded Files (2).zip` | 24/67 |
| `File Download (2).zip` | 35/69 |
| `setup_game_474.zip` | 9/68 |

These relationships are useful investigative leads.

However, they do not establish that all related packages are malicious, that they belong to the same campaign, or that the launcher executable caused the suspicious activity.

The individual surrounding files must be examined to identify where malicious behavior, if present, actually originates.

---

## 5. Network and Behavioral Observations

VirusTotal provided several network-related observations associated with the executable's sandbox reports.

### Reported Domains

The reviewed results included domains associated with Microsoft services, Akamai infrastructure, and certificate-related services.

Examples:

- `assets.msn.com`
- `crt.sectigo.com`
- `query.prod.cms.rt.microsoft.com`
- `www.microsoft.com`
- `a1666.dscr.akamai.net`

### Reported IP Addresses

The reviewed results also included multiple addresses associated with AS20940, an Akamai autonomous system.

Examples include:

- `104.112.185.183`
- `104.80.88.154`
- `104.80.88.155`
- `104.86.182.56`
- `104.86.182.8`

One address, `104.86.182.8`, was flagged by one antivirus vendor in the reviewed results.

However, an isolated detection against a shared content delivery network address is insufficient to establish malicious infrastructure.

The available reports also do not clearly establish whether all network activity originated from `Setup.exe`, related processes, or the sandbox environment itself.

> [!NOTE]
> **No confirmed command-and-control destination or exfiltration endpoint has been identified.**

### Additional Behavioral Observations

VirusTotal reported `WerFault.exe` accessing another process's memory.

As WerFault is a legitimate Windows Error Reporting component, the observation could reflect normal crash diagnostics.

The available information does not establish malicious process access or a confirmed application crash.

### MITRE ATT&CK Classification

VirusTotal displayed several ATT&CK mappings, including:

| Technique | Description | Current Assessment |
|---|---|---|
| T1055 | Process Injection | Not confirmed |
| T1071 | Application Layer Protocol | Not confirmed as malicious C2 |
| T1113 | Screen Capture | Insufficient supporting detail |
| T1497 | Virtualization/Sandbox Evasion | Insufficient supporting detail |
| T1112 | Modify Registry | Insufficient supporting detail |
| T1082 | System Information Discovery | Requires further validation |
| T1057 | Process Discovery | Requires further validation |

Some classifications appeared to be based on generic executable characteristics or normal Windows operations.

For example, one process-injection mapping referenced the executable's `.tls` section.

The mere presence of a TLS section is not evidence of process injection.

These mappings are recorded as tool-generated observations rather than independently verified malicious techniques.

---

## 6. Examination of the Associated ZIP Archive

Following the initial VirusTotal analysis, I obtained an archive named:

```text
RT809H_Software_Free_Download_Archive_win_7552.zip
```

The archive was examined in an isolated Kali Linux virtual machine.

The primary objective was to identify additional application components that might explain the suspicious behavior associated with the Ren'Py launcher.

### Archive Inventory

Initial inspection was performed using:

```bash
unzip -l RT809H_Software_Free_Download_Archive_win_7552.zip
```

The archive contained:

| Property | Result |
|---|---|
| Entries | 1,529 |
| Total Uncompressed Size | 783,784,486 bytes |
| Application Framework | Ren'Py |
| Bundled Python Version | Python 3.9 |
| Primary Platform | Windows |

Several directories were consistent with a packaged Ren'Py application:

```text
RT809H_Software_Free_Download_Archive_win_7552/
├── data/
│   ├── cache/
│   ├── gui/
│   ├── saves/
│   ├── .OBo
│   ├── krqEV1NJShAY.y2
│   ├── libpython.rpmc
│   └── libwin.rpa
├── lib/
│   ├── py3-windows-x86_64/
│   ├── python3.9/
│   ├── python_x64.bin
│   └── python_x86.bin
├── renpy/
├── log.txt
└── setup.py
```

*This is a simplified directory structure highlighting relevant files, not a complete listing of all 1,529 entries.*

### Important Discrepancy: Missing Setup.exe

The original Malwarebytes report identified `SETUP.EXE` in a directory whose name corresponds to the ZIP examined during this investigation.

However, the ZIP's outer file listing contained no standalone `SETUP.EXE`.

Instead, it contained:

```text
setup.py
```

This is a Python script belonging to the Ren'Py application framework and is not equivalent to the Windows executable identified by Malwarebytes.

Several explanations remain possible, including an altered archive, a repackaged application, or differences between the supplied archive and the original extracted files.

None has been confirmed.

> [!IMPORTANT]
> This discrepancy prevents me from establishing that the supplied ZIP is an unchanged copy of the original software package.

### Preliminary setup.py Analysis

The first 120 lines of `setup.py` were inspected without executing the script.

```bash
unzip -p "$ZIP" "$ROOT/setup.py" | head -n 120
```

The inspected portion contained standard Ren'Py framework logic, including:

- `path_to_gamedir`
- `path_to_common`
- `path_to_saves`

No obviously malicious functionality was identified in the inspected portion.

However, the complete script and its interaction with other application resources have not yet been fully analyzed.

---

## 7. Suspicious and Unidentified Application Resources

The archive contained several files that warrant further investigation due to their names, extensions, sizes, or potential relationship to application initialization.

| File | Size (bytes) | Current Status |
|---|---:|---|
| `data/libpython.rpmc` | 339,738,624 | Uncharacterized |
| `data/krqEV1NJShAY.y2` | 2,050,982 | Header inspected |
| `data/libwin.rpa` | 146,626 | RPA 3.0 identified |
| `data/.OBo` | 364 | Header inspected |
| `lib/python_x64.bin` | 343,932,928 | Uncharacterized |
| `lib/python_x86.bin` | 38,797,312 | Uncharacterized |

File sizes and unusual extensions are not sufficient to establish maliciousness.

These files are being prioritized because their formats and relationships to the startup process have not yet been determined.

### 7.1 `libwin.rpa`

I performed a preliminary hexadecimal inspection:

```bash
unzip -p "$ZIP" "$ROOT/data/libwin.rpa" |
  head -c 64 | xxd
```

The file begins with the recognizable signature:

```text
RPA-3.0
```

The archive header also contains:

```text
Index Offset: 0x23946
Archive Key:  0x42424242
```

The strings `Made with Ren'Py` and `RENPY RPC2` were visible in the inspected data.

These observations identify a Ren'Py archive structure and suggest the presence of compiled script-related data.

The next objective is to enumerate the archive's internal contents and determine whether it contains the startup script referenced in the application's execution log.

The internal index has not yet been fully parsed.

### 7.2 `krqEV1NJShAY.y2`

This file is approximately 2.05 MB.

Its initial bytes were inspected using:

```bash
unzip -p "$ZIP" "$ROOT/data/krqEV1NJShAY.y2" |
  head -c 64 | xxd
```

The first bytes were:

```text
39 03 60 4f 43 6a 72 69 77 53 9c d8 01 16 60 cd
```

No immediately recognizable standard file signature was identified.

The file may use a custom format, compression, encryption, or another data representation.

Its purpose is currently unknown.

### 7.3 `.OBo`

The archive also contains a 364-byte file named:

```text
data/.OBo
```

The first bytes were inspected using:

```bash
unzip -p "$ZIP" "$ROOT/data/.OBo" |
  xxd -l 128
```

The content appears to consist of printable alphanumeric characters.

An example from the beginning:

```text
QxNWWlhUa1cORgxEX0oSfW4Df3lnWHNp
```

The visible character set is compatible with certain text encodings, including Base64-like encodings.

However, the file has not yet been decoded or identified, and its purpose remains unknown.

---

## 8. Ren'Py Execution Log Analysis

One of the more interesting discoveries was the presence of an application log inside the ZIP archive.

The file was examined using:

```bash
unzip -p "$ZIP" "$ROOT/log.txt" | head -n 100
```

### Execution Environment

The log begins with:

```text
Mon Nov  2 21:46:14 2026
Windows-10-10.0.26200
Ren'Py 8.1.3.23091805
```

This indicates that the packaged Ren'Py application was previously initialized in a Windows environment.

The reported build family is consistent with the affected computer's Windows build family.

However, the log has not been independently linked to the victim's device.

### Initialization and HTTP Response

The most relevant log entries were:

```text
Set script version to: None (alternate path)
<Response [503]>
 - Init at script.rpyc:313 took 2.24084 s.
Running init code. took 2.34s
```

These entries provide several investigative leads.

First, the log references initialization code associated with `script.rpyc`.

Second, it contains an HTTP response object reporting status 503, generally meaning that a server could not fulfill the request.

Third, the initialization operation took approximately 2.24 seconds.

This could suggest a network-related operation occurring during application initialization.

However, the log does not establish the destination, exact request, response contents, or purpose of the operation.

The application continued through additional initialization stages, including graphics initialization and interface creation.

This indicates that the application progressed beyond initial startup but does not prove successful malicious activity.

### Locating `script.rpyc`

The outer ZIP listing did not contain `script.rpyc` as a standalone file.

One possibility is that the compiled script is stored inside `libwin.rpa` or another application resource.

This has not yet been verified.

Recovering the relevant script is currently one of the highest priorities because it may help explain the initialization behavior observed in the log.

---

## 9. Current Findings and Assessment

### Confirmed Observations

The investigation has established the following observations:

- Malwarebytes detected and quarantined four file-based threats on the affected Windows 11 system.
- One detection involved a `Setup.exe` executable whose hash matches a widely encountered Ren'Py launcher.
- VirusTotal reported a low antivirus detection ratio for the executable despite numerous relationships with suspicious software packages.
- The executable's reported initialization behavior is consistent with a Ren'Py application launcher.
- A separately obtained ZIP archive contains 1,529 entries and recognizable Ren'Py application components.
- The ZIP examined does not contain the original standalone `SETUP.EXE`.
- `libwin.rpa` has a recognizable RPA 3.0 header.
- The `.y2` and `.OBo` files have been subjected to preliminary hexadecimal inspection but remain unidentified.
- An application log inside the ZIP records initialization on November 2, 2026, including an HTTP 503 response and a reference to `script.rpyc`.

### Working Hypotheses

**Hypothesis 1: Legitimate Launcher with Malicious Companion Files**

The detected executable may be a legitimate Ren'Py launcher distributed alongside malicious application scripts or additional resources.

**Hypothesis 2: Embedded or Encoded Application Payload**

One or more unidentified files inside the ZIP could contain encoded scripts, configuration data, or additional executable content.

**Hypothesis 3: Multistage Execution**

The application may retrieve or extract additional files during initialization. This possibility is being investigated through the Ren'Py log and packaged resources.

**Hypothesis 4: Relationship to `ETWPROVIDERS.DLL`**

The suspicious DLL identified by Malwarebytes may be related to a secondary stage of the software package.

No direct relationship has yet been established between the ZIP and the DLL.

> [!NOTE]
> These hypotheses are investigative directions, not confirmed conclusions.

### Current Assessment

The evidence suggests that examining the full Ren'Py application package is more valuable than relying on the launcher executable alone.

However, the original executable's absence from the obtained ZIP presents an important limitation.

There is currently insufficient evidence to establish that the supplied archive contains an infostealer, successfully executed a malicious payload, or caused the infection reported by Malwarebytes.

---

## 10. Research Roadmap

The investigation is actively ongoing.

### Completed

- [x] Review the original Malwarebytes scan report.
- [x] Identify and document detected file hashes.
- [x] Perform initial VirusTotal threat-intelligence research.
- [x] Examine the reported PE structure and imports.
- [x] Review reported network and sandbox behavior.
- [x] Identify suspicious file relationships.
- [x] Obtain and inventory the associated Ren'Py ZIP archive.
- [x] Identify the missing `SETUP.EXE` discrepancy.
- [x] Inspect the initial contents of `setup.py`.
- [x] Identify the `libwin.rpa` format.
- [x] Perform preliminary inspection of the `.y2` and `.OBo` files.
- [x] Analyze the supplied Ren'Py application log.

### In Progress / Planned

- [ ] Calculate and document the SHA-256 of the complete ZIP.
- [ ] Enumerate the internal contents of `libwin.rpa`.
- [ ] Locate and recover the compiled `script.rpyc` code.
- [ ] Analyze startup logic associated with the logged initialization event.
- [ ] Determine the formats and purposes of `.OBo`, `.y2`, and `.rpmc`.
- [ ] Investigate additional suspicious Python files reported through threat intelligence.
- [ ] Examine whether the application retrieves or extracts additional payloads.
- [ ] Investigate the relationship with `ETWPROVIDERS.DLL`.
- [ ] Perform controlled dynamic analysis if a suitable executable package is available.
- [ ] Reconstruct an evidence-supported execution or infection chain.
- [ ] Develop defensive indicators or detection rules if malicious behavior is confirmed.
- [ ] Publish final findings and limitations.

Completing these tasks does not guarantee that a malware family or complete infection chain will be identified. Negative findings and unresolved relationships will also be documented.

---

## 11. Tools and Methodology

Tools and sources used so far include:

| Tool / Source | Purpose |
|---|---|
| Malwarebytes | Initial incident evidence |
| VirusTotal | File reputation, relationships, behavioral reports |
| Kali Linux | Isolated static-analysis environment |
| `unzip` | Archive enumeration and file inspection |
| `xxd` | Hexadecimal inspection |
| SHA-256 | File identification and integrity verification |
| Ren'Py format analysis | Investigation of application resources |

Additional tooling may include Ghidra, Python bytecode analysis utilities, YARA, and Windows sandbox monitoring where applicable.

The investigation follows an evidence-first approach.

Findings are separated into confirmed observations, hypotheses, and unresolved questions. Automated detection labels and ATT&CK classifications are not treated as proof of malicious behavior without supporting evidence.

Potentially malicious files are inspected using isolated environments, and untrusted scripts or executable resources are not intentionally run on the host computer.

---

## 12. Limitations

This project is still in progress, and several limitations remain:

- The original suspicious Minecraft `.jar` has not been obtained.
- The standalone `SETUP.EXE` is absent from the supplied ZIP.
- The ZIP's provenance and relationship to the original quarantined executable have not been fully verified.
- The complete archive has not yet been reverse-engineered.
- The compiled startup script has not been recovered.
- Several application data files remain unidentified.
- No full process tree or network capture from execution of the complete package has been obtained.
- No confirmed malicious command-and-control endpoint has been identified.
- The Ren'Py application log has not been conclusively linked to the affected computer.
- The relationship between the suspicious DLL, the Minecraft launcher, and the Ren'Py application remains unresolved.

As new evidence becomes available, the analysis and conclusions will be updated.

---

## 13. References and Further Reading

### Primary Investigation Sources

- [VirusTotal — Setup.exe](https://www.virustotal.com/gui/file/7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab)
- [VirusTotal — ETWPROVIDERS.DLL](https://www.virustotal.com/gui/file/c3839787f93f90b92f2718981318a1dda1b8a3492dd42c53693afc1b45cdbafe)
- [VirusTotal — ULTIMMC.EXE](https://www.virustotal.com/gui/file/3f34eca2f805d2a83904357ab156ec8a2fc7c82ec254930220d31c7e0a752d39)

### Related Research

These sources provide context for techniques involving Ren'Py applications and malicious software packages. They do not independently establish attribution for the sample investigated here.

- [Malwarebytes — Fake Games Spread Stealers with RenPy Loader, MSBuild and EtherHiding](https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-games-spread-stealers-with-renpy-loader-msbuild-and-etherhiding)
- [Dissecting a Multi-Stage Trojan Dropper — Xoel Rodríguez](https://xoelrdgz.github.io/writeups/renengine-lumma-static-analysis/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Ren'Py Documentation](https://www.renpy.org/doc/html/)

---

## Research Ethics and Disclosure

This investigation is conducted for educational, defensive security, and digital forensic research purposes.

Identifying information associated with the affected individual has been redacted.

The intent is to publish sanitized findings and reproducible analysis methods without distributing the affected individual's private data or live malware samples.

The presence of a file hash, domain, IP address, or application name in this repository does not automatically mean the associated resource is malicious.

---

## Project Status

**Work in Progress — November 2026**

This repository serves as a living technical record of the investigation.

Findings may be expanded, corrected, or revised as additional static-analysis results, execution evidence, and threat intelligence become available.

The immediate research priority is recovering and examining the compiled Ren'Py startup code to determine what the application actually does during initialization.

**Final attribution, payload functionality, and the complete infection chain remain undetermined.**
