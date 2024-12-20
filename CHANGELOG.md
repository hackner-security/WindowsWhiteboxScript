
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

## [3.7.2] - 2024-12-20

### Changed

* Hide progress bar used by certain cmdlets

### Added

* CLI arguments of running processes

## [3.7.1] - 2024-10-28

### Changed

* Refactoring, adding comments and increased the verbosity of the script output

## [3.7] - 2024-08-28

### Added

* Second try for network capture in case the first one does not work
* Extract Windows build number

### Fixed

* Corrected registry value for the most recent patch of MSSQL

## [3.6] - 2024-06-19

### Added

* Check for Attack Surface Reduction (ASR) rules
* Check for MSSQL server version

### Fixed

* Correct registry values to check whether the configured WSUS server is used

## [3.5] - 2024-04-05

### Fixed

* Prevent the prompt for enabling the winrm service if it is not running

## [3.4] - 2024-03-01

### Added

* PowerShell cmdlet ``Get-MpComputerStatus``
* Identifying print spooler settings (related to PrintNightmare)

## [3.3] - 2023-07-27

### Added

* Drivers are now checked from certain folders and their names and SHA256 hash are included in the result JSON file

## [3.2] -2023-05-22

### Added

* NFS client and server settings

### Fixed

* Check only running instances of MSSQL and make the registry settings check more error proof
* Changed ``Write-Information`` cmdlet to ``Write-Output`` to be backward compatible

## [3.1] - 2023-04-18

### Added

* Registry value check for Kernel DMA Protection
* Check for MSSQL connection settings

## [3.0] - 2023-03-09

### Added

* Open sourced version 3.0 of *WindowsWhiteboxScript.ps1*
