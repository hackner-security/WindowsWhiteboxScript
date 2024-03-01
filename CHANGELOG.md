
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

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
