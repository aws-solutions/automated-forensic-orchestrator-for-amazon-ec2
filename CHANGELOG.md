# Automated Forensics for Amazon EC2 Release Changelog

## [1.2.1] - 2023-07-04

### Fixed
- Mitigated impact caused by new default settings for S3 Object Ownership (ACLs disabled) for all new S3 buckets.

## [1.2.0] - 2023-05-06

### Changed
- Red hat linux support, version 8.5
- Windows memory capture support for windows server 2016 and server 2019
- Update new profile building step functions
- Bug fixes for existing san sift images
- Improved logging 
- Improved customization for user defined ssm document.

## [1.1.0] - 2022-11-22

### Changed
- Invalid existing sts session credential after isolation
- Detach EIP from compromised instances
- Attempt isolation regardless memory acquisition result
- Instance isolation - profiles update
- Add EBS termination protection
- Enable termination protection for ec2 instance

## [1.0.0] - 2022-06-20

### Added

-   All files, initial version
