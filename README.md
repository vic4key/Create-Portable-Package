# Create-Portable-Package
Create portable package for an executable file

### Features

- [x] Windows
- [x] Linux
- [ ] MacOS
- [x] CLI
- [ ] GUI

*Note: In-progress ... (if you like it, let join to get it done)*

### Installation

>git clone https://github.com/vic4key/Create-Portable-Package.git
>
>cd Create-Portable-Package

<details>
<summary>CLI Help</summary>

```
$ python -m Create-Portable-Package -h
usage: __main__.py [-h] (-f PE_FILE | -p PE_PID) [-d PACKAGE_DIRECTORY] [-e EXCLUSION_FILES] [-c CLEAN_UP]

Create Portable Package

options:
  -h, --help            show this help message and exit
  -f PE_FILE, --pe-file PE_FILE
                        The path of a specified executable file
  -p PE_PID, --pe-pid PE_PID
                        The pid of a specified executable file
  -d PACKAGE_DIRECTORY, --package-directory PACKAGE_DIRECTORY
                        The package directory
  -e EXCLUSION_FILES, --exclusion-files EXCLUSION_FILES
                        The exclusion files (separate by semicolon).
  -c CLEAN_UP, --clean-up CLEAN_UP
                        Clean-up before creating portable package
```
</details>


### Screenshots

![](screenshots/linux.png?)
