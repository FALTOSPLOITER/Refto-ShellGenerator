# Refto-ShellGenerator Advanced Reverse Shell Generator
[![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)](https://github.com/FALTOSPLOITER/Refto-ShellGenerator.git)
[![Python](https://img.shields.io/badge/Python-3-blue.svg)](https://www.python.org/downloads/)

## Overview

**Refto-ShellGenerator** is a powerful and advanced reverse shell generator supporting multiple programming languages and shell variants. It is designed for penetration testers and security professionals to quickly generate reverse shell commands with encoding options and shell stabilization tips.


## Features

- **Multiple Shell Languages:** Supports Bash, Python, PHP, Perl, Powershell, Java, Golang, Socat, AWK, Lua, and more.
- **Shell Variants:** Provides various shell methods for bypassing different security controls.
- **Encoding Support:** Offers Base64 and URL encoding for payloads.
- **Shell Stabilization Tips:** Includes tips for stabilizing shells after exploitation.
- **Command Saving:** Ability to save generated commands to a file.
- **Color-Coded Output:** Enhances readability with colored output (can be disabled).
- **Raw Output Mode:** Outputs only the reverse shell command for easy scripting.
- **Comprehensive Help:** Detailed usage instructions and examples.

## Table of Contents

- [Usage](#usage)
- [Installation](#installation)
- [Examples](#examples)
  - [Basic Usage](#basic-usage)
  - [Advanced Usage](#advanced-usage)
- [Available Shells](#available-shells)
  - [Basic Shells](#basic-shells)
  - [Extended Shells](#extended-shells)
  - [Shell Variants](#shell-variants)
- [Shell Stabilization Tips](#shell-stabilization-tips)

## Usage

```bash
Usage:
  rshell <ip> <port> [options]       # Generate reverse shell
  rshell --list                      # List all available shells
  rshell --version                   # Show version information

Required Arguments:
  ip                           Target IP address (e.g., 192.168.1.10)
  port                         Target port number (1-65535)

Core Options:
  -h, --help                    Show this help message
  -v, --version                 Show version information
  --list                        List all available reverse shells
  --raw                         Output only the shell command without formatting
  --no-color                    Disable colored output

Shell Options:
  -l, --language <language>     Specify shell language (default: bash)
  --no-tips                     Disable shell stabilization tips

Output Options:
  -e, --encode <method>         Encode payload using specified method
                                Supported encodings: base64, url
  -s, --save <file>             Save output to specified file
```

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/FALTOSPLOITER/Refto-ShellGenerator.git
   ```

2. **Navigate to the Directory**

   ```bash
   cd Refto-ShellGenerator
   ```

3. **Make the Script Executable**

   ```bash
   chmod +x Refto-ShellGenerator
   ```

4. **Ensure Python 3 is Installed**

   Rshell requires Python 3 to run. You can check your Python version with:

   ```bash
   python3 --version
   ```

## Examples

### Basic Usage

Generate a basic Bash reverse shell:

```bash
./Refto 192.168.1.10 4444
```

Generate a Python reverse shell:

```bash
./Refto 10.0.0.1 9001 -l python
```

### Advanced Usage

Generate a Base64 encoded payload:

```bash
./Refto 192.168.1.10 4444 -e base64
```

Save the command to a file:

```bash
./Refto 192.168.1.10 4444 -s shell.txt
```

Output only the command without additional formatting:

```bash
./Refto 192.168.1.10 4444 --raw
```

Generate a PHP reverse shell without stabilization tips:

```bash
./Refto 192.168.1.10 4444 -l php --no-tips
```

## Available Shells

### Basic Shells

- **bash**: Basic bash TCP reverse shell
- **python**: Python socket-based reverse shell
- **php**: Standard PHP reverse shell (recommended)
- **perl**: Perl socket-based reverse shell
- **nc**: Netcat reverse shell with `-e` option
- **ruby**: Ruby socket-based reverse shell

### Extended Shells

- **powershell**: PowerShell reverse shell with stream handling
- **java**: Java runtime reverse shell
- **golang**: Go TCP reverse shell
- **socat**: Socat reverse shell
- **awk**: AWK reverse shell
- **lua**: Lua socket-based reverse shell

### Shell Variants

- **php-system**: PHP shell using `system()`
- **php-passthru**: PHP shell using `passthru()`
- **php-shell_exec**: PHP shell using `shell_exec()`
- **php-popen**: PHP shell using `popen()`
- **php-proc_open**: PHP shell using `proc_open()`
- **perl-pipe**: Perl reverse shell using pipe
- **perl-fork**: Perl reverse shell using fork
- **python-export**: Python reverse shell using environment variables
- **bash-196**: Bash reverse shell using file descriptor 196
- **nc-mkfifo**: Netcat reverse shell using named pipe
- **python-short**: Shortened Python reverse shell
- **bash-tcp**: Bash reverse shell using TCP
- **nc-e**: Netcat reverse shell with `-e` flag
- **nc-c**: Netcat reverse shell with `-c` flag
- **ruby-shell**: Ruby reverse shell with file descriptor
- **xterm**: X11 terminal reverse shell

Use `./Refto --list` to display all available shells directly from the tool.

## Shell Stabilization Tips

After obtaining a reverse shell, you may need to stabilize it for better interaction. Below are some tips for various shells.

### Python Shell Stabilization

**Basic Upgrade:**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

**Full TTY Upgrade Process:**

1. Spawn a TTY shell:

   ```bash
   python -c 'import pty; pty.spawn("/bin/bash")'
   ```

2. Set terminal type:

   ```bash
   export TERM=xterm
   ```

3. Background the shell:

   Press `Ctrl + Z`

4. Adjust terminal settings:

   ```bash
   stty raw -echo; fg
   ```

5. Reset the shell:

   ```bash
   reset
   ```

6. Resize terminal window:

   ```bash
   stty rows <num_rows> columns <num_columns>
   ```

### Bash Shell Stabilization

**Basic Upgrade:**

```bash
SHELL=/bin/bash script -q /dev/null
```

**Full TTY Upgrade Process:**

1. Start a new shell session:

   ```bash
   SHELL=/bin/bash script -q /dev/null
   ```

2. Set terminal type and size:

   ```bash
   export TERM=xterm
   stty rows <num_rows> columns <num_columns>
   ```

### Perl Shell Stabilization

**Basic Upgrade:**

```bash
perl -e 'exec "/bin/bash";'
```

**Full TTY Upgrade Process:**

1. Start a new shell session:

   ```bash
   perl -e 'exec "/bin/bash";'
   ```

2. Adjust terminal settings as with Bash.

**Author:** NITHIEN AACHINTHYA 
**GitHub:** [https://github.com/FALTOSPLOITER/](https://github.com/FALTOSPLOITER/)  
**Website:** [https://faltosploiter.github.io/](https://faltosploiter.github.io/)
