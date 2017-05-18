MPSSH.py executes an SSH command simultaneously on many hosts. The list of hosts is read from a file. You need to have a non-interactive authentication mechanism to the hosts, like Public key authentication or Kerberos.

Executing the same command in parallel saves time when you work with hundreds of hosts. The output of both STDOUT and STDERR, as well as the exit code from each host are displayed in a convenient way on the console.

You can see a sample output at the following page: https://github.com/famzah/mpssh-py/wiki/Sample-output-of-%22mpssh.py%22

MPSSH.py executes the standard "ssh" binary from the OpenSSH package and therefore has no other dependencies. You can control the settings (username, port, hostname) for each host by creating an entry in the "~/.ssh/config" file, as explained by the man page of "ssh_config(5)". You can also define global SSH connect settings in this config file like Connection timeout value, allowed SSH protocol, etc. Alternatively you can specify them as a command-line argument too.

The behavior of MPSSH.py can be altered by various command-line options.

MPSSH.py is a Python fork of the "mpssh" project, originally written in C. The motivation to rewrite it in Python is based on several factors:

1. New versions of MPSSH.py will be fully backward-compatible and new features will be available only by enabling them with a command-line argument.
2. Python is easier to maintain and practically not so slow when working with hundreds of hosts.
3. Python is very portable across UNIX platforms.
4. Unit tests make sure that backward-compatibility is kept and hopefully reduce bugs too.

Review the Wiki pages for more info.
