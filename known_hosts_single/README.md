# `convert.py`

Split a monolithic OpenSSH `known_hosts` file into small per-host files.

This helper is useful when you want to use OpenSSH with a per-host `UserKnownHostsFile` path such as:

```sshconfig
Host *
    UserKnownHostsFile ~/.ssh/known_hosts_single/%h
```

For background, benchmarks, and a full migration walkthrough, see the online article:

<https://blog.famzah.net/2026/03/29/speed-up-ssh-connections-by-splitting-known_hosts-per-host/>

## What it does

`convert.py` reads host entries from standard input or from a file, looks them up in an existing monolithic `known_hosts` file with `ssh-keygen -F`, and writes the matching lines into separate files under `~/.ssh/known_hosts_single` by default.

## Why use it

With a large `known_hosts` file, every SSH connection has to consult the same monolithic file. Splitting it into one small file per host allows OpenSSH to read only the file for the current host when you use `UserKnownHostsFile ~/.ssh/known_hosts_single/%h`.

This keeps normal host key checking intact. It changes the file layout, not the trust model.

## Requirements

- Python 3
- `ssh-keygen` available in `PATH`
- an existing monolithic `known_hosts` file
- a plain-text host list if your current setup uses `HashKnownHosts yes`

## Usage

```bash
./convert.py \
  --known-hosts-file ~/.ssh/known_hosts.monolith \
  --input-file ./servers.list \
  --progress
```

The default values are:

- output directory: `~/.ssh/known_hosts_single`
- source file: `~/.ssh/known_hosts`
- input: standard input if `--input-file` is not provided

You can also see the built-in help:

```bash
./convert.py -h
```

## Suggested migration flow

If your existing SSH setup uses `HashKnownHosts yes`, you will usually need a plain-text list of all server names, because the monolithic `known_hosts` file no longer contains readable hostnames.

If `HashKnownHosts` was disabled, you can usually extract that list from the existing monolithic `known_hosts` file with a simple `cat` and `awk` pipeline.

Typical conversion flow:

```bash
mv ~/.ssh/known_hosts ~/.ssh/known_hosts.monolith
mkdir -p ~/.ssh/known_hosts_single

./convert.py \
  --known-hosts-file ~/.ssh/known_hosts.monolith \
  --input-file ./servers.list \
  --progress
```

Then update `~/.ssh/config`:

```sshconfig
Host *
    GlobalKnownHostsFile none
    UserKnownHostsFile ~/.ssh/known_hosts_single/%h
    HashKnownHosts no
    StrictHostKeyChecking yes
```

Notes:

- Keep `StrictHostKeyChecking yes` if you want normal host key verification.
- Use `GlobalKnownHostsFile none` only if your setup does not rely on a system-wide `known_hosts` file.
- `HashKnownHosts no` is usually the practical choice here, because the `%h` filename already exposes the host identity.

## Examples

Read hosts from a file:

```bash
./convert.py \
  --known-hosts-file ~/.ssh/known_hosts.monolith \
  --input-file ./servers.list \
  --progress
```

Read hosts from standard input:

```bash
printf '%s\n' example.com 203.0.113.10 | \
./convert.py \
  --known-hosts-file ~/.ssh/known_hosts.monolith \
  --progress
```

Custom-port host entry:

```bash
printf '%s\n' '[git.example.com]:7999' | \
./convert.py \
  --known-hosts-file ~/.ssh/known_hosts.monolith \
  --progress
```

Store the generated files in a custom directory:

```bash
./convert.py \
  --known-hosts-file ~/.ssh/known_hosts.monolith \
  --input-file ./servers.list \
  --dot-ssh-output-dir ~/.ssh/known_hosts_per_host
```

## How it works

For each input line, the script:

1. skips empty lines and comments
2. checks whether the entry is a hostname, IP address, or `[host]:port`
3. resolves hostnames to IP addresses
4. runs `ssh-keygen -F` against the monolithic `known_hosts` file for the original entry and for any resolved IPs
5. writes the matching output to one file per host or IP address

The default output file names are based on the hostname or IP address being stored.

## Notes and caveats

- If a hostname cannot be resolved, the script still tries to look up the original hostname in the monolithic `known_hosts` file. The DNS resolution error is printed to `stderr`.
- If `ssh-keygen -F` finds no match for an entry, the script does not create an output file for that entry.
- Existing per-host files for processed entries are overwritten.
- Custom-port entries such as `[host]:port` are supported.
- If you use multiple different custom ports for the same hostname and they have different host keys, review the current file naming strategy before relying on it unchanged.
