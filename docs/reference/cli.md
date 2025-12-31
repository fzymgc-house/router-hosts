# CLI Reference

Command-line interface documentation for router-hosts.

!!! note "Auto-generated"
    This documentation is auto-generated from `router-hosts --help`.

## Global Usage

```
Router hosts file management CLI

Usage: router-hosts [OPTIONS] <COMMAND>

Commands:
  host      Manage host entries
  snapshot  Manage snapshots
  config    Show effective configuration
  help      Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>  Path to config file
  -s, --server <SERVER>  Server address (host:port)
      --cert <CERT>      Client certificate path
      --key <KEY>        Client key path
      --ca <CA>          CA certificate path
  -v, --verbose          Verbose output
  -q, --quiet            Suppress non-error output
      --format <FORMAT>  Output format [default: table] [possible values: table, json, csv]
      --non-interactive  Non-interactive mode: fail immediately on conflicts without prompting
  -h, --help             Print help
  -V, --version          Print version
```

## host

```
Manage host entries

Usage: router-hosts host [OPTIONS] <COMMAND>

Commands:
  add     Add a new host entry
  get     Get a host entry by ID
  update  Update an existing host entry
  delete  Delete a host entry
  list    List all host entries
  search  Search host entries
  import  Import hosts from file
  export  Export hosts to stdout
  help    Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>  Path to config file
  -s, --server <SERVER>  Server address (host:port)
      --cert <CERT>      Client certificate path
      --key <KEY>        Client key path
      --ca <CA>          CA certificate path
  -v, --verbose          Verbose output
  -q, --quiet            Suppress non-error output
      --format <FORMAT>  Output format [default: table] [possible values: table, json, csv]
      --non-interactive  Non-interactive mode: fail immediately on conflicts without prompting
  -h, --help             Print help
```

## snapshot

```
Manage snapshots

Usage: router-hosts snapshot [OPTIONS] <COMMAND>

Commands:
  create    Create a new snapshot
  list      List all snapshots
  rollback  Rollback to a snapshot
  delete    Delete a snapshot
  help      Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>  Path to config file
  -s, --server <SERVER>  Server address (host:port)
      --cert <CERT>      Client certificate path
      --key <KEY>        Client key path
      --ca <CA>          CA certificate path
  -v, --verbose          Verbose output
  -q, --quiet            Suppress non-error output
      --format <FORMAT>  Output format [default: table] [possible values: table, json, csv]
      --non-interactive  Non-interactive mode: fail immediately on conflicts without prompting
  -h, --help             Print help
```

## config

```
Show effective configuration

Usage: router-hosts config [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to config file
  -s, --server <SERVER>  Server address (host:port)
      --cert <CERT>      Client certificate path
      --key <KEY>        Client key path
      --ca <CA>          CA certificate path
  -v, --verbose          Verbose output
  -q, --quiet            Suppress non-error output
      --format <FORMAT>  Output format [default: table] [possible values: table, json, csv]
      --non-interactive  Non-interactive mode: fail immediately on conflicts without prompting
  -h, --help             Print help
```

## help

```
error: unrecognized subcommand '--help'

Usage: router-hosts [OPTIONS] <COMMAND>

For more information, try '--help'.
Error getting help for help
```
