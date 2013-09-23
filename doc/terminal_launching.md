# Terminal Launching

Hackers do things in terminals. GUIs are for suckers!

Kvasir allows launching 'scripted terminals' and sets some environment
variables to keep you from attacking the wrong host.

## Operating Systems supported

Terminal launches have been successfully tested in Linux and OS X. There's
no reason why Windows shouldn't work with the correct command.

## Scheduler setup

In order for launches to work the web2py scheduler must be running. Tasks
are grouped by logical hostname so the use of centralized database does not
launch on other systems.

## Profile setup

The command which launches a terminal is configured in each user's profile.
Profiles are configured at http://localhost:8000/kvasir/default/user/profile

## Environment Variables

The following variables are translated from the profile into environment
variables:

* _IP_ - Target IP Address
* _DATADIR_ - The data directory location in Kvasir
* _LOGFILE_ - A logfile name for the "script" command in data/session-logs

## Terminal commands

You can use whatever terminal you fancy: xterm, gnome-terminal, Eterm, aterm,
Terminal, iTerm, etc. Here are some ideas:

### Xterm (default):

xterm -sb -sl 1500 -vb -T 'manual hacking: _IP_' -n 'manual hacking: _IP_' -e script _LOGFILE_

### OS X Terminal script

osascript ../private/terminal.scpt _IP_ _DATADIR_ _LOGFILE_

