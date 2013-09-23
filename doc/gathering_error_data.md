# Gathering Error Data

Sometimes (well, a lot of the time) errors are introduced into Kvasir. While
this is unfortunate, dealing with errors can be difficult in a complex web
application such as this.

Thankfully web2py offers a fairly easy way to handle/review errors when they
happen within the python code.

## Localhost admin interface

When starting web2py a password is required to access the administration
interface (typically http://localhost:8000/admin). If your webserver is not
running over HTTPS you can only access the admin page through localhost,
otherwise anyone with the password will have access.

## Viewing error history

Any web2py captured errors are stored on disk by default. This can be changed
inside the db.py source.

The web2py admin interface provides a quick and easy way to view errors.

    http://localhost:8000/admin/default/errors/kvasir

## Submitting errors to Github

Be careful when sending error information to Github as it may contain
sensitive information (passwords, vulnerabilities, etc).

GPG Key ID 0x80F4E20A can be used to encrypt the file.

    -----BEGIN PGP PUBLIC KEY BLOCK-----
    Version: GnuPG v1.4.14 (Darwin)

    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
    7pozwgAbLHfRRAmu/oU=
    =APcG
    -----END PGP PUBLIC KEY BLOCK-----

