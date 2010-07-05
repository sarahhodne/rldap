require 'mkmf'

have_library('ldap')
have_library('lber')

have_header('ldap.h')
have_header('lber.h')

create_makefile('ldap')
