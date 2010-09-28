require 'mkmf'

unless have_library('ldap') && have_library('lber') && have_header('ldap.h') && have_header('lber.h')
  abort 'You need to have libldap and liblber installed.'
end

create_makefile('ldap')
