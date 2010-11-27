require 'mkmf'

unless have_library('ldap') && have_library('lber') && have_header('ldap.h') && have_header('lber.h')
  abort 'You need to have libldap and liblber installed.'
end

have_func('ldap_sasl_interactive_bind_s')
have_header('sasl.h') || have_header('sasl/sasl.h')

create_makefile('ldap')
