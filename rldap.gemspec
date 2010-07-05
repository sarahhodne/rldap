$LOAD_PATH.unshift 'lib'
require 'ldap/version'

Gem::Specification.new do |s|
  s.name = 'rldap'
  s.version = LDAP::Version
  s.date = Time.now.strftime('%Y-%m-%d')
  s.summary = 'Ruby LDAP wrapper'
  s.homepage = 'http://github.com/dvyjones/rldap'
  s.email = 'dvyjones@binaryhex.com'
  s.authors = [ 'Henrik Hodne' ]

  s.files  = %w( Rakefile LICENSE )
  s.files += Dir.glob('lib/**/*')
  s.files += Dir.glob('ext/**/*')

  s.extensions << 'ext/extconf.rb'
end
