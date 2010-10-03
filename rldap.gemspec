# -*- encoding: utf-8 -*-
require File.expand_path('../lib/ldap/version', __FILE__)

Gem::Specification.new do |s|
  s.name = 'rldap'
  s.version = LDAP::VERSION
  s.platform = Gem::Platform::RUBY
  s.date = Time.now.strftime('%Y-%m-%d')
  s.summary = 'Ruby LDAP wrapper'
  s.homepage = 'http://github.com/dvyjones/rldap'
  s.email = 'dvyjones@binaryhex.com'
  s.authors = [ 'Henrik Hodne' ]

  s.files = `git ls-files`.split("\n")
  s.executables = `git ls-files`.split("\n").map{|f| f =~ /^bin\/(.*)/ ? $1 : nil}.compact
  s.require_path = 'lib'
  
  s.extensions << 'ext/extconf.rb'
  
  s.add_development_dependency 'bundler', '>= 1.0.0'
end
