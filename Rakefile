desc "Push a new version to Gemcutter"
task :publish do
  require 'ldap/version'

  sh "gem build rldap.gemspec"
  sh "gem push rldap-#{LDAP::Version}.gem"
  sh "git tag v#{LDAP::Version}"
  sh "git push origin --tags"
end

