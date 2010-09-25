class LDAP
  def version=(version)
    set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, version)
  end
end