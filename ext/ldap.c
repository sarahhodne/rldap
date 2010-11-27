#include <ruby.h>
#ifndef RSTRING_PTR
#define RSTRING_PTR(str) RSTRING(str)->ptr
#endif
#ifndef RSTRING_LEN
#define RSTRING_LEN(str) RSTRING(str)->len
#endif

#include <ldap.h>
#include <lber.h>
#include <stdlib.h>

#ifdef HAVE_SASL_H
#include <sasl.h>
#elif defined(HAVE_SASL_SASL_H)
#include <sasl/sasl.h>
#endif

static VALUE cLDAP;
static VALUE cLDAP_Message;
static VALUE eLDAP;

typedef struct {
	LDAP *ld;
} RLDAP_WRAP;

static RLDAP_WRAP *get_wrapper(VALUE obj)
{
	RLDAP_WRAP *wrapper;
	Data_Get_Struct(obj, RLDAP_WRAP, wrapper);
	return wrapper;
}

static void free_wrapper(RLDAP_WRAP *wrapper)
{
	ldap_memfree(wrapper->ld);
	free(wrapper);
}

static void rldap_raise(int errno)
{
	VALUE e = rb_exc_new2(eLDAP, ldap_err2string(errno));
	rb_iv_set(e, "@errno", INT2FIX(errno));
	rb_exc_raise(e);
}

static VALUE ldapmessage2obj(LDAP *ld, LDAPMessage *msg);

/* class LDAP */

static VALUE rldap_err2string(VALUE klass, VALUE rerrno)
{
	int errno;
	errno = FIX2INT(rerrno);
	return rb_str_new2(ldap_err2string(errno));
}

static VALUE rldap_alloc(VALUE klass)
{
	RLDAP_WRAP *wrapper;
	VALUE obj;

	obj = Data_Make_Struct(klass, RLDAP_WRAP, 0, free_wrapper, wrapper);

	return obj;
}

static VALUE rldap_initialize(int argc, VALUE *argv, VALUE obj)
{
	VALUE rhost, rport;
	char *host;
	int port;
	RLDAP_WRAP *wrapper;

	rb_scan_args(argc, argv, "11", &rhost, &rport);

	if (NIL_P(rport))
		rport = INT2FIX(LDAP_PORT);

	wrapper = get_wrapper(obj);
	host = StringValuePtr(rhost);
	port = FIX2INT(rport);

	wrapper->ld = (LDAP *)ldap_init(host, port);

	return obj;
}

static VALUE rldap_start_tls(VALUE obj)
{
	RLDAP_WRAP *wrapper;
	int retval;

	wrapper = get_wrapper(obj);
	retval = ldap_start_tls_s(wrapper->ld, NULL, NULL);
	if (retval == LDAP_SUCCESS)
		return Qtrue;
	else
		rldap_raise(retval);
}

static VALUE rldap_search(int argc, VALUE *argv, VALUE obj)
{
	RLDAP_WRAP *wrapper;
	char *base, *filter;
	int retval, count, i, scope;
	LDAPMessage *res, *msg;
	VALUE ary, rbase, rfilter, rscope;
	ID iscope;
	
	rb_scan_args(argc, argv, "21", &rbase, &rfilter, &rscope);

	switch(TYPE(rscope)) {
		case T_NIL:
			scope = LDAP_SCOPE_SUBTREE;
			break;
		case T_FIXNUM:
			scope = FIX2INT(rscope);
			break;
		case T_SYMBOL:
		case T_STRING:
			iscope = rb_to_id(rscope);
			if (iscope == rb_intern("subtree"))
				scope = LDAP_SCOPE_SUBTREE;
			if (iscope == rb_intern("base"))
				scope = LDAP_SCOPE_BASE;
			if (iscope == rb_intern("one"))
				scope = LDAP_SCOPE_ONE;
			break;
		default:
			rb_raise(rb_eTypeError, "not a valid scope");
			break;
	}
	
	wrapper = get_wrapper(obj);
	base = StringValuePtr(rbase);
	filter = StringValuePtr(rfilter);

	retval = ldap_search_ext_s(wrapper->ld, base, scope, filter, NULL, 0, NULL, NULL, NULL, 0, &res);

	if (retval != LDAP_SUCCESS)
		rldap_raise(retval);

	count = ldap_count_entries(wrapper->ld, res);
	
	if (count == -1) {
		int errno;
		ldap_get_option(wrapper->ld, LDAP_OPT_RESULT_CODE, &errno);
		rldap_raise(errno);
	}
	
	ary = rb_ary_new2((long)count);
	
	msg = ldap_first_entry(wrapper->ld, res);
	
	for (i=0; i<count; i++) {
		rb_ary_store(ary, (long)i, ldapmessage2obj(wrapper->ld, msg));
		msg = ldap_next_entry(wrapper->ld, msg);
	}
	
	return ary;
}

static VALUE rldap_set_option(VALUE obj, VALUE roption, VALUE rvalue)
{
	RLDAP_WRAP *wrapper;
	int retval;
	int option;
	int ival;
	char *sval;
	void *val;
	
	wrapper = get_wrapper(obj);
	option = FIX2INT(roption);
	
	if (TYPE(rvalue) == T_STRING) {
		sval = StringValuePtr(rvalue);
		val = &sval;
	} else {
		ival = FIX2INT(rvalue);
		val = &ival;
	}
	
	retval = ldap_set_option(wrapper->ld, option, val);
	
	if (retval == LDAP_OPT_SUCCESS)
		return Qtrue;
	else
		return Qfalse;
}

static VALUE rldap_set_version(VALUE obj, VALUE version)
{
	return rldap_set_option(obj, INT2FIX(LDAP_OPT_PROTOCOL_VERSION), version);
}

int rldap_errno_c(VALUE obj)
{
	RLDAP_WRAP *wrapper;
	int errno;

	wrapper = get_wrapper(obj);
	ldap_get_option(wrapper->ld, LDAP_OPT_RESULT_CODE, &errno);
	return errno;
}

static VALUE rldap_errno(VALUE obj)
{
	return INT2NUM(rldap_errno_c(obj));
}

static VALUE rldap_uri(VALUE obj)
{
	RLDAP_WRAP *wrapper;
	char *uri;
	VALUE ruri;
	
	wrapper = get_wrapper(obj);
	ldap_get_option(wrapper->ld, LDAP_OPT_URI, &uri);
	
	return rb_str_new2(uri);
}

static VALUE rldap_inspect(VALUE obj)
{
	VALUE ruri, ret;
	
	ruri = rb_funcall(rldap_uri(obj), rb_intern("dump"), 0);
	ret = rb_str_new2("#<LDAP @uri=");
	rb_str_cat2(ret, StringValuePtr(ruri));
	rb_str_cat2(ret, ">");
	
	return ret;
}

static VALUE rldap_bind(int argc, VALUE *argv, VALUE obj)
{
	RLDAP_WRAP *wrapper;
	char *bind_dn = NULL, *bind_password = NULL;
	int retval;
	VALUE rdn, rpassword;
	
	rb_scan_args(argc, argv, "02", &rdn, &rpassword);
	
	if (NIL_P(rdn))
		bind_dn = NULL;
	else
		bind_dn = StringValuePtr(rdn);
	if (NIL_P(rpassword))
		bind_password = NULL;
	else
		bind_password = StringValuePtr(rpassword);
	
	wrapper = get_wrapper(obj);

	retval = ldap_bind_s(wrapper->ld, bind_dn, bind_password, LDAP_AUTH_SIMPLE);
	
	if (retval != LDAP_SUCCESS)
		rldap_raise(retval);
	else
		return Qtrue;
}

static VALUE rldap_unbind(VALUE obj)
{
	RLDAP_WRAP *wrapper;
	int retval;
	
	wrapper = get_wrapper(obj);
	retval = ldap_unbind_s(wrapper->ld);
	if (retval != LDAP_SUCCESS)
		rldap_raise(retval);
	else
		return Qtrue;
}

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S

typedef struct {
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
} RLDAP_BICTX;

static RLDAP_BICTX *_rldap_sasl_setdefs(LDAP *ld, char *sasl_mech, char *sasl_realm, char *sasl_authc_id, char *passwd, char *sasl_authz_id)
{
	RLDAP_BICTX *ctx;
	
	ctx = ber_memalloc(sizeof(RLDAP_BICTX));	
	ctx->mech    = (sasl_mech) ? ber_strdup(sasl_mech) : NULL;
	ctx->realm   = (sasl_realm) ? ber_strdup(sasl_realm) : NULL;
	ctx->authcid = (sasl_authc_id) ? ber_strdup(sasl_authc_id) : NULL;
	ctx->passwd  = (passwd) ? ber_strdup(passwd) : NULL;
	ctx->authzid = (sasl_authz_id) ? ber_strdup(sasl_authz_id) : NULL;

	if (ctx->mech == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_MECH, &ctx->mech);
	}
	if (ctx->realm == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_REALM, &ctx->realm);
	}
	if (ctx->authcid == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHCID, &ctx->authcid);
	}
	if (ctx->authzid == NULL) {
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHZID, &ctx->authzid);
	}

	return ctx;
}

static void _rldap_sasl_freedefs(RLDAP_BICTX *ctx)
{
	if (ctx->mech) ber_memfree(ctx->mech);
	if (ctx->realm) ber_memfree(ctx->realm);
	if (ctx->authcid) ber_memfree(ctx->authcid);
	if (ctx->passwd) ber_memfree(ctx->passwd);
	if (ctx->authzid) ber_memfree(ctx->authzid);
	ber_memfree(ctx);
}

static int _rldap_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in)
{
	sasl_interact_t *interact = in;
	const char *p;
	RLDAP_BICTX *ctx = defaults;

	for (;interact->id != SASL_CB_LIST_END;interact++) {
		p = interact->defresult;
		switch(interact->id) {
			case SASL_CB_GETREALM:
				p = ctx->realm;
				break;
			case SASL_CB_AUTHNAME:
				p = ctx->authcid;
				break;
			case SASL_CB_USER:
				p = ctx->authzid;
				break;
			case SASL_CB_PASS:
				p = ctx->passwd;
				break;
		}
		if (p) {
			interact->result = p;
			interact->len = strlen(p);
		}
	}
	return LDAP_SUCCESS;
}

static VALUE rldap_sasl_bind(int argc, VALUE *argv, VALUE obj)
{
	RLDAP_WRAP *wrapper;
	char *bind_dn = NULL, *passwd = NULL, *sasl_mech = NULL,
		*sasl_realm = NULL, *sasl_authz_id = NULL, *sasl_authc_id = NULL;
	VALUE rbind_dn, rpasswd, rsasl_mech, rsasl_realm,
		rsasl_authz_id, rsasl_authc_id, rprops;
	int retval;
	RLDAP_BICTX *ctx;
	
	wrapper = get_wrapper(obj);
	rb_scan_args(argc, argv, "07", &rbind_dn, &rpasswd, &rsasl_mech, &rsasl_realm, &rsasl_authz_id, &rsasl_authc_id, &rprops);
	
	if (!NIL_P(rprops))
		ldap_set_option(wrapper->ld, LDAP_OPT_X_SASL_SECPROPS, StringValuePtr(rprops));
	
	if (!NIL_P(rbind_dn))
		bind_dn = StringValuePtr(rbind_dn);
	if (!NIL_P(rpasswd))
		passwd = StringValuePtr(rpasswd);
	if (!NIL_P(rsasl_mech))
		sasl_mech = StringValuePtr(rsasl_mech);
	if (!NIL_P(rsasl_realm))
		sasl_realm = StringValuePtr(rsasl_realm);
	if (!NIL_P(rsasl_authz_id))
		sasl_authz_id = StringValuePtr(rsasl_authz_id);
	if (!NIL_P(rsasl_authc_id))
		sasl_authc_id = StringValuePtr(rsasl_authc_id);
	
	ctx = _rldap_sasl_setdefs(wrapper->ld, sasl_mech, sasl_realm, sasl_authc_id, passwd, sasl_authz_id);
	
	retval = ldap_sasl_interactive_bind_s(wrapper->ld, bind_dn, ctx->mech, NULL, NULL, LDAP_SASL_AUTOMATIC, _rldap_sasl_interact, ctx);
	
	_rldap_sasl_freedefs(ctx);
	
	if (retval != LDAP_SUCCESS)
		rldap_raise(retval);
	else
		return Qtrue;
}

#endif

/* class LDAP::Message */

static VALUE ldapmessage2obj(LDAP *ld, LDAPMessage *msg)
{
	VALUE obj;
	
	char *dn, *attr;
	BerElement *ber;
	BerValue **values;
	BerValue *value;
	VALUE rdn, attrs, ary, str;
	int length, i;

	obj = rb_class_new_instance(0, NULL, cLDAP_Message);
	
	// Set the DN
	dn = ldap_get_dn(ld, msg);
	rdn = rb_str_new2(dn);
	ldap_memfree(dn);
	rb_iv_set(obj, "@dn", rdn);
	
	// Set the attributes
	attrs = rb_hash_new();
	attr = ldap_first_attribute(ld, msg, &ber);
	do {
		values = ldap_get_values_len(ld, msg, attr);

		if (values == NULL) {
			rldap_raise(rldap_errno_c(obj));
		}

		ary = rb_ary_new();
		length = ldap_count_values_len(values);

		for (i=0; i<length; i++) {
			value = values[i];
			str = rb_str_new(value->bv_val, value->bv_len);
			rb_ary_push(ary, str);
		}
		
		rb_hash_aset(attrs, rb_str_new2(attr), ary);

		ldap_value_free_len(values);
		ldap_memfree(attr);
	} while (attr = ldap_next_attribute(ld, msg, ber));

	ber_free(ber, 0);

	rb_iv_set(obj, "@attrs", attrs);

	return obj;
}

static VALUE rldap_msg_dn(VALUE obj)
{	
	return rb_iv_get(obj, "@dn");
}

static VALUE rldap_msg_get_val(VALUE obj, VALUE key)
{	
	return rb_hash_aref(rb_iv_get(obj, "@attrs"), key);
}

static VALUE rldap_msg_keys(VALUE obj)
{
	return rb_funcall(rb_iv_get(obj, "@attrs"), rb_intern("keys"), 0);
}


void Init_ldap()
{
	cLDAP = rb_define_class("LDAP", rb_cObject);
	cLDAP_Message = rb_define_class_under(cLDAP, "Message", rb_cObject);
	eLDAP = rb_define_class_under(cLDAP, "Error", rb_eStandardError);

	rb_define_alloc_func(cLDAP, rldap_alloc);
	rb_define_singleton_method(cLDAP, "err2string", rldap_err2string, 1);
	rb_define_method(cLDAP, "initialize", rldap_initialize, -1);
	rb_define_method(cLDAP, "start_tls", rldap_start_tls, 0);
	rb_define_method(cLDAP, "search", rldap_search, -1);
	rb_define_method(cLDAP, "set_option", rldap_set_option, 2);
	rb_define_method(cLDAP, "version=", rldap_set_version, 1);
	rb_define_method(cLDAP, "errno", rldap_errno, 0);
	rb_define_method(cLDAP, "uri", rldap_uri, 0);
	rb_define_method(cLDAP, "inspect", rldap_inspect, 0);
	rb_define_method(cLDAP, "bind", rldap_bind, -1);
	rb_define_method(cLDAP, "unbind", rldap_unbind, 0);
	rb_define_method(cLDAP, "sasl_bind", rldap_sasl_bind, -1);
	
	rb_define_method(cLDAP_Message, "dn", rldap_msg_dn, 0);
	rb_define_method(cLDAP_Message, "[]", rldap_msg_get_val, 1);
	rb_define_method(cLDAP_Message, "keys", rldap_msg_keys, 0);
	
	#include "constants.h"
}
