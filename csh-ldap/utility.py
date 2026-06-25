from functools import wraps
import ldap
import srvlookup

MAX_RECONNECTS = 3


def reconnect_on_fail(method):
    """
    Decorator for CSHLDAP operations that attempts to reconnect and recall a
    method on a failed call.

    :param method: Method to call
    :return: wrapper function
    """

    @wraps(method)
    def wrapper(*method_args, **method_kwargs):
        """
        Wrapper for method, calls method and returns the result if successful,
         otherwise tries reconnecting.

        :param method_args: method's arguments
        :param method_kwargs: method's keyword arguments
        :return: result of method call
        """
        max_reconnects = MAX_RECONNECTS

        def is_cshldap(arg):
            return any(
                filter(
                    lambda t: t.__name__ == 'CSHLDAP',
                    type(arg).__mro__
                )
            )
        ldap_obj = next(filter(is_cshldap, method_args)) \
                   if any(filter(is_cshldap, method_args)) \
                   else method_args[0].__lib__
        while max_reconnects:
            try:
                result = method(*method_args, **method_kwargs)
                return result
            except (ldap.SERVER_DOWN, ldap.TIMEOUT):
                ldap_srvs = srvlookup.lookup(
                    "ldap", "tcp", ldap_obj.__domain__)
                ldap_obj.ldap_uris = ['ldaps://' + uri.hostname
                                      for uri in ldap_srvs]

                for uri in ldap_obj.ldap_uris:
                    try:
                        ldap_obj.__con__.reconnect(uri)
                        ldap_obj.server_uri = uri
                        result = method(*method_args, **method_kwargs)
                        return result
                    except (ldap.SERVER_DOWN, ldap.TIMEOUT):
                        continue
                max_reconnects -= 1
                if max_reconnects == 0:
                    raise
        return None

    return wrapper
