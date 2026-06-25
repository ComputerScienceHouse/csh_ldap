import ldap
from csh_ldap.utility import reconnect_on_fail


class CSHMember:
    __ldap_user_ou__ = "cn=users,cn=accounts,dc=csh,dc=rit,dc=edu"
    __ldap_group_ou__ = "cn=groups,cn=accounts,dc=csh,dc=rit,dc=edu"

    @reconnect_on_fail
    def __init__(self, lib, search_val, uid):
        """Object Model for CSH LDAP users.

        Arguments:
        lib -- handle to a CSHLDAP instance
        search_val -- the uuid (or uid) of the member to bind to
        uid -- whether or not search_val is a uid
        """
        self.__dict__['__lib__'] = lib
        self.__dict__['__con__'] = lib.get_con()

        res = None

        if uid:
            res = self.__con__.search_s(
                self.__ldap_user_ou__,
                ldap.SCOPE_SUBTREE,
                f"(uid={search_val})",
                ['ipaUniqueID'])
        else:
            res = self.__con__.search_s(
                self.__ldap_user_ou__,
                ldap.SCOPE_SUBTREE,
                f"(ipaUniqueID={search_val})",
                ['uid'])

        if res:
            self.__dict__['__dn__'] = res[0][0]
        else:
            raise KeyError("Invalid Search Name")

    def __eq__(self, other):
        if isinstance(other, CSHMember):
            return self.__dn__ == other.__dn__
        return False

    def __hash__(self):
        """Generate a unique hash value for the bound CSH LDAP member object.
        """
        return hash(self.__dn__)

    def __repr__(self):
        """Generate a str representation of the bound CSH LDAP member object.
        """
        return f"CSH Member(dn: {self.__dn__})"

    def get(self, key):
        """Get an attribute from the bound CSH LDAP member object.

        Arguments:
        key -- the attribute to get the value of
        """
        return self.__getattr__(key, as_list=True) # pylint: disable=unnecessary-dunder-call

    @reconnect_on_fail
    def groups(self):
        """Get the list of Groups (by dn) that the bound CSH LDAP member object
        is in.
        """
        group_list = []
        all_groups = self.get('memberof')
        for group_dn in all_groups:
            if self.__ldap_group_ou__ in group_dn:
                group_list.append(group_dn)

        return group_list

    def in_group(self, group, dn=False):
        """Get whether or not the bound CSH LDAP member object is part of a
        group.

        Arguments:
        group -- the CSHGroup object (or distinguished name) of the group to
                 check membership for
        """
        if dn:
            return group in self.groups()
        return group.check_member(self)

    def get_dn(self):
        """Get the distinguished name of the bound LDAP object"""
        return self.__dn__

    @reconnect_on_fail
    def __getattr__(self, key, as_list=False):
        res = self.__con__.search_s(
            self.__dn__,
            ldap.SCOPE_BASE,
            "(objectClass=*)",
            [key])

        if as_list:
            ret = []
            for val in res[0][1][key]:
                try:
                    ret.append(val.decode('utf-8'))
                except UnicodeDecodeError:
                    ret.append(val)
                except KeyError:
                    continue

            return ret
        try:
            return res[0][1][key][0].decode('utf-8')
        except UnicodeDecodeError:
            return res[0][1][key][0]
        except KeyError:
            return None

    @reconnect_on_fail
    def __setattr__(self, key, value):
        ldap_mod = None

        exists = self.__con__.search_s(
            self.__dn__,
            ldap.SCOPE_BASE,
            "(objectClass=*)",
            [key])

        if value is None or value == "":
            ldap_mod = ldap.MOD_DELETE
            if exists[0][1] == {}:
                # if element doesn't exist STOP
                return
        elif exists[0][1] == {}:
            ldap_mod = ldap.MOD_ADD
        else:
            ldap_mod = ldap.MOD_REPLACE

        if value is None:
            mod = (ldap_mod, key, None)
        else:
            mod = (ldap_mod, key, value.encode('utf-8'))

        if self.__lib__.__batch_mods__:
            self.__lib__.enqueue_mod(self.__dn__, mod)
        elif not self.__lib__.__ro__:
            mod_attrs = [mod]
            self.__con__.modify_s(self.__dn__, mod_attrs)
        else:
            if ldap_mod == ldap.MOD_DELETE:
                mod_str = "DELETE"
            elif ldap_mod == ldap.MOD_ADD:
                mod_str = "ADD"
            else:
                mod_str = "REPLACE"
            print(f"{mod_str} FIELD {key} WITH {value} FOR {self.__dn__}")
