import ldap
from csh_ldap.member import CSHMember
from csh_ldap.utility import reconnect_on_fail


class CSHGroup:
    __ldap_group_ou__ = "cn=groups,cn=accounts,dc=csh,dc=rit,dc=edu"
    __ldap_base_dn__ = "dc=csh,dc=rit,dc=edu"

    @reconnect_on_fail
    def __init__(self, lib, search_val):
        """Object Model for CSH LDAP groups.

        Arguments:
        lib -- handle to a CSHLDAP instance
        search_val -- the cn of the LDAP group to bind to
        """
        self.__dict__['__lib__'] = lib
        self.__dict__['__con__'] = lib.get_con()

        res = self.__con__.search_s(
            self.__ldap_group_ou__,
            ldap.SCOPE_SUBTREE,
            f"(cn={search_val})",
            ['cn'])

        if res:
            self.__dict__['__dn__'] = res[0][0]
        else:
            raise KeyError("Invalid Search Name")

    @reconnect_on_fail
    def get_member_uids(self):
        """Return the uids of all members in the group"""

        res = self.__con__.search_s(
            self.__ldap_base_dn__,
            ldap.SCOPE_SUBTREE,
            f"(memberof={self.__dn__})",
            ['uid'])

        ret = []
        for val in res:
            if 'uid' not in val[1]:
                continue

            val = val[1]['uid'][0]
            try:
                ret.append(val.decode('utf-8'))
            except UnicodeDecodeError:
                ret.append(val)
            except KeyError:
                continue

        return ret


    @reconnect_on_fail
    def get_members(self):
        """Return all members in the group as CSHMember objects"""

        uids = self.get_member_uids()

        return [CSHMember(self.__lib__,
                          result,
                          uid=True)
                for result in uids]

    @reconnect_on_fail
    def check_member(self, member, dn=False):
        """Check if a Member is in the bound group.

        Arguments:
        member -- the CSHMember object (or distinguished name) of the member to
                  check against

        Keyword arguments:
        dn -- whether or not member is a distinguished name
        """

        if dn:
            res = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                f"(member={dn})",
                ['ipaUniqueID'])
        else:
            res = self.__con__.search_s(
                self.__dn__,
                ldap.SCOPE_BASE,
                f"(member={member.get_dn()})",
                ['ipaUniqueID'])
        return len(res) > 0

    @reconnect_on_fail
    def add_member(self, member, dn=False):
        """Add a member to the bound group

        Arguments:
        member -- the CSHMember object (or distinguished name) of the member

        Keyword arguments:
        dn -- whether or not member is a distinguished name
        """

        if dn:
            if self.check_member(member, dn=True):
                return
            mod = (ldap.MOD_ADD, 'member', member.encode('ascii'))
        else:
            if self.check_member(member):
                return
            mod = (ldap.MOD_ADD, 'member', member.get_dn().encode('ascii'))

        if self.__lib__.__batch_mods__:
            self.__lib__.enqueue_mod(self.__dn__, mod)
        elif not self.__lib__.__ro__:
            mod_attrs = [mod]
            self.__con__.modify_s(self.__dn__, mod_attrs)
        else:
            print(f"ADD VALUE member = {mod[2]} FOR {self.__dn__}")

    @reconnect_on_fail
    def del_member(self, member, dn=False):
        """Remove a member from the bound group

        Arguments:
        member -- the CSHMember object (or distinguished name) of the member

        Keyword arguments:
        dn -- whether or not member is a distinguished name
        """

        if dn:
            if not self.check_member(member, dn=True):
                return
            mod = (ldap.MOD_DELETE, 'member', member.encode('ascii'))
        else:
            if not self.check_member(member):
                return
            mod = (ldap.MOD_DELETE, 'member', member.get_dn().encode('ascii'))

        if self.__lib__.__batch_mods__:
            self.__lib__.enqueue_mod(self.__dn__, mod)
        elif not self.__lib__.__ro__:
            mod_attrs = [mod]
            self.__con__.modify_s(self.__dn__, mod_attrs)
        else:
            print(f"DELETE VALUE member = {mod[2]} FOR {self.__dn__}")
