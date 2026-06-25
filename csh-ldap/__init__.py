from enum import Enum
import ldap
from ldap.ldapobject import ReconnectLDAPObject
import srvlookup
from csh_ldap.member import CSHMember
from csh_ldap.group import CSHGroup
from csh_ldap.utility import reconnect_on_fail


class CSHLDAP:
    __domain__ = "csh.rit.edu"

    @reconnect_on_fail
    def __init__(self, bind_dn, bind_pw, *, batch_mods=False,
                 sasl=False, ro=False):
        """Handler for bindings to CSH LDAP.

        Keyword arguments:
        batch_mods -- whether or not to batch LDAP writes (default False)
        sasl -- whether or not to bypass bind_dn and bind_pw and use SASL bind
        ro -- whether or not CSH LDAP is in read only mode (default False)
        """
        if ro:
            print("########################################\n"
                  "#                                      #\n"
                  "#    CSH LDAP IS IN READ ONLY MODE     #\n"
                  "#                                      #\n"
                  "########################################")
        ldap_srvs = srvlookup.lookup("ldap", "tcp", self.__domain__)
        self.ldap_uris = ['ldaps://' + uri.hostname for uri in ldap_srvs]
        self.server_uri = None
        self.__con__ = None
        for uri in self.ldap_uris:
            try:
                self.__con__ = ReconnectLDAPObject(uri)
                self.server_uri = uri
            except (ldap.SERVER_DOWN, ldap.TIMEOUT):
                continue

        if self.__con__ is None:
            raise ldap.SERVER_DOWN

        if sasl:
            self.__con__.sasl_non_interactive_bind_s('')
        else:
            self.__con__.simple_bind_s(bind_dn, bind_pw)
        self.__mod_queue__ = {}
        self.__pending_mod_dn__ = []
        self.__batch_mods__ = batch_mods
        self.__ro__ = ro

    @reconnect_on_fail
    def get_member(self, val, uid=False):
        """Get a CSHMember object.

        Arguments:
        val -- the uuid (or uid) of the member

        Keyword arguments:
        uid -- whether or not val is a uid (default False)
        """
        return CSHMember(self, val, uid)

    @reconnect_on_fail
    def get_member_ibutton(self, val):
        """Get a CSHMember object.

        Arguments:
        val -- the iButton ID of the member

        Returns:
        None if the iButton supplied does not correspond to a CSH Member
        """
        members = self.__con__.search_s(
            CSHMember.__ldap_user_ou__,
            ldap.SCOPE_SUBTREE,
            f"(ibutton={val})",
            ['ipaUniqueID'])
        if members:
            return CSHMember(
                self,
                members[0][1]['ipaUniqueID'][0].decode('utf-8'),
                False)
        return None

    @reconnect_on_fail
    def get_member_slackuid(self, slack):
        """Get a CSHMember object.

        Arguments:
        slack -- the Slack UID of the member

        Returns:
        None if the Slack UID provided does not correspond to a CSH Member
        """
        members = self.__con__.search_s(
            CSHMember.__ldap_user_ou__,
            ldap.SCOPE_SUBTREE,
            f"(slackuid={slack})",
            ['ipaUniqueID'])
        if members:
            return CSHMember(
                self,
                members[0][1]['ipaUniqueID'][0].decode('utf-8'),
                False)
        return None

    @reconnect_on_fail
    def get_group(self, val):
        """Get a CSHGroup object.

        Arguments:
        val -- the cn of the group

        """
        return CSHGroup(self, val)

    def get_con(self):
        """Get the PyLDAP Connection"""
        return self.__con__

    @reconnect_on_fail
    def get_directorship_heads(self, val):
        """Get the head of a directorship

        Arguments:
        val -- the cn of the directorship
        """

        __ldap_group_ou__ = "cn=groups,cn=accounts,dc=csh,dc=rit,dc=edu"

        res = self.__con__.search_s(
            __ldap_group_ou__,
            ldap.SCOPE_SUBTREE,
            f"(cn=eboard-{val})",
            ['member'])

        ret = []
        for member in res[0][1]['member']:
            try:
                ret.append(member.decode('utf-8'))
            except UnicodeDecodeError:
                ret.append(member)
            except KeyError:
                continue

        return [CSHMember(self,
                          dn.split('=')[1].split(',')[0],
                          True)
                for dn in ret]

    def get_query_for_groups(self, groups = None, excluded_groups = None):
        """Returns the ldap query string to get members in groups but not in others

        Argumenets:
        groups -- the groups members must be a member of
        excluded_groups -- the groups members cannot be a part of
        """

        group_dns = [f"(memberOf=cn={group},cn=groups,cn=accounts,dc=csh,dc=rit,dc=edu)" for group in groups]
        excluded_group_dns = [
            f"(memberOf=cn={group},cn=groups,cn=accounts,dc=csh,dc=rit,dc=edu)"
            for group in excluded_groups
        ]

        query = ""

        for group in group_dns:
            if query == "":
                query = group
                continue

            query = f"(&{query}{group})"

        for group in excluded_group_dns:
            group = f"(!{group})"
            if query == "":
                query = group
                continue

            query = f"(&{query}{group})"

        return query

    def get_group_member_attributes(self, groups = None, excluded_groups = None, attributes = None):
        """Returns a list of dicts containing all the attributes requested in the groups listed in groups, 
            but not in exlcuded_groups

        Arguements:
        groups -- the groups members must be a member of
        excluded_groups -- the groups members cannot be a part of
        attributues -- the ldap attributes to return, defaults to uid
        """

        # I HATE PYTHON
        if attributes is None:
            attributes = ['uid']

        query_result = self.__con__.search_s(
            "dc=csh,dc=rit,dc=edu",
            ldap.SCOPE_SUBTREE,
            self.get_query_for_groups(groups=groups, excluded_groups=excluded_groups),
            attributes)

        # the rest of this could be one giant list compression but I don't hate you that much so I chose not to

        # filter out subgroups, probably the second check all we need
        # but if we used just the second one but the first one was empty that would probably be confusing?
        byte_result = [member[1] for member in query_result if not member[1] == {} and "cn=users" in member[0]]

        result = []

        for byte_member in byte_result:
            # decoding the byte strings
            result.append({key: value[0].decode('utf-8') for (key, value) in byte_member.items()})

        return result

    def get_group_member_uids(self, groups = None, excluded_groups = None):
        """Get a list of member uids in a group

        Arguements:
        groups -- the groups members must be a member of
        excluded_groups -- the groups members cannot be a part of
        """

        query_result = self.__con__.search_s(
            "dc=csh,dc=rit,dc=edu",
            ldap.SCOPE_SUBTREE,
            self.get_query_for_groups(groups=groups, excluded_groups=excluded_groups),
            ['uid'])

        return [
            member[1]['uid'][0].decode('utf-8')
            for member in query_result
            if not member[1] == {} and "cn=users" in member[0]
        ]

    def get_group_member_uuids(self, groups = None, excluded_groups = None):
        """Get a list of member uuids in a group (ipaUniqueId)

        Arguements:
        groups -- the groups members must be a member of
        excluded_groups -- the groups members cannot be a part of
        """

        query_result = self.__con__.search_s(
            "dc=csh,dc=rit,dc=edu",
            ldap.SCOPE_SUBTREE,
            self.get_query_for_groups(groups=groups, excluded_groups=excluded_groups),
            ['ipaUniqueId'])

        return [
            member[1]['ipaUniqueId'][0].decode('utf-8')
            for member in query_result
            if not member[1] == {} and "cn=users" in member[0]
        ]

    def enqueue_mod(self, dn, mod):
        """Enqueue a LDAP modification.

        Arguments:
        dn -- the distinguished name of the object to modify
        mod -- an ldap modfication entry to enqueue
        """
        # mark for update
        if dn not in self.__pending_mod_dn__:
            self.__pending_mod_dn__.append(dn)
            self.__mod_queue__[dn] = []

        self.__mod_queue__[dn].append(mod)

    @reconnect_on_fail
    def flush_mod(self):
        """Flush all pending LDAP modifications."""
        for dn in self.__pending_mod_dn__:
            try:
                if self.__ro__:
                    for mod in self.__mod_queue__[dn]:
                        if mod[0] == ldap.MOD_DELETE:
                            mod_str = "DELETE"
                        elif mod[0] == ldap.MOD_ADD:
                            mod_str = "ADD"
                        else:
                            mod_str = "REPLACE"
                        print(f"{mod_str} VALUE {mod[1]} = {mod[2]} FOR {dn}")
                else:
                    self.__con__.modify_s(dn, self.__mod_queue__[dn])
            except ldap.TYPE_OR_VALUE_EXISTS:
                print(f"Error! Conflicting Batch Modification: {self.__mod_queue__[dn]}")
                continue
            except ldap.NO_SUCH_ATTRIBUTE:
                print(f"Error! Conflicting Batch Modification: {self.__mod_queue__[dn]}")
                continue
            self.__mod_queue__[dn] = None
        self.__pending_mod_dn__ = []
