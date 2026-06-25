# csh-ldap

[![PyPI version](https://badge.fury.io/py/csh_ldap.svg)](https://badge.fury.io/py/csh_ldap)
[![Build Status](https://travis-ci.org/liam-middlebrook/csh_ldap.svg?branch=master)](https://travis-ci.org/liam-middlebrook/csh_ldap)

Python 3 ORM for CSH LDAP


## Installation

`pip install csh-ldap`


## Usage

```
import csh_ldap

# Create an unbatched instance
instance = csh_ldap.CSHLDAP(bind_dn, bind_pw)

# Create an batched instance
instance_batched = csh_ldap.CSHLDAP(bind_dn, bind_pw, batch_mods=True)

# Create a Read-Only instance that will only echo your changes
instance_ro = csh_ldap.CSHLDAP(bind_dn, bind_pw, ro=True)

# Get member by UUID
liam = instance.get_member(uuid_of_liam)

# Get member by UID
liam = instance.get_member(uid_of_liam, uid=True)

# Get member by iButton ID
liam = instance.get_member_ibutton(ibutton_id)

# Get member by Slack UID
liam = instance.get_member_slackuid(slack_uid)

# Get group by cn
rtp = instance.get_group('rtp')

# get group member uids 
rtp = instance.get_group('rtp').get_member_uids()
# returns ['spaced', ...]

# get group member uids (other way)
rtp = instance.get_group_member_uids(groups=["rtp"])

# get uids of members in two (or more) groups and not in groups
fancy = instance.get_group_member_uids(groups=["rtp", "onfloor"], excluded=["eboard-opcomm"])

# get uuids of members in two (or more) groups and not in groups
# that's right! ipaUniqueId
fancy = instance.get_group_member_uuids(groups=["rtp", "onfloor"], excluded=["eboard-opcomm"])

# get other miscellaneous attributes of members in group
# look how rich drink admins are (admin abuse!!!)
admin_abuse = instance.get_group_member_attributes(group=["drink"], attributes=["uid", "drinkBalance"])
# returns dicts for each member
"""
I wonder what happened here
[
{
    'uid': 'cole',
    'drinkBalance': '996246'
},
{
    'uid': 'zxcv',
    'drinkBalance': '3847173'
}
]
"""

# Get cn of member
print(liam.cn)

# Set cn of member
liam.cn = "Liam Middlebrook"

# Setting attributes to None removes them
liam.roomNumber = None

# Process batched writes per-dn
instance_batched.flush_mod()

# Get EBoard Directorship
# Directorships: ['chairman', 'evaluations', 'financial', 'history', 'imps', 'opcomm', 'research', 'social']
social = instance.get_directorship_heads('social')

for director in social:
    # Directorships are always lists, since it can be multiple people.
    print(director.cn)

```
