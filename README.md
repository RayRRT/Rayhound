# Rayhound
Dirty code to learn more about ldap queries in C#


- Users & Groups "(&(objectClass=computer)(objectClass=user))"
- Try to read LAPS "ms-mcs-AdmPwd"
- Constrained "msDS-AllowedToDelegateTo"
- Unconstrained "(&(objectCategory=computer)(objectClass=computer)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
- Asreproast "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
- Kerberoast "(&(samAccountType=805306368)(servicePrincipalName=*))"
- Get TGS to Kerberoast (using KerberosRequestorSecurityToken, i just implemented https://github.com/GhostPack/SharpRoast here)
- Domain & Forest trusts ( Using GetCurrentForest method and TrustRelationshipInformation fromSystem.DirectoryServices.ActiveDirectory)

TODO: I should clean up the code, but the goal was to understand how to launch ldap queries from C# so it probably remains that dirty :)

https://user-images.githubusercontent.com/52030285/189893568-20402a7c-6226-42e0-8672-f87411c0a988.mp4

