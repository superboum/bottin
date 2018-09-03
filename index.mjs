import ldap from 'ldapjs'

const server = ldap.createServer()

server.listen(1389, () => console.log('LDAP server listening at %s', server.url))
