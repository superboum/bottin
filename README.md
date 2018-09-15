# Bottin

A cloud native LDAP server with a consul backend written in node.

## Manually create your database

Go to your consul web ui (on port 8500 by default), in the key/value tab.
We will need to add a first user manually to be able to interact with our database.

Create the following keys:

  * `dc=com/dc=example/cn=admin/attribute=cn` with content `"admin"`
  * `dc=com/dc=example/cn=admin/attribute=objectclass` with content `["simpleSecurityObject"]`
  * `dc=com/dc=example/cn=admin/attribute=userPassword` with content `"{SSHA}PSUVFMGeuz3YRrgEIGcbto6PRzuqnpT3"` (here we have the `admin` password, but you can use the `slappaswd` command shipped with openldap server to generate a SSHA password)
  * `dc=com/dc=example/cn=admin/internal=permission` with content `["read", "write"]`
 
## Run

You need at least `node v10.9.0`.

```
npm install
node --experimental-modules index.mjs
```

## Docker

Run:

```
docker run superboum/bottin --env BOTTIN_PORT=389 --env BOTTIN_CONSUL=192.168.1.1 --env BOTTIN_SUFFIX="dc=example,dc=com"
```

Build:

```
docker build -t superboum/bottin .
docker build -t superboum/arm32v7_bottin .
```
