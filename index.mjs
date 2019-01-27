"use strict"
import ldap from 'ldapjs'
import consul from 'consul'
import ssha from './ssha.mjs'
import config from './config.json'

// @FIXME: Need to check if a DN can contains a /. If yes, we are in trouble with consul.
// @FIXME: Rewrite with Promises + async 
// @FIXME: Warning crypto functions are deprecated
// @FIXME: Error are probably too verbose
// @FIXME: Add an initial prefix to the consul key value
// @FIXME: Check that a user can't read more than it should -> check requests for wrong inclusion and use the consul ACL system
// @FIXME: Handle multi suffix
// @FIXME: Implement base, one, sub in search
// @FIXME: Implement modify, delete, compare
// @FIXME: Implement a REAL permission system

config.suffix = process.env.BOTTIN_SUFFIX ? process.env.BOTTIN_SUFFIX : config.suffix
config.port = process.env.BOTTIN_PORT ? process.env.BOTTIN_PORT : config.port
config.consul = process.env.BOTTIN_CONSUL ? process.env.BOTTIN_CONSUL : config.consul

const server = ldap.createServer()
const svc_mesh = consul({host: config.consul})
const suffix = config.suffix

/*
 * Data Transform
 */

const explode_dn = dn => dn.rdns.map(rdn => rdn.toString())
const dn_to_consul = dn => explode_dn(dn).reverse().join('/')

const consul_to_dn = entry => {
  const exploded_key = entry.Key.split("/").filter(e => e !== null && e !== undefined && e !== "")
  const last_element = exploded_key[exploded_key.length - 1].split('=', 2)
  if (last_element[0] !== "attribute" || last_element.length < 2) {
    const dn = exploded_key.reverse().join(',')
    return {dn: dn, attribute: null, value: null}
  }
  
  const dn = exploded_key.slice(0,-1).reverse().join(',')
  const attribute = last_element[1]
  return {dn: dn, attribute: attribute, value: entry.Value}
}

const parse_consul_res = keys => {
  const aggregator = {}
  keys
    .map(consul_to_dn)
    .filter(e => e.attribute !== null)
    .forEach(e => {
      if (!(e.dn in aggregator)) aggregator[e.dn] = {}
      aggregator[e.dn][e.attribute] = JSON.parse(e.value)
    })

  return Object
           .keys(aggregator)
           .map(k => ({dn: k, attributes: aggregator[k]}))
}

const extract_memberof_from_filter = filter => {
  let res = []
  if (filter.attribute && filter.attribute == "memberof")
    res.push(filter.value)
  
  if (filter.filters)
    res = res.concat(filter.filters.reduce((acc, cur) => acc.concat(extract_memberof_from_filter(cur)), []))

  return res
}

const fetch_membership = (memberof_to_load, cb) => {
  let remaining_requests = memberof_to_load.length
  const error_list = []
  const membership = {}

  memberof_to_load.forEach(m => {
    svc_mesh.kv.get(dn_to_consul(ldap.parseDN(m)) + "/attribute=member", (err, data) => {
      if (err) error_list.push(err)
      // We might search unrelated things
      //else if (!data || !data.Value) error_list.push(m + " not found")
      else if (!data || !data.Value) console.warn("No entry found for " + m)
      else if (data.Value) JSON.parse(data.Value).forEach(user => {
        if (!(user in membership)) membership[user] = []
        membership[user].push(m)
      })

      remaining_requests--
      if (remaining_requests === 0) cb(error_list.length === 0 ? null : error_list, membership)
    })           
  })
  if (memberof_to_load.length === 0)
    cb(null, [])
}

const decorate_with_memberof = (obj, member_data) => {
  if (obj.dn in member_data) {
    obj.attributes.memberof = member_data[obj.dn]
  }

  return obj
}

/*
 * Object abstraction
 */

const add_elements = (dn, attributes_to_add, internal_type="attribute") => Promise.all(
    Object.keys(attributes_to_add)
          .map(k =>
            new Promise((resolve, reject) =>
              svc_mesh.kv.set(dn + "/" + internal_type + "=" + k, JSON.stringify(attributes_to_add[k]), (err, setres) => err ? reject(err) : resolve(setres)))))

/*
 * Handlers
 */
const authorize = (req, res, next) => {
  if (req.connection.ldap.bindDN.equals('')) {
    console.error("Anonymous bind are not authorized")
    return next(new ldap.InsufficientAccessRightsError())
  }

  console.log("Check authorization for " + req.connection.ldap.bindDN)
  const query = new Promise((resolve, reject) =>
    svc_mesh.kv.get(dn_to_consul(req.connection.ldap.bindDN) + "/internal=permission", (err, getres) => err ? reject(err) : resolve(getres)))

  query.then(key => {
    if (!key || !key.Value) {
      console.error("There is no internal=permission key for " + req.connection.ldap.bindDN)
      return next(new ldap.InsufficientAccessRightsError())
    }

    const user_perm = JSON.parse(key.Value)
    const is_search = (req instanceof ldap.SearchRequest)
    
    if (is_search && user_perm.includes("read"))
      return next()

    if (!is_search && user_perm.includes("write"))
      return next()
    
    console.error(req.dn.toString() + "doesn't have the correct write access")
    return next(new ldap.InsufficientAccessRightsError())
  }).catch(err => {
    console.error("The Consul database query failed when we tried to fetch " + req.dn.toString() + "'s permissions")
    return next(new ldap.OperationsError(err.toString()))
  })
}

/*
 * Routes
 */
server.bind(suffix, (req, res, next) => {
  const user_dn = dn_to_consul(req.dn)
  svc_mesh.kv.get(user_dn+"/attribute=userpassword", (err, data) => {
    if (err) {
      console.error("Failed bind for " + req.dn.toString(), err)
      return next(new ldap.OperationsError(err.toString()))
    }
    if (data === undefined || data === null) {
      console.error("Failed bind for " + req.dn.toString(), "No entry in consul")
      return next(new ldap.NoSuchObjectError(user_dn))
    }
    const hash = JSON.parse(data.Value).toString()
    const password = req.credentials
    ssha.checkssha(req.credentials, hash, (err, v) => {
      if (err) return next(new ldap.OperationsError(err.toString()))
      if (!v) return next(new ldap.InvalidCredentialsError())
    
      res.end()
      console.log("Successful bind for "+req.dn.toString())
      return next()
    })
  })
})

server.search(suffix, authorize, (req, res, next) => {
  const prefix = dn_to_consul(req.dn)
  svc_mesh.kv.get({key: prefix+"/", recurse: true }, (err, data) => {
    if (err) {
      console.error("Failed to search in "+req.dn.toString(), err)
      return next(new ldap.OperationsError(err.toString()))
    }

    fetch_membership(extract_memberof_from_filter(req.filter), (err, membership) => {
      if (err) {
	console.error("Failed to fetch memberof in "+req.dn.toString() + " for " + req.filter.toString(), err)
        return next(new ldap.OperationsError(err.toString()))
      }

      parse_consul_res(data)
        .filter(o => req.filter.matches(decorate_with_memberof(o, membership).attributes))
        .forEach(o => res.send(o))
  
      console.log("search - dn=%s - filter=%s - bind=%s", req.dn, req.filter, req.connection.ldap.bindDN)
      res.end();
    })
  })
})

server.add(suffix, authorize, (req, res, next) => {
  const consul_dn = dn_to_consul(req.dn)
  svc_mesh.kv.get({key: consul_dn, recurse: true}, (err, data) => {
    if (err) return next(new ldap.OperationsError(err.toString()))
    if (data) return next(new ldap.EntryAlreadyExistsError(req.dn.toString()))

    const attributes_to_add = req.toObject().attributes
    add_elements(consul_dn, attributes_to_add).then(setres => {
      res.end()
      console.log("add - dn=%s - bind=%s", req.dn, req.connection.ldap.bindDN)
      return next() 
    }).catch(seterr => {
      return next(new ldap.OperationsError(seterr.toString()))
    })
  })
})

/*
 * Main
 */

const init = () => new Promise((resolve, reject) => {
  svc_mesh.kv.get(dn_to_consul(ldap.parseDN(config.suffix)) + "/attribute=dc", (err, data) => {
    if (err) {
      reject(err);
      return;
    }

    if (data) {
      resolve();
      return;
    }

    const base_attributes = {
      objectClass: ['top', 'dcObject', 'organization'],
      structuralObjectClass: 'organization'
    }

    const suffix_dn = ldap.parseDN(config.suffix)
    const exploded_suffix = explode_dn(suffix_dn)
    const exploded_last_entry = exploded_suffix[exploded_suffix.length - 1].split('=', 2)
    if (exploded_last_entry.length != 2) {
      reject(config.suffix + " is incorrect");
      return;
    }
    const type = exploded_last_entry[0]
    const value = exploded_last_entry[1] 
    base_attributes[type] = value

    add_elements(dn_to_consul(suffix_dn), base_attributes).then(() => {
      const username = Math.random().toString(36).slice(2)
      const password = Math.random().toString(36).slice(2)
      const admin_dn = ldap.parseDN( "dc=" + username + "," + config.suffix)

      ssha.ssha_pass(password, (err, hashedPass) => {
        if (err) {
          reject(err);
          return;
        }

        const admin_attributes = {
          objectClass: ['simpleSecurityObject', 'organizationalRole'],
          description: 'LDAP administrator',
          cn: username,
          userpassword: hashedPass,
          structuralObjectClass: 'organizationalRole',
          permissions: ['read', 'write']
        }

        add_elements(dn_to_consul(admin_dn), admin_attributes).then(() => {
          console.log(
            "It seems to be a new installation, we created a default user for you: %s with password %s\nWe didn't use true random, you should replace it as soon as possible.",
            admin_dn.toString(),
            password
          )
          resolve();
        }).catch(err => reject(err))
      })
    }).catch(err => reject(err))
  })
})

init().then(() => {
  server.listen(
    config.port,
    () => console.log(
      'LDAP server listening at %s on suffix %s and linked to consul server %s',
      server.url,
      config.suffix,
      config.consul))
}).catch(err => console.error(err))
