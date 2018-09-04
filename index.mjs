import ldap from 'ldapjs'
import consul from 'consul'
import ssha from 'openldap_ssha' 

// @FIXME: Need to check if a DN can contains a /. If yes, we are in trouble with consul.

const server = ldap.createServer()
const svc_mesh = consul()
const suffix = 'dc=deuxfleurs,dc=fr'

/*
 * Data Transform
 */
const dn_to_consul = dn => {
  return dn.rdns.map(rdn => rdn.toString()).reverse().join('/')
}

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

/*
 * Handlers
 */
server.bind(suffix, (req, res, next) => {
  const user_dn = req.dn.toString()
  svc_mesh.kv.get(user_dn+"/attribute=userPassword", (err, data) => {
    if (err) {
      return next(new ldap.OperationsError(err))
    }
    if (data === undefined || data === null) {
      return next(new ldap.NoSuchObjectError(user_dn))
    }
    const hash = data.Value
    const password = req.credentials 
    ssha.checkssha(req.credentials, hash, err => {
      
    }
    console.log(err, data) 
    res.end()
    return next()
  })
})

/*
 * Routes
 */
server.search(suffix, (req, res, next) => {
  const prefix = dn_to_consul(req.dn)
  svc_mesh.kv.get({key: prefix+"/", recurse: true }, (err, data) => {
    if (err) {
      return next(new ldap.OperationsError(err))
    }

    parse_consul_res(data)
      .filter(o => req.filter.matches(o.attributes))
      .forEach(o => res.send(o))
  
    res.end();
  })
})

server.listen(1389, () => console.log('LDAP server listening at %s', server.url))
