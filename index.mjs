import ldap from 'ldapjs'
import consul from 'consul'
import crypto from 'crypto'
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
 * Security
 */

const ssha_pass = (passwd, salt, next) => {
    const _ssha = (passwd, salt, next ) => {
        const ctx = crypto.createHash('sha1');
        ctx.update(passwd, 'utf-8');
        ctx.update(salt, 'binary');
        const digest = ctx.digest('binary');
        const ssha = '{ssha}' + new Buffer(digest+salt,'binary').toString('base64');
        return next(null, ssha);
    }
    if(next === undefined) {
            next = salt;
            salt = null;
    }
    if(salt === null ){
        crypto.randomBytes(32, function(ex, buf) {
            if (ex) return next(ex);
            _ssha(passwd,buf.toString('base64') ,next);
            return null;
        });
    }else{
        _ssha(passwd,salt,next);
    }
    return null;
}

const checkssha = (passwd, hash, next) => {
    if (hash.substring(0,6).toLowerCase() != '{ssha}') {
        return next(new Error('not {ssha}'),false);
    }
    const bhash = new Buffer(hash.substr(6),'base64');
    const salt = bhash.toString('binary',20); // sha1 digests are 20 bytes long
    ssha_pass(passwd,salt,function(err,newssha){
        if(err) return next(err)
        return next(null,hash.substring(6) === newssha.substring(6))
    });
    return null;
}

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
      else if (!data || !data.Value) error_list.push(m + " not found")
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
 * Handlers
 */
const authorize = (req, res, next) => {
  if (req.connection.ldap.bindDN.equals('')) {
    console.error("Anonymous bind are not authorized")
    return next(new ldap.InsufficientAccessRightsError())
  }

  const query = new Promise((resolve, reject) =>
    svc_mesh.kv.get(dn_to_consul(req.connection.ldap.bindDN) + "/internal=permission", (err, getres) => err ? reject(err) : resolve(getres)))

  query.then(key => {
    if (!key || !key.Value) {
      console.error("There is no internal=permission key for "+req.dn.toString())
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
  svc_mesh.kv.get(user_dn+"/attribute=userPassword", (err, data) => {
    if (err) {
      console.error("Failed bind for " + req.dn.toString(), err)
      return next(new ldap.OperationsError(err.toString()))
    }
    if (data === undefined || data === null) {
      console.error("Failed bind for " + req.dn.toString(), "No entry in consul")
      return next(new ldap.NoSuchObjectError(user_dn))
    }
    const hash = JSON.parse(data.Value)
    const password = req.credentials
    checkssha(req.credentials, hash, (err, v) => {
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
    Promise.all(
      Object.keys(attributes_to_add)
            .map(k => new Promise((resolve, reject) => {
              svc_mesh.kv.set(consul_dn + "/attribute=" + k, JSON.stringify(attributes_to_add[k]), (err, setres) => err ? reject(err) : resolve(setres))
    }))).then(setres => {
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
server.listen(config.port, () => console.log('LDAP server listening at %s on suffix %s and linked to consul server %s', server.url, config.suffix, config.consul))
