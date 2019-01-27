import crypto from 'crypto'

export default class {
  static ssha_pass(passwd, salt, next) {
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

  static checkssha(passwd, hash, next) {
    if (hash.substring(0,6).toLowerCase() != '{ssha}') {
        return next(new Error('not {ssha}'),false);
    }
    const bhash = new Buffer(hash.substr(6),'base64');
    const salt = bhash.toString('binary',20); // sha1 digests are 20 bytes long
    this.ssha_pass(passwd,salt,function(err,newssha){
        if(err) return next(err)
        return next(null,hash.substring(6) === newssha.substring(6))
    });
    return null;
  }
}
