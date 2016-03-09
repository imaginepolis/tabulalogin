/**
 * TabulaLogin: Simple library for authentication
 * @author Juan Camilo Ibarra
 * @version 0.0.0
 * @date December 2015
 */

/**
 * Module requires 
 */
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');

var TabulaLogin = function(){
	this.app = null;
	this.express = null;
	this.tokenkey = null;
	this.routes = null;
	this.tokenexpiration = 3600;
	this.authenticator = null;
};

TabulaLogin.prototype.setup = function()
{
	_this = this;
	this.app.use(bodyParser.urlencoded({extended : false}));
	this.app.use(bodyParser.json());
	
	this.routes = this.express.Router();
	this.app.set('secret', _this.tokenkey);
	
	
	this.routes.post("/authenticate", function(req,res){
		_this.authenticator(req.body, function(result){
			if(result.success)
			{
				var token = jwt.sign({user : req.body.name}, _this.app.get('secret'),{
					expiresIn : _this.tokenexpiration
				});
				
				res.json({
					success : true,
					message : 'Login succesful!',
					token : token,
					params : result.params
				});	
			}
			else
			{
				res.json({
					success : false,
					message : 'Login unsuccesful!',
				});	
			}
		});
		
	});
	// Authenticate the token
	this.routes.use(function(req, res, next){
		var token = req.body.token || req.query.token || req.headers['x-access-token'];
		if(token)
		{
			jwt.verify(token, _this.app.get('secret'), function (err, decoded){
				if(err)
				{
					return res.status(403).send({
						success : false, 
						message : 'Failed to authenticate token'
					});
				}
				else
				{
					req.decoded = decoded;
					next();
				}
			});
		}
		else
		{
			return res.status(403).send({
				success : false,
				message : 'No token provided'
			});
		}
	});
	
	this.app.use("/api", _this.routes);
};


module.exports = function(){
	var login = new TabulaLogin();
	return login;
};
