package routes

import (
	"fmt"
	"time"
	// "reflect"
	// filepath "path/filepath"
	bcrypt "golang.org/x/crypto/bcrypt"
	// try "github.com/manucorporat/try"
	fiber "github.com/gofiber/fiber/v2"
	rate_limiter "github.com/gofiber/fiber/v2/middleware/limiter"
	// uuid "github.com/satori/go.uuid"
	bolt_api "github.com/boltdb/bolt"
	types "github.com/0187773933/KeyValueStoreServer/v1/types"
	// utils "github.com/0187773933/KeyValueStoreServer/v1/utils"
	encryption "github.com/0187773933/encryption/v1/encryption"
)

var GlobalConfig *types.ConfigFile

func RegisterRoutes( fiber_app *fiber.App , config *types.ConfigFile ) {
	GlobalConfig = config
	fiber_app.Get( "/" , public_limiter , Home )
	fiber_app.Get( "/logout" , public_limiter , HandleLogout )
	fiber_app.Get( "/login" , public_limiter , ServeLoginPage )
	fiber_app.Post( "/login" , public_limiter , HandleLogin )
	fiber_app.Get( "/set/:key/:value" , Set )
	fiber_app.Get( "/set/:key" , Set )
	fiber_app.Get( "/tk" , NewTempKey )
	fiber_app.Get( "/:key" , public_limiter , Get )
}

var public_limiter = rate_limiter.New(rate_limiter.Config{
	Max: 3 , // set a different rate limit for this route
	Expiration: 30 * time.Second ,
	// your remaining configurations...
	KeyGenerator: func( c *fiber.Ctx ) string {
		return c.Get( "x-forwarded-for" )
	} ,
	LimitReached: func( c *fiber.Ctx ) error {
		ip_address := c.IP()
		log_message := fmt.Sprintf( "%s === %s === %s === PUBLIC RATE LIMIT REACHED !!!" , ip_address , c.Method() , c.Path() );
		fmt.Println( log_message )
		c.Set( "Content-Type" , "text/html" )
		// return c.SendString( "<html><h1>loading ...</h1><script>setTimeout(function(){ window.location.reload(1); }, 6);</script></html>" )
		return c.SendString( "<html><h1>why</h1></html>" )
	} ,
})

func ServeLoginPage( context *fiber.Ctx ) ( error ) {
	return context.SendFile( "./v1/server/html/login.html" )
}

func return_error( context *fiber.Ctx , error_message string ) ( error ) {
	context.Set( "Content-Type" , "text/html" )
	return context.SendString( error_message )
}

func validate_api_key( context *fiber.Ctx ) ( result bool ) {
	result = false
	posted_key := context.Get( "key" )
	if posted_key == "" { return }
	key_matches := bcrypt.CompareHashAndPassword( []byte( posted_key ) , []byte( GlobalConfig.ServerAPIKey ) )
	if key_matches != nil { return }
	result = true
	return
}

func validate_login_credentials( context *fiber.Ctx ) ( result bool ) {
	result = false
	uploaded_username := context.FormValue( "username" )
	if uploaded_username == "" { fmt.Println( "username empty" ); return }
	if uploaded_username != GlobalConfig.AdminUsername { fmt.Println( "username not correct" ); return }
	uploaded_password := context.FormValue( "password" )
	if uploaded_password == "" { fmt.Println( "password empty" ); return }
	password_matches := bcrypt.CompareHashAndPassword( []byte( uploaded_password ) , []byte( GlobalConfig.AdminPassword ) )
	if password_matches != nil { fmt.Println( "bcrypted password doesn't match" ); return }
	result = true
	return
}

func HandleLogout( context *fiber.Ctx ) ( error ) {
	context.Cookie( &fiber.Cookie{
		Name: GlobalConfig.ServerCookieName ,
		Value: "" ,
		Expires: time.Now().Add( -time.Hour ) , // set the expiration to the past
		HTTPOnly: true ,
		Secure: true ,
	})
	context.Set( "Content-Type" , "text/html" )
	return context.SendString( "<h1>Logged Out</h1>" )
}

// POST http://localhost:5950/admin/login
func HandleLogin( context *fiber.Ctx ) ( error ) {
	valid_login := validate_login_credentials( context )
	if valid_login == false { return return_error( context , "invalid login" ) }
	context.Cookie(
		&fiber.Cookie{
			Name: GlobalConfig.ServerCookieName ,
			Value: encryption.SecretBoxEncrypt( GlobalConfig.SecretBoxKey , GlobalConfig.ServerCookieAdminSecretMessage ) ,
			Secure: true ,
			Path: "/" ,
			// Domain: "blah.ngrok.io" , // probably should set this for webkit
			HTTPOnly: true ,
			SameSite: "Lax" ,
			Expires: time.Now().AddDate( 10 , 0 , 0 ) , // aka 10 years from now
		} ,
	)
	return context.Redirect( "/" )
}

func validate_admin_cookie( context *fiber.Ctx ) ( result bool ) {
	result = false
	admin_cookie := context.Cookies( GlobalConfig.ServerCookieName )
	if admin_cookie == "" { fmt.Println( "admin cookie was blank" ); return }
	admin_cookie_value := encryption.SecretBoxDecrypt( GlobalConfig.SecretBoxKey , admin_cookie )
	if admin_cookie_value != GlobalConfig.ServerCookieAdminSecretMessage { fmt.Println( "admin cookie secret message was not equal" ); return }
	result = true
	return
}

func validate_admin_session( context *fiber.Ctx ) ( result bool ) {
	result = false
	admin_cookie := context.Cookies( GlobalConfig.ServerCookieName )
	if admin_cookie != "" {
		admin_cookie_value := encryption.SecretBoxDecrypt( GlobalConfig.SecretBoxKey , admin_cookie )
		if admin_cookie_value == GlobalConfig.ServerCookieAdminSecretMessage {
			result = true
			return
		}
	}
	admin_api_key_query := context.Query( "k" )
	if admin_api_key_query != "" {
		if admin_api_key_query == GlobalConfig.ServerAPIKey {
			result = true
			return
		}
	}
	admin_api_key_header := context.Get( "key" )
	if admin_api_key_header != "" {
		if admin_api_key_header == GlobalConfig.ServerAPIKey {
			result = true
			return
		}
	}
	api_temp_key_header := context.Query( "tk" )
	if api_temp_key_header != "" {
		result = temp_api_key_exists( api_temp_key_header )
		return
	}
	return
}

func Home( context *fiber.Ctx ) ( error ) {
	// return context.SendFile( "./v1/server/html/admin_login.html" )
	return context.JSON( fiber.Map{
		"route": "/" ,
		"result": "https://github.com/0187773933/KeyValueStoreServer" ,
	})
}

// deletes on true
func temp_api_key_exists( value string ) ( result bool ) {
	db , _ := bolt_api.Open( GlobalConfig.BoltDBPath , 0600 , &bolt_api.Options{ Timeout: ( 3 * time.Second ) } )
	defer db.Close()
	db.Update( func( tx *bolt_api.Tx ) error {
		b := tx.Bucket( []byte( "temp-api-keys" ) )
		v := b.Get( []byte( value ) )
		result = v != nil
		fmt.Println( "temp_api_key_exists ===", value , "===" , result )
		if result == true {
			b.Delete( []byte( value ) )
		}
		return nil
	})
	return
}

func NewTempKey( context *fiber.Ctx ) ( error ) {
	if validate_admin_session( context ) == false { return return_error( context , "why" ) }
	temp_key := encryption.SecretBoxGenerateKey( GlobalConfig.ServerTempAPIKeyPrefix )
	temp_key_string := fmt.Sprintf( "%x" , temp_key )
	fmt.Println( temp_key_string )
	db , _ := bolt_api.Open( GlobalConfig.BoltDBPath , 0600 , &bolt_api.Options{ Timeout: ( 3 * time.Second ) } )
	defer db.Close()
	db.Update( func( tx *bolt_api.Tx ) error {
		bucket := tx.Bucket( []byte( "temp-api-keys" ) )
		bucket.Put( []byte( temp_key_string ) , []byte( "1" ) )
		return nil
	})
	context.Set( "Content-Type" , "text/html; charset=utf-8" )
	return context.SendString( temp_key_string )
}

func Set( context *fiber.Ctx ) ( error ) {
	if validate_admin_session( context ) == false { return return_error( context , "why" ) }
	key := context.Params( "key" )
	var value string
	value_param := context.Params( "value" )
	value_query := context.Query( "value" )
	if value_param != "" {
		value = value_param
	} else if value_query != "" {
		value = value_query
	} else {
		return return_error( context , "why" )
	}
	fmt.Println( key , "===" , value )
	db , _ := bolt_api.Open( GlobalConfig.BoltDBPath , 0600 , &bolt_api.Options{ Timeout: ( 3 * time.Second ) } )
	defer db.Close()
	db.Update( func( tx *bolt_api.Tx ) error {
		bucket := tx.Bucket( []byte( "keys" ) )
		bucket.Put( []byte( key ) , []byte( value ) )
		return nil
	})
	context.Set( "Content-Type" , "text/html; charset=utf-8" )
	return context.SendString( "👍" )
}

func Get( context *fiber.Ctx ) ( error ) {
	// if validate_admin_session( context ) == false { return return_error( context , "why" ) }
	key := context.Params( "key" )
	db , _ := bolt_api.Open( GlobalConfig.BoltDBPath , 0600 , &bolt_api.Options{ Timeout: ( 3 * time.Second ) } )
	defer db.Close()
	var value string
	db.View( func( tx *bolt_api.Tx ) error {
		b := tx.Bucket( []byte( "keys" ) )
		v := b.Get( []byte( key ) )
		if v != nil {
			value = string( v )
		}
		return nil
	})
	fmt.Println( fmt.Sprintf( "%s === %s" , key , value ) )
	if value == "" {
		return context.JSON( fiber.Map{
			"route": "/get" ,
			"key": key ,
			"value": value ,
			"result": "key not found" ,
		})
	}
	return context.SendString( value )
}