package server

import (
	"fmt"
	"time"
	bolt_api "github.com/boltdb/bolt"
	fiber "github.com/gofiber/fiber/v2"
	fiber_cookie "github.com/gofiber/fiber/v2/middleware/encryptcookie"
	rate_limiter "github.com/gofiber/fiber/v2/middleware/limiter"
	favicon "github.com/gofiber/fiber/v2/middleware/favicon"
	types "github.com/0187773933/KeyValueStoreServer/v1/types"
	utils "github.com/0187773933/KeyValueStoreServer/v1/utils"
	routes "github.com/0187773933/KeyValueStoreServer/v1/server/routes"
)

type Server struct {
	FiberApp *fiber.App `json:"fiber_app"`
	Config types.ConfigFile `json:"config"`
}

func request_logging_middleware( context *fiber.Ctx ) ( error ) {
	time_string := utils.GetFormattedTimeString()
	ip_address := context.Get( "x-forwarded-for" )
	if ip_address == "" { ip_address = context.IP() }
	fmt.Printf( "%s === %s === %s === %s\n" , time_string , ip_address , context.Method() , context.Path() )
	return context.Next()
}

func New( config types.ConfigFile ) ( server Server ) {

	server.FiberApp = fiber.New( fiber.Config{
		BodyLimit: ( 100 * 1024 * 1024 ) , // 50 megabytes
	})
	server.Config = config

	// pre-create all necessary db buckets
	db , _ := bolt_api.Open( config.BoltDBPath , 0600 , &bolt_api.Options{ Timeout: ( 3 * time.Second ) } )
	defer db.Close()
	db.Update( func( tx *bolt_api.Tx ) error {
		tx.CreateBucketIfNotExists( []byte( "keys" ) )
		tx.CreateBucketIfNotExists( []byte( "temp-api-keys" ) )
		return nil
	})

	ip_addresses := utils.GetLocalIPAddresses()
	fmt.Println( "Server's IP Addresses === " , ip_addresses )
	// https://docs.gofiber.io/api/middleware/limiter
	server.FiberApp.Use( request_logging_middleware )
	server.FiberApp.Use( favicon.New() )
	server.FiberApp.Use( rate_limiter.New( rate_limiter.Config{
		Max: config.RateLimitPerSecond ,
		Expiration: ( 1 * time.Second ) ,
		Next: func( c *fiber.Ctx ) ( bool ) {
			// TODO : somehow allow large files using SendStream
			return c.IP() == "127.0.0.1"
		} ,
		LimiterMiddleware: rate_limiter.SlidingWindow{} ,
		KeyGenerator: func( c *fiber.Ctx ) string {
			return c.Get( "x-forwarded-for" )
		} ,
		LimitReached: func( c *fiber.Ctx ) error {
			ip := c.IP()
			fmt.Printf( "%s === limit reached\n" , ip )
			c.Set( "Content-Type" , "text/html" )
			return c.SendString( "<html><h1>why</h1></html>" )
		} ,
		// Storage: myCustomStorage{}
		// monkaS
		// https://github.com/gofiber/fiber/blob/master/middleware/limiter/config.go#L53
		// https://github.com/gofiber/fiber/issues/255
	}))
	server.FiberApp.Use( fiber_cookie.New( fiber_cookie.Config{
		Key: server.Config.ServerCookieSecret ,
	}))
	server.SetupRoutes()
	return
}

func ( s *Server ) SetupRoutes() {
	routes.RegisterRoutes( s.FiberApp , &s.Config )
}

func ( s *Server ) Start() {
	fmt.Printf( "Listening on %s\n" , s.Config.ServerPort )
	s.FiberApp.Listen( fmt.Sprintf( ":%s" , s.Config.ServerPort ) )
}