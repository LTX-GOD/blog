---
title: Study Golang「3」
published: 2025-07-08
pinned: false
description: 学习golang的一些笔记
tags: ['golang']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-07-08
pubDate: 2025-07-08
---


## study golang / demo5

***后端***：mongodb+gorm+MVC+gin+air
***前端***：vue+vite+ts
***仓库***：https://github.com/LTX-GOD/study-golang-demo

### 项目架构

```
demo5/
├── main.go
├── .air.toml
├── ecommerce-sys
├── go.mod
├── go.sum
├── controllers/
│   ├── address.go
│   ├── cart.go
│   └── controllers.go
├── database/
│   ├── cart.go
│   └── databasesetup.go
├── middleware/
│   └── middleware.go
├── models/
│   └── models.go
├── routes/
│   └── routes.go
├── tokens/
│   └── tokengen.go
├── tmp/
│   ├── build-errors.log
│   └── main
└── static/
    ├── form.html
    └── index.html
```

#### 关于Air包

```bash
go install github.com/air-verse/air@latest //拉包
air init //初始化
air //启动热重载
```

#### 关于mongodb

这里本地包docker上去的

```bash
docker exec -it mongodb sh
use gotest
```

### 关于后端项目

#### ***router & main***

路由文件中我只存了关于用户的，其他的存在了`main.go`里面，原因是这个练手项目的作者第一开始没写完，我后面自己补完的，包括前端的内容。

然后在main里面，我没有把端口写死，选择环境变量注入的方法

```go
	// 获取环境变量PORT的值, 如果不存在则赋值8000
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
```

这样的好处是包docker的时候灵活一点

因为项目是前后端分离，加上前端后还需要解决跨域问题

```go
	// 配置CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5173", "http://localhost:3000", "http://localhost:8080"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "token"}
	config.AllowCredentials = true
	router.Use(cors.New(config))
```

#### ***models***

这里定义的有点多

```go
type User struct {
	ID            primitive.ObjectID `json:"_id" bson:"_id"`
	Name          *string            `json:"name" validate:"required,min=6,max=30"`
	Password      *string            `json:"password" validate:"required,min=6,max=30"`
	Email         *string            `json:"email" validate:"email,required"`
	Phone         *string            `json:"phone" validate:"required"`
	Token         *string            `json:"token" `
	Refresh_Token *string            `json:"refresh_token"`
	Created_At    time.Time          `json:"created_at"`
	Updated_At    time.Time          `json:"updated_at"`
	User_ID       string             `json:"user_id"`
	// 切片本身已经是一个引用类型，能够提供对底层数据的引用，因此不加*号
	UserCart        []ProductUser `json:"usercart" bson:"usercart"`
	Address_Details []Address     `json:"address" bson:"address"`
	Order_Status    []Order       `json:"order" bson:"order"`
}

type Product struct {
	Product_ID   primitive.ObjectID `json:"_id" bson:"_id"`
	Product_Name *string            `json:"product_name"`
	Price        *string            `json:"price"`
	Rating       *string            `json:"rating"`
	Image        *string            `json:"image"`
}

type ProductUser struct {
	Product_ID   primitive.ObjectID `json:"_id" bson:"_id"`
	Product_Name *string            `json:"product_name"`
	Price        *string            `json:"price"`
	Rating       *string            `json:"rating"`
	Image        *string            `json:"image"`
}

type Address struct {
	Address_id primitive.ObjectID `bson:"_id"`
	House      *string            `json:"house_name" bson:"house_name"`
	Street     *string            `json:"street_name" bson:"street_name"`
	City       *string            `json:"city_name" bson:"city_name"`
	PostalCode *string            `json:"postalcode" bson:"postalcode"`
}

type Order struct {
	Order_ID       primitive.ObjectID `bson:"_id"`
	Order_Cart     []ProductUser      `json:"order_list" bson:"order_list"`
	Ordered_At     time.Time          `json:"ordered_at" bson:"ordered_at"`
	Price          int                `json:"price" bson:"price"`
	Discount       *int               `json:"discount" bson:"discount"`
	Payment_Method Payment            `json:"payment_method" bson:"payment_method"`
}

type Payment struct {
	Digital bool
	COD     bool
}
```

***结构体中字段为什么是首字母大写***
在go中，首字母大写的含义是这些字段是`导出`的，可以在包外部访问，就有点像其他语言中的public

加入首字母小写，就类似private，在外部无权限访问

***结构体中`json`和`bson`的不同***
+ `json` 标签：用于指定当结构体字段被序列化为 JSON 时，使用的字段名。例如：

```go
type User struct {
    Name  string  `json:"name"`
}  
```

即使定义的是Name，在json输出中也会被序列化成name

+ `bson` 标签：用于指定当结构体字段被序列化为 BSON（MongoDB 的文档格式）时，使用的字段名。例如：

```go
type User struct {
    ID  primitive.ObjectID  `bson:"_id"`
}  
```

这个例子中，ID 字段会被映射到 MongoDB 文档的 `_id` 字段，这是 MongoDB 中常用的主键字段名。

#### ***database***

这里分成两个文件进行编写，分别是`databasesetup.go`和`cart.go`

+ databasesetup.go
主要用来处理数据库连接还有获取用户和产品的集合，稍微多加的一点就是写了个连接数据库时的超时限制，其他的都是很简单的内容

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
```

+ cart.go
这里先定义了一些报错，然后写业务逻辑
主要任务有：
  1. 将指定产品添加到用户的购物车
  2. 从用户购物车中移除指定产品
  3. 处理用户购物车的购买过程
  4. 立即购买
代码太长就不放了bro

#### ***controllers***

这里写的也比较乱

+ controllers.go：处理密码哈希、注册、密码校验、登录、添加商品、购物车逻辑(增、删、查、购买、下单)
+ cart.go：提供接口处理功能，比如加购物车、移除商品、查看购物车、下单等，也就是main.go哪里的api接口
+ addre.go：提供用户地址接口，实现增加、编辑、删除的功能

代码很多，就不放了，部分还不是特别完善，像后面两个都是自己实现的，比较潦草

#### ***middleware***

这里主要用来实现中间件鉴权

```go
func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		ClientToken := c.Request.Header.Get("token")
		if ClientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No authorization header founded"})
			c.Abort()
			return
		}
		claims, err := token.ValidateToken(ClientToken)
		if err != "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("uid", claims.Uid)
		c.Next()
	}
}
```

#### ***tokens***

+ 生成jwttoken

```go
type SignedDetails struct {
	Email string
	Name  string
	Uid   string
	jwt.StandardClaims
}

// UserData 是存储用户数据的 MongoDB 集合引用
var UserData *mongo.Collection = database.UserData(database.Client, "Users")

// 从环境变量中读取JWT的签名和认证
var SECRET_KEY = os.Getenv("SECRET_KEY")

// TokenGenerator 生成一个签名的访问令牌和一个签名的刷新令牌。
func TokenGenerator(email string, name string, uid string) (signedtoken string, signedrefeshtoken string, err error) {
	claims := &SignedDetails{
		Email: email,
		Name:  name,
		Uid:   uid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(), // 令牌有效期为24小时
		},
	}

	//创建一个仅包含过期时间的声明，用来刷新令牌
	refreshclaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24*7)).Unix(), //刷新有效七天
		},
	}

	//HS256访问令牌
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}

	//刷新
	refreshtoken, err := jwt.NewWithClaims(jwt.SigningMethodHS384, refreshclaims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		log.Panic(err)
		return
	}

	return token, refreshtoken, err
}
```

+ 实现校验功能

```go
func ValidateToken(signedtoken string) (claims *SignedDetails, msg string) {
	// 解析并验证签名令牌，使用提供的密钥和声明类型
	token, err := jwt.ParseWithClaims(signedtoken, &SignedDetails{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET_KEY), nil // 使用SECRET_KEY作为签名密钥
	})
	if err != nil {
		msg = err.Error() // 如果解析过程中出现错误，设置错误信息并返回
		return
	}

	// 断言token.Claims为*SignedDetails类型，并进行类型检查
	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = "Invalid token" // 如果断言失败，说明令牌无效，设置错误信息并返回
		return
	}

	// 检查令牌的过期时间
	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = "Token expired" // 如果令牌已过期，设置错误信息并返回
		return
	}

	// 如果所有检查都通过，返回令牌中的声明和一个空消息
	return claims, ""
}
```

+ 实现刷新功能

```go
func UpdateAllTokens(signedtoken string, signedrefreshtoken string, userid string) {

	// 创建一个带有超时的上下文，超时时间为100秒
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel() // 确保函数返回时取消上下文

	var updateobj primitive.D

	// 构建更新对象，包括访问令牌、刷新令牌和更新时间
	updateobj = append(updateobj, bson.E{Key: "token", Value: signedtoken})
	updateobj = append(updateobj, bson.E{Key: "refresh_token", Value: signedrefreshtoken})
	updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339)) // 格式化当前时间为RFC3339格式

	updateobj = append(updateobj, bson.E{Key: "updated_at", Value: updated_at})

	// 设置Upsert选项，表示如果用户不存在则插入新记录
	upsert := true
	filter := bson.M{"user_id": userid} // 设置过滤条件，匹配指定的用户ID
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	// 执行更新操作，将更新对象应用到符合过滤条件的文档中
	_, err := UserData.UpdateOne(ctx, filter, bson.D{
		{Key: "$set", Value: updateobj},
	}, &opt)

	// 处理更新操作中的错误
	if err != nil {
		log.Panic(err) // 记录错误并引发恐慌
		return
	}
}
```

## study golang / demo6

***后端***：mysql+redis+gorm+MVC+gin+air+viper
***前端***：vue+vite+ts
***仓库***：https://github.com/LTX-GOD/study-golang-demo

### 项目架构

```
demo6/
├── main.go
├── .air.toml
├── go.mod
├── go.sum
├── readme.md
├── config/
│   ├── config.go
│   ├── config.yml
│   ├── db.go
│   └── redis.go
├── controllers/
│   ├── article_controller.go
│   ├── auth_controller.go
│   ├── exchange_rate_controller.go
│   └── like_controller.go
├── global/
│   └── global.go
├── middlewares/
│   └── auth_middleware.go
├── models/
│   ├── article.go
│   ├── exchange_rate.go
│   └── user.go
├── routes/
│   └── routes.go
├── utils/
│   └── utils.go
└── tmp/
```

#### ***redis && mysql***

这边都用docker去启动，然后先不建库，后面都现场用

### 关于后端项目

#### 编写习惯

1. 这里用viper编写资源管理项
2. 写路由，并且定义每个地方的函数
3. 写数据库models层
4. 写数据库配置文件，mysql和redis
5. 写config.go
6. 写utils和middlewares

#### 关于***viper***

```yml
app:
  name: CurrencyExchangeApp
  port: ":8000"

database:
  dsn: root:password@tcp(127.0.0.1:3306)/gotest?charset=utf8mb4&parseTime=True&loc=Local
  MaxIdleConns: 11
  MaxOpenCons: 114

redis:
  addr: localhost:6379
  DB: 0
  Password: ""
```

这里去定义端口、数据库连接还有数量

在`config.go`里面，把这个viper的规则引入

```go
viper.SetConfigName("config")
viper.SetConfigType("yml")
viper.AddConfigPath("./config")
```

#### ***global.go***的作用

这个的作用是让这个全局文件都可以访问数据库和redis，在其他的项目中也经常使用这种方法

```go
package global

import (
	"github.com/go-redis/redis"
	"gorm.io/gorm"
)

var (
	Db      *gorm.DB
	RedisDB *redis.Client
)
```

#### 关于***routes.go***

这里稍微的严谨了一点，登录和注册是不用token判断的，但是其他的接口都需要，这样就更加规范了

```go
	auth := r.Group("/api/auth")
	{
		auth.POST("/login", controllers.Login)

		auth.POST("/register", controllers.Register)
	}

	api := r.Group("/api")
	api.GET("/exchangeRates", controllers.GetExchangeRates)
	api.Use(middlewares.AuthMiddleWare())
	{
		api.POST("/exchangeRates", controllers.CreateExchangeRate)
		api.POST("/articles", controllers.CreateArticle)
		api.GET("/articles", controllers.GetArticles)
		api.GET("/articles/:id", controllers.GetArticleByID)

		api.POST("/articles/:id/like", controllers.LikeArticle)
		api.GET("/articles/:id/like", controllers.GetArticleLikes)
	}
	return r
```