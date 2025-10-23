---
title: Study Golang「2」
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


## study golang / demo3

mysql+gorm+MVC

### 项目架构

```
D:.
├─ go.mod
├─ go.sum
│  
├─cmd
│  └─main
│          main.go
│
└─pkg
    ├─config
    │      app.go
    │
    ├─controllers
    │      book-controller.go
    │
    ├─models
    │      book.go
    │
    ├─routes
    │      bookstore-routes.go
    │
    └─utils
            utils.go
```

这里直接按照mvc思想去编写了，互相引用比较多，可以初始化规范一点了`go mod init github.com/your_username/go-bookstore`，但是我比较懒，所以就没有这样(

### 整体代码

#### ***1. 编写 routes/routes.go 文件***

先把接口定义好，这样后面就知道要写什么了

```go
package routes

import (
	"zsm/pkg/controllers"

	"github.com/gorilla/mux"
)

var RegisterBookStoreRoutes = func(router *mux.Router) {
	// 将 /book/ 路径和 POST 方法映射到 controllers.CreateBook 函数。
	// 也就是说，当一个 POST 请求发送到 /book/ 时，controllers.CreateBook 函数将被调用来处理这个请求。
	router.HandleFunc("/book/", controllers.CreateBook).Methods("POST")
	router.HandleFunc("/book/", controllers.GetBook).Methods("GET")
	router.HandleFunc("/book/{BookId}", controllers.GetBookById).Methods("GET")
	router.HandleFunc("/book/{BookId}", controllers.UpdateBook).Methods("PUT")
	router.HandleFunc("/book/{BookId}", controllers.DeleteBook).Methods("DELETE")
}
```

#### ***2. 编写 config/app.go 文件***
这里提前建个库
>CREATE DATABASE `gotest` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

```go
package config

import (
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

var (
	db *gorm.DB
)

func Connect() {
	d, err := gorm.Open("mysql", "root:mnbvcxz123321.@tcp(127.0.0.1:3306)/gotest?chartset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic(err)
	}
	fmt.Println("Connect to database successfully")
	db = d
}

func GetDB() *gorm.DB {
	return db
}
```

有一说一，感觉`gorm`没有nodejs那边的orm好用

#### ***3. 编写 utils/utils.go 文件***

这里的函数一般用来代码复用/解藕逻辑/统一格式，放的一般是常用的，小而通用的函数

```go
package utils

import (
	"encoding/json"
	"io"
	"net/http"
)

func ParseBody(r *http.Request, x interface{}) {
	if body, err := io.ReadAll(r.Body); err == nil {
		if err := json.Unmarshal([]byte(body), x); err != nil {
			return
		}
	}
}
```

#### ***4. 编写 models/models.go 文件***

这里有个小东西，在定义结构体时，嵌套 gorm.Model 结构体，它包含了默认的字段：ID（主键）、CreatedAt、UpdatedAt 和 DeletedAt（软删除）。

在go包初始化时`init`函数会自动执行，所以我们可以在这个时候连接/初始化数据库

```go
package models

import (
	"zsm/pkg/config"

	"github.com/jinzhu/gorm"
)

var db *gorm.DB

type Book struct {
    gorm.Model
	Name        string `json:"name"`
	Author      string `json:"author"`
	Publication string `json:"publication"`
}
func init() {
    config.Connect()
    db = config.GetDB()
    // 使用 GORM 的 AutoMigrate 方法自动迁移 Book 结构体。
    // 自动迁移会创建或更新数据库表，使其与 Book 结构体匹配。如果表不存在，则创建表；如果表已存在，则更新表结构以匹配 Book 结构体的定义。
    db.AutoMigrate(&Book{})
}

// CreateBook 方法用于创建 Book 结构体的实例并插入到数据库中。
func (b *Book) CreateBook() *Book{
    db.NewRecord(b)
    db.Create(&b)
    return b
}

// GetAllBooks 方法用于从数据库中获取所有 Book 结构体的实例。
func GetAllBooks() []Book {
    var Books []Book
    db.Find(&Books)
    return Books
}

// GetBookById 方法用于从数据库中获取指定 ID 的 Book 结构体的实例。
func GetBookById(Id int64) (*Book, *gorm.DB) {
    var getBook Book
    db:=db.Where("ID=?", Id).Find(&getBook)
    return &getBook, db
}

// DeleteBook 方法用于从数据库中删除指定 ID 的 Book 结构体的实例。
func DeleteBook(ID int64) Book {
    var book Book
    db.Where("ID=?", ID).Delete(book)
    return book
}
```

#### ***5. 编写 main.go 文件***
这里其实就是最起初的启动项了，绑定端口还有创建路由即可

```go
package main

import (
	"log"
	"net/http"
	"zsm/pkg/routes"

	"github.com/gorilla/mux"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

func main() {
	r := mux.NewRouter()
	routes.RegisterBookStoreRoutes(r)
	http.Handle("/", r)
	log.Fatal(http.ListenAndServe("localhost:9010", r))
}
```

#### ***编写 book-controller.go 文件***
就是传统的controllers层罢了

```go
package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"zsm/pkg/models"
	"zsm/pkg/utils"

	"github.com/gorilla/mux"
)

var NewBook models.Book

func GetBook(w http.ResponseWriter, r *http.Request) {
	newBooks := models.GetAllBooks()
	res, _ := json.Marshal(newBooks)
	w.Header().Set("Content-Type", "pkglication/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

// GetBookById 根据书籍ID获取书籍详情
// 通过URL路径参数获取书籍ID，然后调用models包中的GetBookById函数获取书籍详情，
// 最后将书籍详情以JSON格式返回给客户端。
func GetBookById(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bookId := vars["bookId"]
	ID, err := strconv.ParseInt(bookId, 0, 0)
	if err != nil {
		fmt.Println("error write parsing")
	}
	bookDetails, _ := models.GetBookById(ID)
	res, _ := json.Marshal(bookDetails)
	w.Header().Set("Content-Type", "pkglication/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

// CreateBook 创建新的书籍记录
// 解析请求体中的书籍信息，然后调用models包中的CreateBook方法创建新的书籍记录，
// 最后将创建结果以JSON格式返回给客户端。
// 注意：这里假设models.Book结构体有一个CreateBook()方法来处理创建逻辑。
func CreateBook(w http.ResponseWriter, r *http.Request) {
	CreateBook := &models.Book{}
	utils.ParseBody(r, CreateBook)
	b := CreateBook.CreateBook()
	res, _ := json.Marshal(b)
	w.Header().Set("Content-Type", "pkglication/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

// DeleteBook 根据书籍ID删除书籍记录
// 通过URL路径参数获取书籍ID，然后调用models包中的DeleteBook函数删除书籍记录，
// 最后将删除结果以JSON格式返回给客户端。
func DeleteBook(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bookId := vars["bookId"]
	ID, err := strconv.ParseInt(bookId, 0, 0)
	if err != nil {
		fmt.Println("error while parsing")
	}
	book := models.DeleteBook(ID)
	res, _ := json.Marshal(book)
	w.Header().Set("Content-Type", "pkglication/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

// UpdateBook 更新书籍信息
// 解析请求体中的书籍信息，然后结合URL路径参数中的书籍ID，调用models包中的相关方法更新书籍记录，
// 最后将更新后的书籍详情以JSON格式返回给客户端。
func UpdateBook(w http.ResponseWriter, r *http.Request) {
	var updateBook = &models.Book{}
	utils.ParseBody(r, updateBook)
	vars := mux.Vars(r)
	bookId := vars["bookId"]
	ID, err := strconv.ParseInt(bookId, 0, 0)
	if err != nil {
		fmt.Println("error while parsing")
	}
	bookDetails, db := models.GetBookById(ID)
	if updateBook.Name != "" {
		bookDetails.Name = updateBook.Name
	}
	if updateBook.Author != "" {
		bookDetails.Author = updateBook.Author
	}
	if updateBook.Publication != "" {
		bookDetails.Publication = updateBook.Publication
	}
	db.Save(&bookDetails)
	res, _ := json.Marshal(bookDetails)
	w.Header().Set("Content-Type", "pkglication/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}
```

## study golang / demo4

mysql+gorm+MVC+gin

### 项目架构

```
.
├─ go.mod
├─ go.sum
│
├─ cmd
│  └─ main
│      └─ main.go
│
└─ pkg
    ├─ config
    │      └─ app.go
    │
    ├─ controllers
    │      └─ book-controller.go
    │
    ├─ models
    │      └─ book.go
    │
    └─ routes
       └─ bookstore-routes.go
```

数据库还是用上一个，比较懒导致的

### 整体代码

#### ***1. 编写 routes/routes.go 文件***

因为所有操作都从请求接口开始，定义好路由可以帮助我们明确应用的整体结构。

在路由确定之后，我们可以进一步编写控制器和模型，这样可以确保应用的各个部分都能协调工作。

虽然每个人的开发习惯和业务逻辑可能不同，但从路由入手通常是一个推荐的方法，它能帮助你更清晰地组织代码, 并且让你曾经觉得难以完成的独立开发一个项目变得轻松可行。

```go
package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/zsm/go-bookstore/pkg/controllers"
)

func Router() *gin.Engine {
	r := gin.Default()
	book := r.Group("/book")
	{
		book.GET("/", controllers.GetBookTest)
		book.GET("/:bookId", controllers.GetBookByIdTest)
		book.POST("/", controllers.CreateBookTest)
		book.PUT("/:bookId", controllers.UpdateBookTest)
		book.DELETE("/:bookId", controllers.DeleteBookTest)
	}
	return r
}
```

#### ***2. 编写config/app.go 文件***

```go
package config

import (
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

var (
	db *gorm.DB
)

func Connect() {
	d, err := gorm.Open("mysql", "root:mnbvcxz123321.@tcp(127.0.0.1:3306)/gotest?chartset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic(err)
	}
	fmt.Println("Connect to database successfully")
	db = d
}

func GetDB() *gorm.DB {
	return db
}
```

#### ***3. models/models.go***

这里其实和demo3差不多，这里要稍微注意一点，查询的时候要写入`ID=?`，这样去防止sql注入

```go
package models

import (
	"github.com/jinzhu/gorm"
	"github.com/zsm/go-bookstore/pkg/config"
)

var db *gorm.DB

type Book struct {
	gorm.Model
	Name        string `json:"name"`
	Author      string `json:"author"`
	Publication string `json:"publication"`
}

func init() {
	config.Connect()
	db = config.GetDB()
	db.AutoMigrate(&Book{})
}

func (b *Book) CreateBook() *Book {
	db.NewRecord(b)
	db.Create(&b)
	return b
}

func GetAllBooks() []Book {
	var Books []Book
	db.Find(&Books)
	return Books
}

func GetBookById(Id int64) (*Book, *gorm.DB) {
	var getBook Book
	db := db.Where("ID=?", Id).Find(&getBook)
	return &getBook, db
}

func DeleteBook(ID int64) Book {
	var book Book
	db.Where("ID=?", ID).Delete(&book)
	return book
}
```

#### ***4. 编写 mian.go 文件***

这里就很简洁了，两行搞定bro

```go
package main

import (
	"fmt"

	"github.com/zsm/go-bookstore/pkg/routes"
)

func main() {
	r := routes.Router()
	fmt.Println("Server is running on localhost:9010")
	r.Run(":9010")
}
```

#### ***5. 编写 controllers/controller.go 文件***

```go
package controllers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zsm/go-bookstore/pkg/models"
)

// NewBook 是一个用来创建新书的结构体
var NewBook models.Book

// GetBookTest 函数返回所有的书籍
func GetBookTest(c *gin.Context) {
	newBooks := models.GetAllBooks()
	c.JSON(http.StatusOK, newBooks)
}

// GetBookByIdTest 函数返回指定ID的书籍
func GetBookByIdTest(c *gin.Context) {
	bookId := c.Param("bookId")
	ID, _ := strconv.ParseInt(bookId, 0, 0)
	bookDetails, _ := models.GetBookById(ID)
	// 以JSON格式返回书籍详情
	c.JSON(http.StatusOK, bookDetails)
}

// CreateBookTest 函数创建一个新的书籍并返回详细信息
func CreateBookTest(c *gin.Context) {
	// 初始化一个新书籍结构体
	var CreateBook = &models.Book{}
	// 从请求体中解析书籍信息
	c.ShouldBindJSON(CreateBook)
	// 创建书籍并保存到数据库
	b := CreateBook.CreateBook()
	// 以JSON格式返回书籍详情
	c.JSON(http.StatusOK, b)
}

func DeleteBookTest(c *gin.Context) {
	bookId := c.Param("bookId")
	ID, err := strconv.ParseInt(bookId, 0, 0)
	if err != nil {
		fmt.Printf("解析错误！")
	}
	// 删除之前获取书籍详情, 并删除书籍
	book, _ := models.GetBookById(ID)
	models.DeleteBook(ID)
	c.JSON(http.StatusOK, book)
}

func UpdateBookTest(c *gin.Context) {
	var updateBook = &models.Book{}
	c.ShouldBindJSON(updateBook)
	bookId := c.Param("bookId")
	ID, err := strconv.ParseInt(bookId, 0, 0)
	if err != nil {
		fmt.Println("解析错误！")
	}
	bookDetails, db := models.GetBookById(ID)
	// 如果Name、Author、Publication字段有更新，则更新数据库对应数据
	if updateBook.Name != "" {
		bookDetails.Name = updateBook.Name
	}
	if updateBook.Author != "" {
		bookDetails.Author = updateBook.Author
	}
	if updateBook.Publication != "" {
		bookDetails.Publication = updateBook.Publication
	}
	// 保存更新后的书籍信息到数据库
	db.Save(&bookDetails)
	c.JSON(http.StatusOK, bookDetails)
}
```
