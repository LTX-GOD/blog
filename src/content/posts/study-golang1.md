---
title: Study golang「1」
published: 2025-07-07
pinned: false
description: 学习golang的一些笔记
tags: ['golang']
category: 开发
licenseName: "MIT"
author: zsm
draft: false
date: 2025-07-07
pubDate: 2025-07-07
---


## study golang / demo1

作为一个初学者，跟着佬的步伐写五个小demo玩玩，熟悉一下整个的开发方式和流程

### 项目架构
```
.
├── main.go
└── static
    ├── form.html
    └── index.html
```
最初级的东西了，这里不用`gin`练练代码，静态文件就不写了，自由发挥了bro

### 整体代码
先初始化一下，这里就一个go文件，所以随便了`go mod init zsm`

main.go
```go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func formHandler(w http.ResponseWriter, r *http.Request) {
	// w 为 http.ResponseWriter 的实例，用于向客户端返回响应。
	// r 为 http.Request 的实例，包含了客户端的请求信息。
	err := r.ParseForm()
	if err != nil {
		fmt.Println(w, "ParseForm() err:%v", err)
		return
	}
	fmt.Fprintln(w, "POST request successful")

	name := r.FormValue("name")
	address := r.FormValue("address")
	fmt.Fprintf(w, "Name=%s\n", name)
	fmt.Fprintf(w, "address=%s\n", address)

}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	//请求路径
	if r.URL.Path != "/hello" {
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}
	//请求方法
	if r.Method != "GET" {
		http.Error(w, "method is not supported", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "Hello")
}

func main() {
	fileServer := http.FileServer(http.Dir("./static")) //挂载静态文件
	http.Handle("/", fileServer)                        //挂载到根目录

	//路径绑定函数
	http.HandleFunc("/form", formHandler)
	http.HandleFunc("/hello", helloHandler)

	fmt.Println("server is running on 8080")

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}

}

```

原生`http`模块比较麻烦算是，练练熟练度就行了

### 关于指针传递

比较好玩的是在go里面`*`是用来声明以及操作指针的，而`&`是一个运算符，它用于获取（或查找）变量的地址。比如

```go
func handleRequest(r *http.Request) {

}
```

这里r赋值为后面的指针，那我要访问后再说解析的时候，就可以直接在上面进行操作了，比如

```go
func modifyHeader(r *http.Request) {
    r.Header.Set("X-Custom-Header", "Value") // 修改请求头
}
```

这样的好处是如果`http.Request`是一个大结构体，传指针可以减少内存使用还有复制开销，也避免了将整个结构体复制到函数调用栈，有效提高性能  

那我怎么获取实际对象呢，直接解引用就行了，即`*r`  

这样的好处不仅仅在性能优化上，也为开发者提供了一种一致的编程模式，在一定程度上有利于规范化

## study golang / demo2

为降低难度，本项目未使用 DATEBASE ，仅使用本地 json 文件存储数据。

### 项目架构

```
.
└─src
    ├─go-basic-server
    ├─go-code
    ├─go-keword-scraper
    ├─go-movies-curd
    │      go.mod
    │      go.sum
    │      main.go
    │
    ├─go-rest
    ├─go-server
    └─go-todo
```

这里没有用数据库，用简单的方法先模拟一下xd

### 整体代码

先写结构体，方便后面的定义全局变量

```go
//电影
type Movie struct {
	ID       string    `json:"id"`
	Isbn     string    `json:"isbn"`
	Title    string    `json:"title"`
	Director *Director `json:"director"`
}

//导演
type Director struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

var movies []Movie
```

接下来创建路由还有插入几个真数据

```go
func main() {
	//router
	r := mux.NewRouter()

	movies = append(movies, Movie{ID: "1", Isbn: "438227", Title: "Movie One", Director: &Director{FirstName: "John", LastName: "Doe"}})
	movies = append(movies, Movie{ID: "2", Isbn: "45455", Title: "Movie Two", Director: &Director{FirstName: "Steve", LastName: "Smith"}})

	r.HandleFunc("/movies", getMovies).Methods("GET")
	r.HandleFunc("/movies/{id}", getMovie).Methods("GET")
	r.HandleFunc("/movies", createMovie).Methods("POST")
	r.HandleFunc("/movies/{id}", updateMovie).Methods("POST")
	r.HandleFunc("/movies{id}", deleteMovie).Methods("DELETE")

	fmt.Println("server is running on 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

这里写五个api接口，依次写上去

```go
// 拿全部的电影
func getMovies(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(movies)
}

// 删除指定电影
func deleteMovie(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    // 从 HTTP 请求 r 中提取路径参数，并将它们以 map[string]string 的形式返回
    params := mux.Vars(r)
    // index 是当前元素的索引（即位置），它是一个整数值; item 是当前索引位置上的元素本身
    for index, item := range movies {

        if item.ID == params["id"] {
            // append(movies[:index], movies[index+1:]...) 实际上创建了一个新的切片，其中包含了删除指定元素后的所有元素。
            movies = append(movies[:index], movies[index+1:]...)
            // break 语句用于退出 for 循环
            break
        }
    }
    json.NewEncoder(w).Encode(movies)
}

// 拿一个电影
func getMovie(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type","application/json")
    params := mux.Vars(r)
    for _, item := range movies {

        if item.ID == params["id"] {
            json.NewEncoder(w).Encode(item)
            return
        }
    }
}

// 增加一个电影
func createMovie(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    var movie Movie
    // Decode(&movie)：传入 movie 的指针，以便解码器可以直接修改 movie 变量的内容。
    // _ 表示我们忽略 Decode 方法的返回值。如果解码过程发生错误，通常会记录错误信息而不是简单地忽略。
    _ = json.NewDecoder(r.Body).Decode(&movie)
    // rand.Intn(100000000)：生成一个随机整数，范围是 0 到 99999999（不包括 100000000）。
    movie.ID = strconv.Itoa(rand.Intn(100000000))
    // 将 movie 添加到 movies 切片的末尾。append 函数会创建一个新的切片（如果原切片空间不足），并将原切片和新元素合并到一起。
    movies = append(movies, movie)
    json.NewEncoder(w).Encode(movie)
}

// 更新单个电影
func updateMovie(w http.ResponseWriter, r *http.Request) {

    // 设定响应头 Content-Type 为 application/json
    w.Header().Set("Content-Type", "application/json")
    params := mux.Vars(r)

    for index, item := range movies {
        if item.ID == params["id"] {
            // 删除原有电影
            movies = append(movies[:index], movies[index+1:]...)
            // 创建新电影
            var movie Movie
            // 创建一个 JSON 解码器，并从 HTTP 请求的主体中解码 JSON 数据到 `movie` 变量。
            _ = json.NewDecoder(r.Body).Decode(&movie)
            movie.ID = params["id"]
            movies = append(movies, movie)
            json.NewEncoder(w).Encode(movies)
            return
        }
    }
    
}
```

### 关于测试接口
很多人都喜欢用`POSTMAN`这个软件，其实vsc里面是有这个插件的，可以使用，或者是用`REST Client`这个插件，手写GET/POST包发过去即可，前者比较轮椅

### 关于结构体标签

结构体里面定义的时候，一般后面都会加上`json`这个东西，主要的用途就是编码和解码、数据库字段映射、表单解析和 XML 编码和解码，如

```go
//结构体标签最常见的用途是与 JSON 编码和解码相关。通过指定 JSON 标签，可以控制 JSON 数据中的字段名称和行为。
type Person struct {
 Name  string `json:"name"`
 Age   int    `json:"age"`
 Email string `json:"email"`
}
// 当你使用 encoding/json 包对这个结构体进行编码时，json:"name" 标签指定了在 JSON 数据中应该使用 "name" 作为字段名。这使得 JSON 数据与 Go 结构体字段之间能够正确映射。
import (
 "encoding/json"
 "fmt"
)

func main() {
 p := Person{Name: "Alice", Age: 30, Email: "alice@example.com"}
 jsonData, _ := json.Marshal(p)
 fmt.Println(string(jsonData)) // 输出: {"name":"Alice","age":30,>>"email":"alice@example.com"}
}

//------------------//

// 结构体标签也可以用于数据库操作，通过标签指定字段名与数据库表中的列名之间的映射。
// 这里，gorm:"column:user_name" 标签指定了结构体字段 Name 对应数据库表中的 user_name 列。
type User struct {
 ID    int    `gorm:"primary_key"`
 Name  string `gorm:"column:user_name"`
 Email string `gorm:"column:user_email"`
}

//------------------//

// 在 Web 开发中，结构体标签可以用于表单解析，指定表单字段的名称与结构体字段之间的映射关系。例如，使用 gin 框架处理表单数据：
// 在这个例子中，form:"username" 标签表示表单字段 username 将被映射到结构体字段 Username。
type LoginForm struct {
 Username string `form:"username"`
 Password string `form:"password"`
}

//------------------//

// 除了 JSON，结构体标签也可以用于 XML 编码和解码。例如，使用 encoding/xml 包：
// 这里，xml:"title" 标签指定了 XML 数据中字段名为 title，这在 XML 编码和解码时起作用。
type Book struct {
 Title  string `xml:"title"`
 Author string `xml:"author"`
}
```
