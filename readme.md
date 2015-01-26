# TOAuth Library v1.3.0
* Twitter OAuth Library
* MIT License
* Require .Net 4.0 or 2.0
* use .NET 4.0, remove annotation of ***#define USENET40***

# Function
## Parameters
  * `Method`
    * **GET** or **POST**
  * `Uri`
    * **System.Uri** or **tring**
    * Support short uri string
      * "https://api.twitter.com/1.1/statuses/update.json"
        * "1.1/statuses/update.json"
        * "statuses/update.json"
      * "https://stream.twitter.com/1.1/statuses/filter.json"
        * "1.1/statuses/filter.json"
        * "statuses/filter.json"
  * `Data`
    * **String**
    ```
    object data = "param1=value1&param2=value2"
    ```

    * **Stream**
    ```
    object data = System.IO.File.OpenRead(path)
    ```

    * **IDictinoray<string, object>**
     ```
     IDictionary<string, object> dic = new Dictionary<string, object>
     dic.Add("status", "test");
     object data = dic;
     ```

    * **byte[]**
    ```
    object data = System.IO.ReadAllBytes(path);
    ```

    * **Properties**
    ```
    object data = new { Key1 = "Value1", Key2 = 123 }
    ```

    * **Class (Must contains properties)**
    ```
    class Info
    {
        public string status { set; get; }
        public long in_reply_to_status_id { set; get; }
    }
    object data = new Info();
	```

## Constructor
* `TOAuth `

## Common# TOAuth Library v1.3.0
* Twitter OAuth Library
* MIT License
* Require .Net 4.0 or 2.0
* use .NET 4.0, remove annotation ***#define USENET40***

# Function
## Parameters
  * `Method`
    * **GET** or **POST**
  * `Uri`
    * **System.Uri** or **tring**
    * Support short uri string
      * "https://api.twitter.com/1.1/statuses/update.json"
        * "1.1/statuses/update.json"
        * "statuses/update.json"
      * "https://stream.twitter.com/1.1/statuses/filter.json"
        * "1.1/statuses/filter.json"
        * "statuses/filter.json"
  * `Data`
    * **String**
    ```
    object data = "param1=value1&param2=value2"
    ```

    * **Stream**
    ```
    object data = System.IO.File.OpenRead(path)
    ```

    * **IDictinoray<string, object>**
     ```
     IDictionary<string, object> dic = new Dictionary<string, object>
     dic.Add("status", "test");
     object data = dic;
     ```

    * **byte[]**
    ```
    object data = System.IO.ReadAllBytes(path);
    ```

    * **Properties**
    ```
    object data = new { Key1 = "Value1", Key2 = 123 }
    ```

    * **Class (Must contains properties)**
    ```
    class Info
    {
        public string status { set; get; }
        public long in_reply_to_status_id { set; get; }
    }
    object data = new Info();
	```

## Constructor
* `TOAuth (AppToken, AppSecret)`
* `TOAuth (AppToken, AppSecret, UserToken, UserSecret)`

## Common
* `WebRequest MakeRequest(Method, Uri, Data, OAuthCallback)`

## .NET 2.0
* `String Call(Method, Uri, Data, ContentType, OAuthCallback, CallbackFunction, State)`
* `IAsyncResult BeginCall(Method, Uri, Data, ContentType, OAuthCallback, CallbackFunction, State)`
* `String EndCall(IAsyncResult)`

## .Net 4.0
* `String Call(Method, Uri, Data, ContentType, OAuthCallback)`
* `Task<string> BeginCall(Method, Uri, Data, ContentType, OAuthCallback)`
* `WebRequest MakeRequest(Method, Uri, Data, OAuthCallback)`

## .NET 2.0
* `String Call(Method, Uri, Data, ContentType, OAuthCallback, CallbackFunction, State)`
* `IAsyncResult BeginCall(Method, Uri, Data, ContentType, OAuthCallback, CallbackFunction, State)`
* `String EndCall(IAsyncResult)`

## .Net 4.0
* `String Call(Method, Uri, Data, ContentType, OAuthCallback)`
* `Task<string> BeginCall(Method, Uri, Data, ContentType, OAuthCallback)`
